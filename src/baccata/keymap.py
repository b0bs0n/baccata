"""Shared keyboard behaviour: the Esc contract, filter/list bridges, and the
cheat sheet the F1 overlay renders.

The contract these helpers exist to enforce: Esc always means "leave this text
field and go back to navigation", in the main window and in every dialog. In a
dialog that works by *consuming* Esc in the field — when focus is already on a
list, tree or button nothing filters Esc, it reaches QDialog, and the dialog
closes. So the two-step Esc needs no dialog-side code, and none should be
added: an Escape handler on a dialog would break it.

Dialogs with no navigation position (AddGa, BulkGa, ScanQr) are bridged to
nothing and keep Qt's plain Esc = Cancel.
"""
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QKeyEvent, QKeySequence, QPalette, QShortcut
from PySide6.QtWidgets import (QApplication, QComboBox, QPushButton,
                               QTreeWidget)

# The contextual keys, in cheat-sheet order: (chords, what it does). This is
# the status-bar line F1 renders — only keys with no widget to sit behind:
# tab, pane and button keys appear at their widget while hints are on. A
# binding shown nowhere is undocumented by construction.
# tests/test_keymap.py checks the chords are real sequences.
HELP = (
    (('Alt+H', 'Alt+J', 'Alt+K', 'Alt+L'),     'arrows'),
    (('Left', 'Right'),                        'panes'),
    (('Up', 'Down'),                           'fields'),
    (('Shift+Up', 'Shift+Down'),               'change a value'),
    (('Ctrl+F',),                              'filter (or /)'),
    (('Ctrl+Z', 'Ctrl+Shift+Z'),               'undo / redo'),
    (('Esc',),                                 'leave any text box'),
    (('Return', 'F2'),                         'edit / rename'),
    (('Space',),                               'expand / toggle'),
)


class _Cursor(QObject):
    """Fusion paints the focus ring on combos and buttons only after a
    *keyboard* focus change (WA_KeyboardFocusChange on the window). Qt sets
    that for Tab alone and a click clears it; every arrow move here is a
    plain setFocus(), so without this the cursor is invisible."""

    def eventFilter(self, w, ev):
        if (ev.type() not in (QEvent.FocusIn, QEvent.FocusOut)
                or not w.isWidgetType()):
            return False
        if ev.type() == QEvent.FocusIn and ev.reason() != Qt.MouseFocusReason:
            w.window().setAttribute(Qt.WA_KeyboardFocusChange, True)
        # Buttons and pickers get a filled cursor on top of the 1px ring
        # (the ring alone is faint on the dark ground); text fields keep the
        # ring, they show a caret. Form fields paint their own (edit mode).
        if (isinstance(w, (QPushButton, QComboBox))
                and w.property('pref_id') is None
                and not (isinstance(w, QComboBox) and w.isEditable())):
            pal = QPalette()
            if ev.type() == QEvent.FocusIn:
                pal.setColor(QPalette.Button,
                             pal.color(QPalette.Inactive, QPalette.Highlight))
            w.setPalette(pal)
        return False


def keyboard_cursor(app):
    app.installEventFilter(_Cursor(app))


def native(key):
    """A chord the way the platform writes it (mac keys are symbols)."""
    return QKeySequence(key).toString(QKeySequence.NativeText)


def cheatsheet():
    """One status-bar line, built from HELP."""
    return ' \u00b7 '.join(f"{'/'.join(native(k) for k in ks)} {what}"
                           for ks, what in HELP)


def button(label, fn, key=None, on=None):
    """A push button and its key. "&X" mnemonics do nothing on macOS, so the
    key is set explicitly. With `on`, the key is scoped to that widget (a
    list): a bare letter is fine there — no text is being typed, and a bare
    letter is the one thing reliable everywhere (Option+letter is a compose
    key on macOS: Option+T types "\u2020"). It costs the tree's type-ahead
    search on those letters, which "/" already replaces."""
    b = QPushButton(label)
    if fn:
        b.clicked.connect(fn)
    if key and on is not None:
        sc = QShortcut(QKeySequence(key), on, b.click)   # honours disabled
        sc.setContext(Qt.WidgetShortcut)
        b.setToolTip(f'{native(key)} (on the list)')
    elif key:
        b.setShortcut(QKeySequence(key))
        b.setToolTip(native(key))
    return b


def focus_field(edit):
    """Focus a filter/text field with its text selected, so typing replaces."""
    edit.setFocus()
    if hasattr(edit, 'selectAll'):
        edit.selectAll()


class _Bridge(QObject):
    """Keyboard bridge between a line edit and its list/tree: Down in the edit
    enters the view (selecting the first row if none is current), Up from the
    view's top row returns to the edit, and Esc always does. With edit_below
    the edit sits under
    the view, so the directions flip: Up in the edit enters the view, Down
    past the view's last row returns to the edit. With consume_return, Return
    in the edit fires returnPressed WITHOUT also triggering the dialog's
    default button."""

    def __init__(self, edit, view, consume_return=False, edit_below=False):
        super().__init__(edit)
        self.edit, self.view, self.consume_return = edit, view, consume_return
        self.edit_below = edit_below
        edit.installEventFilter(self)
        view.installEventFilter(self)

    def _at_edge(self):
        """Current row is the one next to the edit (top, or bottom if
        edit_below)."""
        if isinstance(self.view, QTreeWidget):
            it = self.view.currentItem()
            step = self.view.itemBelow if self.edit_below else self.view.itemAbove
            return it is None or step(it) is None
        r = self.view.currentRow()
        return r >= self.view.count() - 1 if self.edit_below else r <= 0

    def _enter_view(self):
        if isinstance(self.view, QTreeWidget):
            if not self.view.currentItem():
                self.view.setCurrentItem(self.view.topLevelItem(0))
        elif self.view.currentRow() < 0:
            self.view.setCurrentRow(
                self.view.count() - 1 if self.edit_below else 0)
        self.view.setFocus()

    def eventFilter(self, w, ev):
        if QApplication.activePopupWidget():
            return False        # a completer/combo popup owns the keyboard
        if (ev.type() == QEvent.KeyPress
                and not ev.modifiers() & ~Qt.KeypadModifier):  # mac arrows
            if w is self.edit and self.consume_return and ev.key() in (
                    Qt.Key_Return, Qt.Key_Enter):
                self.edit.returnPressed.emit()
                return True
            into, back = ((Qt.Key_Up, Qt.Key_Down) if self.edit_below
                          else (Qt.Key_Down, Qt.Key_Up))
            if w is self.edit and ev.key() == into:
                self._enter_view()
                return True
            if w is self.view and ev.key() == back and self._at_edge():
                self.edit.setFocus()
                return True
            if w is self.edit and ev.key() == Qt.Key_Escape:
                self.view.setFocus()     # Esc always leaves the field
                return True
        return False


class _Escape(QObject):
    """Esc in a form field returns to the list it belongs to. Without this a
    QDialog rejects on Esc, so the key that means "leave this field" everywhere
    else in the app would throw the dialog away."""

    def __init__(self, w, target):
        super().__init__(w)
        self.target = target
        w.installEventFilter(self)

    def eventFilter(self, w, ev):
        if QApplication.activePopupWidget():
            return False        # let a popup close itself first
        if (ev.type() == QEvent.KeyPress and ev.key() == Qt.Key_Escape
                and not ev.modifiers() & ~Qt.KeypadModifier):
            self.target.setFocus()
            return True
        return False


def escape_to(target, *widgets):
    """Esc in any of these widgets focuses target. A second Esc, now in
    navigation position, closes the dialog the normal way."""
    for w in widgets:
        _Escape(w, target)


def bridge(edit, view, consume_return=False, edit_below=False, slash=True):
    """Wire a text field to the list/tree it filters. You also get
    "/" on the view to jump into the edit, and Esc in the edit to come back.
    A view with a second edit (a "new item" box under the list) passes
    slash=False on that one: only one edit per view may own "/"."""
    _Bridge(edit, view, consume_return, edit_below)
    if slash:
        sc = QShortcut(QKeySequence('/'), view, lambda: focus_field(edit))
        sc.setContext(Qt.WidgetShortcut)


def vim_arrows(dlg):
    """Alt+H/J/K/L replay as arrow keys in the dialog — the main window's
    window-context shortcuts don't fire while a modal dialog is open."""
    for key, arrow in [('Alt+H', Qt.Key_Left), ('Alt+J', Qt.Key_Down),
                       ('Alt+K', Qt.Key_Up), ('Alt+L', Qt.Key_Right)]:
        QShortcut(QKeySequence(key), dlg,
                  lambda a=arrow: QApplication.focusWidget() and
                  QApplication.postEvent(
                      QApplication.focusWidget(),
                      QKeyEvent(QEvent.KeyPress, a, Qt.NoModifier)))

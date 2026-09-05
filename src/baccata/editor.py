"""Baccata main window. Usage: uv run python -m baccata [project_dir]"""
import html, re, sys, threading, time
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import (QEvent, QEventLoop, QItemSelectionModel, QObject,
                            QSize, QStandardPaths, Qt, QTimer, Signal)
from PySide6.QtGui import (QAction, QFont, QIcon, QImage, QKeyEvent,
                           QKeySequence, QPalette, QPixmap, QShortcut)
from PySide6.QtWidgets import (
    QAbstractSpinBox, QApplication, QCheckBox, QComboBox, QCompleter, QDialog, QDoubleSpinBox,
    QFileDialog, QFormLayout,
    QFrame, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QRadioButton, QScrollArea, QSizePolicy,
    QSpinBox, QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QGridLayout, QVBoxLayout, QWidget)

from .keymap import (bridge, button, cheatsheet, escape_to, focus_field,
                     keyboard_cursor, native)
from .dialogs import (AddDeviceDialog, AddGaDialog, BulkGaDialog,
                     ConnectionDialog, LinkDialog, ReportDialog, ScanQrDialog, TagDialog,
                     ask, busy, info, password_edit, set_passwords_shown, warn)
from .knxip import (decode_dpt, dpt_small, encode_dpt, ia_str, ia_int,
                   ia_parts, _dpt_main)
from .knxprod import (Block, Channel, Choose, PRef, CRef, Separator,
                     active_children, iter_visible)
from .project import Project, expand_addr_template, ga_str, ga_int
from .knxdatasec import S_A_DATA, decode_fdsk, unsecure_group
from .knxsec import make_bus
from . import theme
from . import knxsecure as ks
from .knxproj import KnxProj, PasswordRequired, WrongPassword, import_knxproj

TP_RE = re.compile(r'\{\{\d+(?::([^}]*))?\}\}')   # {{0}} or {{0:default}}
HEADER_ROLE = Qt.UserRole + 1   # settings tree: groups pages, has none
TUNNEL_ROLE = Qt.UserRole + 1   # device tree: tunnel slot index

from . import __version__ as VERSION

# synthetic settings pages (build_form matches identity): Info for every
# device, IP settings for KNXnet/IP interfaces, Security for KNX Secure products
INFO_PAGE = Block('§info', 'Info', None, [])
IFACE_PAGE = Block('§iface', 'IP settings', None, [])
SECURITY_PAGE = Block('§security', 'Security', None, [])


def _ga_sec_text(g, secured):
    """The Security column: the effective state, plus whether a key is stored.

    Those are different facts and both matter. A key outlives the state that
    created it — decommission a device and its addresses go back to plain while
    the keys stay in the project, which is correct (a key belongs to the
    address, so re-securing reuses it) but is otherwise invisible and looks like
    a leak. The reverse gap is worth showing too: an address that resolves
    secured but has no key yet has not been through a download.

    A forced setting always shows; plain-and-keyless shows nothing, because that
    is the quiet default and a column of "Auto (plain)" would say nothing on
    almost every row."""
    mode = g.get('security', 'auto')
    key = bool(g.get('key'))
    if secured:
        base = 'Secured (forced)' if mode == 'on' else 'Secured'
        return base if key else base + ' — no key yet'
    base = 'Plain (forced)' if mode == 'off' else ''
    if not key:
        return base
    return (base + ' — key stored') if base else 'Key stored'


def device_pages(prog):
    """The synthetic pages a product gets, from its two INDEPENDENT capabilities.
    `tunnels` (AdditionalAddressesCount) means KNXnet/IP interface; `secure`
    (IsSecureEnabled) means KNX Secure. Neither implies the other: a secure
    actuator has no tunnels, and a pre-Secure IP interface has tunnels and no
    security object — it must NOT be offered a Security page. Kept a pure
    function of the program so all four combinations are testable without a
    product for each (tests/test_pages.py)."""
    pages = [INFO_PAGE]                      # notes + timestamps, every device
    if prog.secure:
        pages.append(SECURITY_PAGE)          # commissioning, its own action
    if prog.tunnels:
        pages.append(IFACE_PAGE)             # written by Program, like the params
    return pages

# sendable datapoint types offered when a GA has no assigned type
SEND_DPTS = [
    ('DPST-1-1', '1.001 switch'), ('DPST-3-7', '3.007 dimming'),
    ('DPST-5-1', '5.001 percent'), ('DPST-5-10', '5.010 counter'),
    ('DPST-6-10', '6.010 int8'), ('DPST-7-1', '7.001 uint16'),
    ('DPST-8-1', '8.001 int16'), ('DPST-9-1', '9.001 temperature'),
    ('DPST-12-1', '12.001 uint32'), ('DPST-13-1', '13.001 int32'),
    ('DPST-14-56', '14.056 power'), ('DPST-16-1', '16.001 text'),
    ('DPST-17-1', '17.001 scene'), ('', 'raw hex')]


def _col(*widgets, margin=0):
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(margin, margin, margin, margin)
    lay.setSpacing(6 if margin else lay.spacing())
    for x in widgets:
        lay.addWidget(x)
    return w


def _dark(pal):
    return pal.color(QPalette.Window).lightness() < 128


def _lighten(pix):
    """Make a knxprod icon (black line art, drawn for ETS's light theme) read
    on a dark background: flip the lightness of its grey pixels and leave the
    coloured ones alone, so hues survive and only the ink turns white."""
    img = pix.toImage().convertToFormat(QImage.Format_ARGB32)
    for y in range(img.height()):
        for x in range(img.width()):
            c = img.pixelColor(x, y)
            h, sat, l, a = c.getHsl()
            if a > 0 and sat < 40:
                c.setHsl(h, sat, 255 - l, a)
                img.setPixelColor(x, y, c)
    return QPixmap.fromImage(img)


def _mute(lab):
    pal = lab.palette()
    dim = pal.color(QPalette.Disabled, QPalette.WindowText)
    pal.setColor(QPalette.WindowText, dim)
    pal.setColor(QPalette.Text, dim)        # labels on a Base-coloured parent
    lab.setPalette(pal)
    return lab


def _bold(lab):
    """Heading font: bold, a point larger."""
    f = lab.font()
    f.setBold(True)
    f.setPointSize(f.pointSize() + 1)
    lab.setFont(f)
    lab.setWordWrap(True)
    return lab


def _note(text):
    """A quiet explanatory line under a caption: normal weight, muted colour,
    wrapped. _caption is bold and a point larger — that is a heading, and using
    it for a sentence of explanation shouts."""
    lab = QLabel(text)
    lab.setContentsMargins(0, 0, 0, 6)
    lab.setWordWrap(True)
    return _mute(lab)


def _caption(text):
    """Pane caption: bold, upper-case, tracked out a little -- a label on
    a rail rather than a heading in the text."""
    lab = QLabel(text.upper())
    f = lab.font()
    f.setBold(True)
    f.setLetterSpacing(QFont.PercentageSpacing, 108)
    lab.setFont(f)
    lab.setContentsMargins(0, 4, 0, 2)
    return _mute(lab)


def _empty_hint(tree, text):
    """Centred muted hint on a QTreeWidget's viewport while it has no
    rows -- the empty pane says what would fill it."""
    lab = _mute(QLabel(text, tree.viewport()))
    lab.setAlignment(Qt.AlignCenter)
    lab.setWordWrap(True)
    lay = QVBoxLayout(tree.viewport())
    lay.addWidget(lab)
    m = tree.model()

    def upd(*_):
        lab.setVisible(m.rowCount() == 0)
    for sig in (m.rowsInserted, m.rowsRemoved, m.modelReset):
        sig.connect(upd)
    lab.destroyed.connect(lambda: [sig.disconnect(upd) for sig in
                                   (m.rowsInserted, m.rowsRemoved,
                                    m.modelReset)])   # teardown order
    upd()



class _Elided(QLabel):
    """A one-line label that elides its text in the middle to the width it
    gets — a long product filename would otherwise wrap every row."""
    def __init__(self, text):
        super().__init__()
        self.full = text
        self.setToolTip(text)
        self.setMinimumWidth(60)

    def resizeEvent(self, e):
        self.setText(self.fontMetrics().elidedText(self.full, Qt.ElideMiddle,
                                                   self.width()))
        super().resizeEvent(e)


def _headline(text, icon=None):
    """ETS section headline: bold, full-strength text with the block's icon."""
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 8, 0, 2)
    lay.setSpacing(6)
    if icon:
        pic = QLabel()
        pic.setPixmap(icon.pixmap(18, 18))
        lay.addWidget(pic, 0, Qt.AlignTop)
    lay.addWidget(_bold(QLabel(text.strip())), 1)
    return w


def _notebox(text, error=False):
    """ETS note: an ⓘ icon and the text in a tinted, outlined box."""
    tint = theme.RED if error else theme.GREEN
    rgb = f'{tint.red()},{tint.green()},{tint.blue()}'
    box = QFrame()
    box.setStyleSheet(
        f'QFrame{{border:1px solid rgba({rgb},0.55); background:rgba({rgb},'
        '0.10);} QLabel{border:none;background:transparent;}')
    lay = QHBoxLayout(box)
    lay.setContentsMargins(8, 6, 8, 6)
    lay.setSpacing(8)
    mark = QLabel('\u24d8')                   # circled i
    mf = mark.font()
    mf.setPointSize(mf.pointSize() + 4)
    mark.setFont(mf)
    pal = mark.palette()
    pal.setColor(QPalette.WindowText, tint)
    mark.setPalette(pal)
    lay.addWidget(mark, 0, Qt.AlignTop)
    lab = QLabel(text)
    lab.setWordWrap(True)
    lay.addWidget(lab, 1)
    return box


def _plabel(text):
    """Parameter-row label; ETS-style leading spaces become a real indent."""
    lab = QLabel(text.strip())
    ind = len(text) - len(text.lstrip(' '))
    if ind:
        lab.setIndent(ind * 5)
    return lab


def _items(tree, children=False):
    """Top-level items of a QTreeWidget in visual order, with their
    children when asked."""
    for i in range(tree.topLevelItemCount()):
        top = tree.topLevelItem(i)
        yield top
        if children:
            yield from (top.child(j) for j in range(top.childCount()))


class BusBridge(QObject):
    """Marshals knxip reader-thread callbacks onto the Qt main thread."""
    telegram = Signal(object)
    lost = Signal(str)


class MgmtDialog(QDialog):
    """Runs a management task on a worker thread, streaming its log lines.

    Log-line style: lowercase, present tense, no period, one clause split
    with an em dash, '->' for state changes, a trailing '…' only while
    waiting, two-space indent for sub-steps. The window title carries the
    device name/IA, lines never do. The terminal line is one of
    'DONE — <what changed>.', 'FAILED — <reason>', 'CANCELLED.'; lines
    containing MISMATCH are shown red as well.

    `task(mgmt, dlg)` runs with a Mgmt on a connected bus; use dlg.line.emit
    to log. With `cancellable` (read-only tasks only — a download stopped
    halfway leaves the device half-programmed) Mgmt.wait raises Cancelled
    between telegrams; a task that sleeps or loops without waiting polls
    dlg.cancelled itself. The dialog is NOT modal — run() spins a local
    event loop until the task is done and returns, leaving the log open;
    the editor locks project edits meanwhile (see Editor._task_lock)."""
    line = Signal(str)
    done = Signal(str)                   # error message, '' on success

    def __init__(self, parent, title, bus, make_bus, task, done_msg,
                 cancellable=False, tries=1, on_report=None):
        super().__init__(parent)
        self.on_report = on_report       # Report… after the run (not cancelled)
        self.setWindowTitle(title)
        self.resize(560, 360)
        self.running = True
        self.cancelled = False
        self.err = None                  # '' = task finished successfully
        self.tip = False                 # failed on timeout/connection
        self.done_msg = done_msg
        self.tries = tries
        self.log = QPlainTextEdit(readOnly=True)
        self.btn = QPushButton('Cancel' if cancellable else 'Close')
        self.btn.setEnabled(cancellable)
        self.btn.clicked.connect(self.btn_clicked)
        self.report_btn = QPushButton('Report…')
        self.report_btn.hide()
        self.report_btn.clicked.connect(lambda: self.on_report(self))
        lay = QVBoxLayout(self)
        lay.addWidget(self.log)
        row = QHBoxLayout()
        row.addWidget(self.report_btn)
        row.addStretch(1)
        row.addWidget(self.btn)
        lay.addLayout(row)
        self.line.connect(self.append)
        self.done.connect(self.finish)
        self.loop = QEventLoop(self)
        self.done.connect(self.loop.quit)   # connected before the thread starts
        threading.Thread(target=self.work, args=(bus, make_bus, task),
                         daemon=True).start()

    def append(self, text):
        color = (theme.RED if text.startswith(('FAILED', 'CANCELLED'))
                 or 'MISMATCH' in text else
                 theme.GREEN if text.startswith('DONE') else None)
        if color is None:
            self.log.appendPlainText(text)
        else:
            self.log.appendHtml(f'<span style="color:{color.name()}">'
                                f'{html.escape(text)}</span>')

    def run(self):
        """Show and wait for the task (not for the window to close)."""
        self.show()
        if self.running:
            self.loop.exec()
        return self.err

    def btn_clicked(self):
        if self.running:                 # Cancel: worker polls self.cancelled
            self.cancelled = True
            self.btn.setEnabled(False)
        else:
            self.accept()

    def reject(self):                    # Esc: cancel if possible, never close
        if not self.running:             # a running task
            super().reject()
        elif self.btn.isEnabled():
            self.btn_clicked()

    def work(self, bus, make_bus, task):
        from .knxmgmt import Cancelled, Mgmt
        own = bus is None
        # tries > 1 (idempotent tasks only): after churn, a secure interface
        # sometimes brings up a tunnel that can't carry management — a FRESH
        # session fixes it, so retries always run on an own fresh bus, even
        # when the first attempt borrowed the monitor's (left to its owner).
        for attempt in range(self.tries):
            try:
                if own:
                    self.line.emit('connecting…')
                    bus = make_bus()
                    bus.connect()
                m = Mgmt(bus)
                if self.btn.text() == 'Cancel':
                    m.cancelled = lambda: self.cancelled
                try:
                    task(m, self)
                finally:
                    m.close()
                    if own:
                        bus.disconnect()
                self.done.emit('')
                return
            except (TimeoutError, ConnectionError, OSError) as e:
                if attempt + 1 < self.tries and not self.cancelled:
                    self.line.emit('  no answer — retrying with a fresh '
                                   'session…')
                    try:
                        if own and bus:
                            bus.disconnect()
                    except Exception:
                        pass
                    own, bus = True, None
                    time.sleep(3)
                    continue
                kind = ('timeout: ' if isinstance(e, TimeoutError) else
                        'connection: ' if isinstance(e, ConnectionError) else '')
                self.tip = bool(kind)
                self.done.emit(f'{kind}{e}')
                return
            except Cancelled:
                self.done.emit('cancelled')
                return
            except Exception as e:
                self.done.emit(str(e) or type(e).__name__)
                return

    def finish(self, err):
        self.running = False
        self.err = err
        self.append('CANCELLED.' if err == 'cancelled' else
                    self.done_msg if not err else f'FAILED — {err}')
        if err and self.tip:
            self.log.appendPlainText(
                'tip: secure interfaces free their tunnel slots after ~1 min '
                '— wait, then retry')
        self.btn.setText('Close')
        self.btn.setEnabled(True)
        if self.on_report and err != 'cancelled':
            self.report_btn.show()
        self.btn.setDefault(True)        # Enter closes once the task is done
        self.btn.setFocus()

    def closeEvent(self, e):             # no closing while the task runs
        e.ignore() if self.running else e.accept()


class Editor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.resize(1400, 800)
        self.proj = Project()
        self.dev = None          # selected Device
        self.prog = None
        self.dirty = False
        # undo: project.state() snapshots. _state mirrors the project after
        # the last mark_dirty; _saved is the state on disk
        self._state = self._saved = self.proj.state()
        self._undo, self._redo = [], []
        self._task = None        # the MgmtDialog whose task is running
        self._last_dlg = None    # the previous task's log window, if open
        self.defaults = {}
        self.values = {}         # defaults + deviations + calculated params
        self.hints = []          # (button, label, key) for the F1 help toggle
        self.hint_labels = []    # (widget, base text, key): captions
        self.form_widgets = []   # parameter-form widgets in visual order
        self._focus_pid = None   # field to refocus after a value-set rebuild
        self._icons = {}         # nav/headline icons of the selected device
        self._expanded = set()   # nav tree: channels the user opened,
        self._collapsed = set()  # pages the user closed
        self.proj_buttons = []
        self.bus = None
        self.bus_conn = ''       # connection name self.bus was made from
        self.bridge = BusBridge()
        self.bridge.telegram.connect(self.bus_row)
        self.bridge.lost.connect(self.bus_lost)

        tb = self.addToolBar('main')
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        tb.setIconSize(QSize(16, 16))
        twig = QLabel()
        twig.setPixmap(theme.pixmap(20, ground=False))
        twig.setContentsMargins(4, 0, 6, 0)
        tb.addWidget(twig)
        self.hint_acts = []      # (action, label, key)
        for label, fn, key in [
                ('New', self.new_project, 'Ctrl+N'),
                ('Open…', self.open_project, 'Ctrl+O'),
                ('Import…', self.import_ets, 'Ctrl+I'),
                ('Save', self.save_project, 'Ctrl+S'),
                ('Reload', self.reload_project, 'Ctrl+Shift+R')]:
            a = tb.addAction(label, fn)
            a.setShortcut(QKeySequence(key))
            self.hint_acts.append((a, label, key))
        self.file_acts = [a for a, *_ in self.hint_acts]   # locked by a task
        tb.addSeparator()
        self.undo_act = tb.addAction('Undo', self.undo)
        self.undo_act.setShortcut(QKeySequence.Undo)
        self.redo_act = tb.addAction('Redo', lambda: self.undo(redo=True))
        self.redo_act.setShortcuts([QKeySequence.Redo,
                                    QKeySequence('Ctrl+Shift+Z')])
        self.hint_acts += [(self.undo_act, 'Undo', 'Ctrl+Z'),
                           (self.redo_act, 'Redo', 'Ctrl+Shift+Z')]
        tb.addSeparator()
        self.hints_act = tb.addAction('Shortcuts')
        self.hints_act.setCheckable(True)
        self.hints_act.toggled.connect(self.toggle_hints)
        self.hints_act.setShortcuts([QKeySequence('Ctrl+/'), QKeySequence('F1')])
        self.hints_act.setToolTip('Show keyboard shortcuts')
        self.hint_acts.append((self.hints_act, 'Shortcuts', 'Ctrl+/'))
        pw_act = tb.addAction('Show passwords')
        pw_act.setCheckable(True)
        pw_act.toggled.connect(set_passwords_shown)
        pw_act.setShortcut(QKeySequence('Ctrl+Shift+P'))
        pw_act.setToolTip('Reveal every password field '
                          '(Security page, connections)')
        about = QAction('About Baccata', self)
        about.setMenuRole(QAction.AboutRole)   # macOS: app menu; else Help
        about.triggered.connect(self.about)
        edit = self.menuBar().addMenu('&Edit')   # mac: the standard place too
        edit.addAction(self.undo_act)
        edit.addAction(self.redo_act)
        self.menuBar().addMenu('&Help').addAction(about)

        # -- connection bar (app-level: used by monitor and programming),
        # pushed to the right edge
        stretch = QWidget()
        stretch.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(stretch)
        self.conn_combo = QComboBox()
        self.conn_combo.setMinimumWidth(180)
        self.conn_combo.currentTextChanged.connect(self.conn_picked)
        conns_btn = self._btn('Connections…', self.edit_connections, 'Alt+E')
        self.connect_btn = self._btn('Connect', self.toggle_bus, 'Alt+O')
        self.bus_status = _mute(QLabel('\N{BLACK CIRCLE} not connected'))
        self.bus_status.setContentsMargins(0, 0, 8, 0)
        for w in (self.conn_combo, conns_btn, self.connect_btn):
            tb.addWidget(w)
        pad = QWidget()
        pad.setFixedWidth(8)
        tb.addWidget(pad)
        tb.addWidget(self.bus_status)
        self.proj_buttons += [conns_btn, self.connect_btn]

        # -- devices tab
        self.dev_filter = QLineEdit(
            placeholderText='filter name/tag, :us :up :ua (unsynced/unprogrammed/unassigned)')
        self.dev_filter.setToolTip(
            'Boolean filter: & = all, | = any, e.g. "EG & light" or '
            '"EG | OG". Pseudo-tags: ":unsynced" (:us) = IA or configuration '
            'differs from the device, ":unprogrammed" (:up) = application '
            'never downloaded, ":unassigned" (:ua) = IA never written.')
        self.dev_filter.textChanged.connect(self.build_devices)
        self.dev_list = QTreeWidget()
        self.dev_list.setHeaderLabels(['IA', 'Name', 'Tags'])
        self.dev_list.headerItem().setToolTip(0, 'Individual address')
        hdr = self.dev_list.header()      # Name draggable, Tags takes the rest
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)   # IA: fits
        hdr.resizeSection(1, 170)
        self.dev_list.setToolTip('Double-click or Enter on name/IA to edit, '
                                 'tags (or T) for the tag editor.\n'
                                 'Muted IA: not the address the device has; '
                                 'muted name: configuration differs from the '
                                 'last download.')
        self.dev_list.setAlternatingRowColors(True)
        self.dev_list.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.dev_list.setIndentation(12)   # tunnel rows near-flush, arrow kept
        self.dev_list.setEditTriggers(QTreeWidget.NoEditTriggers)
        self.dev_list.setExpandsOnDoubleClick(False)   # dclick = edit, not toggle
        self.dev_list.currentItemChanged.connect(self.select_device)
        self.dev_list.itemChanged.connect(self.device_edited)
        self.dev_list.itemActivated.connect(self.device_dclick)
        dev_btns = QWidget()
        db = QVBoxLayout(dev_btns)
        db.setContentsMargins(0, 0, 0, 0)
        db.setSpacing(2)
        # row 1 edits the project (undoable); row 2 talks to the device
        rows = [[('Add…', self.add_device, 'A'),
                 ('Duplicate…', self.duplicate_device, 'D'),
                 ('Delete', self.delete_device, QKeySequence.Delete),
                 ('Set IAs…', self.set_addresses, 'S'),
                 ('Tags…', self.tag_current, 'T')],
                [('Program IA…', self.assign_address, 'I'),
                 ('Program…', self.program_device, 'P'),
                 ('Verify', self.verify_device, 'V'),
                 ('Read…', self.read_device_state, 'R')]]
        tips = ['project only — Ctrl+Z undoes', 'writes to the device']
        for row, tip in zip(rows, tips):
            rw = QHBoxLayout()
            rw.setContentsMargins(0, 0, 0, 0)
            for label, fn, key in row:
                b = self._btn(label, fn, key, on=self.dev_list)
                b.setToolTip(f'{b.toolTip()} — {tip}')
                rw.addWidget(b)
            db.addLayout(rw)

        self.objects = QTreeWidget()
        # Group addresses come first, before the name — they are what the row
        # is usually being read for; size/type/flags are reference detail.
        self.objects.setHeaderLabels(['#', 'Group addresses', 'Name', 'Function',
                                      'Size', 'Type', 'Flags'])
        self.objects.setRootIsDecorated(False)
        self.objects.setAlternatingRowColors(True)
        self.objects.headerItem().setToolTip(
            6, 'C=Communication, R=Read, W=Write, T=Transmit, U=Update')
        self.objects.setToolTip('Double-click or press Enter to assign group addresses')
        self.objects.itemActivated.connect(self.edit_links)
        self.objects.setContextMenuPolicy(Qt.CustomContextMenu)
        self.objects.customContextMenuRequested.connect(self.objects_menu)
        link_btn = self._btn('Link group addresses…', self.link_current,
                             'N', on=self.objects)

        self.blocks = QTreeWidget()
        self.blocks.setHeaderHidden(True)
        self.blocks.currentItemChanged.connect(self.build_form)
        self.blocks.itemDoubleClicked.connect(self.rename_node)
        self.blocks.itemExpanded.connect(lambda it: self._note_open(it, True))
        self.blocks.itemCollapsed.connect(lambda it: self._note_open(it, False))

        self.form_host = QScrollArea()
        self.form_host.setWidgetResizable(True)

        self.panes = [self.dev_list, self.objects, self.blocks, self.form_host]
        for w in self.panes:
            w.installEventFilter(self)

        split = QSplitter()
        split.addWidget(_col(self._cap('Devices', 'Alt+1'), self.dev_filter,
                             self.dev_list, dev_btns))
        split.addWidget(_col(self._cap('Group objects', 'Alt+2'), self.objects,
                             link_btn))
        split.addWidget(_col(self._cap('Settings', 'Alt+3'), self.blocks))
        split.addWidget(_col(self._cap('Parameters', 'Alt+4'), self.form_host))
        split.setSizes([300, 520, 220, 380])   # 5 hinted buttons fit
        _empty_hint(self.dev_list, 'No devices\n\nAdd… (A)')
        _empty_hint(self.objects, 'No group objects')
        _empty_hint(self.blocks, 'Select a device')

        # -- group address tab
        self.ga_pattern = QLineEdit(placeholderText='1/2/*, 1/?/3 or name…')
        self.ga_pattern.setMaximumWidth(240)
        self.ga_used = QComboBox()
        self.ga_used.addItems(['all', 'used', 'unused'])
        self.ga_tag = QLineEdit(placeholderText='tags: EG & light, EG | OG')
        self.ga_tag.setToolTip('Filter by linked-device tags. & = all, | = any, '
                               'e.g. "EG & light" or "EG | OG".')
        self.ga_tag.setMaximumWidth(200)
        for w in (self.ga_pattern, self.ga_tag):
            w.textChanged.connect(self.build_gas)
        self.ga_used.currentIndexChanged.connect(self.build_gas)

        self.ga_list = QTreeWidget()
        self.ga_list.setHeaderLabels(['Address', 'Name', 'Type', 'Used by',
                                      'Security'])
        self.ga_list.headerItem().setToolTip(
            4, 'Whether this address is encrypted, and whether a group key is '
               'stored for it. A key is kept when the address goes back to '
               'plain, so re-securing it reuses the same one.')
        self.ga_list.setToolTip('Double-click or Enter on address to move, '
                                'name to rename')
        self.ga_list.setRootIsDecorated(False)
        self.ga_list.setAlternatingRowColors(True)
        self.ga_list.setEditTriggers(QTreeWidget.NoEditTriggers)
        self.ga_list.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.ga_list.itemChanged.connect(self.ga_edited)
        self.ga_list.itemActivated.connect(self.ga_dclick)
        self.ga_list.installEventFilter(self)     # Return = rename

        bar = QWidget()
        h = QHBoxLayout(bar)
        h.setContentsMargins(0, 0, 0, 0)
        for w in (QLabel('Filter:'), self.ga_pattern, self.ga_used, self.ga_tag):
            h.addWidget(w)
        h.addStretch(1)                     # filters left, actions right
        for label, fn, key in [('Add GA…', self.add_ga, 'A'),
                               ('Bulk add…', self.bulk_add_ga, 'B'),
                               ('Change address…', self.change_ga, 'C'),
                               ('Security…', self.ga_security, 'S'),
                               ('Delete GA', self.delete_ga,
                                QKeySequence.Delete)]:
            h.addWidget(self._btn(label, fn, key, on=self.ga_list))
        ga_tab = _col(bar, self.ga_list, margin=8)

        # -- bus tools tab: monitor left, send/diagnostics pane right
        self.mon_filter = QLineEdit(
            placeholderText='filter source/GA/name/value…')
        self.mon_filter.textChanged.connect(self._mon_refilter)
        self.mon = QTreeWidget()
        self.mon.setHeaderLabels(['Time', 'Source', 'GA', 'Name', 'Type',
                                  'Value', 'Raw'])
        self.mon.setRootIsDecorated(False)
        self.mon.setAlternatingRowColors(True)
        self.mon.installEventFilter(self)   # Right/L -> tools pane
        self.pause_btn = self._btn('Pause', None, 'P', on=self.mon,
                                   project=False)
        self.pause_btn.setCheckable(True)

        mbar = QWidget()
        mh = QHBoxLayout(mbar)
        mh.setContentsMargins(0, 0, 0, 0)
        mh.addWidget(self.mon_filter, 1)
        mh.addWidget(self.pause_btn)
        mh.addWidget(self._btn('Clear', self.mon.clear, 'C', on=self.mon,
                               project=False))

        msplit = QSplitter()
        msplit.addWidget(_col(_caption('Monitor'), mbar, self.mon))
        msplit.addWidget(self._build_bus_tools())
        msplit.setSizes([1020, 340])
        _empty_hint(self.mon, 'No telegrams\n\nConnect to a bus')
        _empty_hint(self.ga_list, 'No group addresses\n\nAdd GA… (A)')

        tabs = QTabWidget()
        tabs.addTab(_col(split, margin=8), 'Devices')
        tabs.addTab(ga_tab, 'Group addresses')
        tabs.addTab(_col(msplit, margin=8), 'Bus tools')
        self.setCentralWidget(tabs)
        self.tabs = tabs
        self.statusBar()

        # -- keyboard navigation
        # per tab: the main view (focused on switch) and its filters (Ctrl+F)
        self.tab_views = [(self.dev_list, [self.dev_filter]),
                          (self.ga_list, [self.ga_pattern, self.ga_used,
                                          self.ga_tag]),
                          (self.mon, [self.mon_filter])]
        tabs.currentChanged.connect(lambda i: self.tab_views[i][0].setFocus())
        for i in range(3):
            QShortcut(QKeySequence(f'Ctrl+{i + 1}'), self,
                      lambda i=i: tabs.setCurrentIndex(i))
        for key, w in [('Alt+1', self.dev_list), ('Alt+2', self.objects),
                       ('Alt+3', self.blocks), ('Alt+4', self.form_host)]:
            QShortcut(QKeySequence(key), self, lambda w=w: self._jump(w))
        QShortcut(QKeySequence('Ctrl+F'), self, self._focus_filter)
        bridge(self.dev_filter, self.dev_list)
        bridge(self.ga_pattern, self.ga_list)
        bridge(self.ga_tag, self.ga_list, slash=False)   # ga_pattern owns "/"
        escape_to(self.ga_list, self.ga_used)
        bridge(self.mon_filter, self.mon)
        sc = QShortcut(QKeySequence('/'), self.objects, self._focus_filter)
        sc.setContext(Qt.WidgetShortcut)   # no filter of its own: use the tab's
        for key, arrow in [('Alt+H', Qt.Key_Left), ('Alt+J', Qt.Key_Down),
                           ('Alt+K', Qt.Key_Up), ('Alt+L', Qt.Key_Right)]:
            QShortcut(QKeySequence(key), self,
                      lambda a=arrow: self._vimkey(a))
        self.update_enabled()
        self.refresh_title()
        self.build_form()

    # ---- project ---------------------------------------------------------

    def refresh_title(self):
        p = f' — {self.proj.path}' if self.proj.path else ''
        star = ' *' if self.dirty else ''
        self.setWindowTitle(f'Baccata{p}{star}')

    def mark_dirty(self):
        """Call after any project mutation: pushes the previous state onto
        the undo stack (when something changed) and derives dirty."""
        cur = self.proj.state()
        if cur != self._state:
            self._undo.append(self._state)
            del self._undo[:-200]
            self._redo.clear()
            self._state = cur
        self.dirty = cur != self._saved
        self.refresh_title()
        self.update_enabled()

    def _reset_history(self):
        """After load/save: the current state is the saved one."""
        self._state = self._saved = self.proj.state()
        self._undo.clear()
        self._redo.clear()
        self.dirty = False
        self.refresh_title()
        self.update_enabled()

    def undo(self, redo=False):
        src, dst = (self._redo, self._undo) if redo else (self._undo, self._redo)
        if not src or self._task:
            return
        dst.append(self._state)
        self._state = src.pop()
        self.proj.restore(self._state)
        did = self.dev.id if self.dev else None   # Device objects are new
        self.dev = next((d for d in self.proj.devices if d.id == did), None)
        self.dirty = self._state != self._saved
        self.refresh_title()
        self.update_enabled()
        self.build_devices()
        self.build_gas()
        self.fill_connections()
        self.statusBar().showMessage(
            f"{'Redone' if redo else 'Undone'} — {len(src)} more", 3000)

    def update_enabled(self):
        for b in self.proj_buttons:
            b.setEnabled(bool(self.proj.path) and not self._task)
        self.undo_act.setEnabled(bool(self._undo) and not self._task)
        self.redo_act.setEnabled(bool(self._redo) and not self._task)

    def _task_lock(self, on):
        """While a bus task runs the project is read-only: the task's worker
        reads it, and the selected device must stay the task's. Browsing
        (settings pages, scrolling, the monitor) stays open."""
        for w in (self.dev_list, self.objects, self.ga_list,
                  self.form_host.widget(), self.conn_combo, self.connect_btn):
            if w is not None:
                w.setEnabled(not on)
        for a in self.file_acts:
            a.setEnabled(not on)
        self._bus_ui(bool(self.bus) and not on)   # the task owns the bus
        self.update_enabled()

    def _cap(self, text, key):
        """Pane caption; F1 shows its jump key behind the name."""
        lab = _caption(text)
        self.hint_labels.append((lab, text, key))
        return lab

    def _btn(self, label, fn, key=None, on=None, project=True):
        """keymap.button, listed in the F1 hints; `project` buttons are
        disabled until a project is open."""
        b = button(label, fn, key, on)
        if key:
            self.hints.append((b, label, key))
        if project:
            self.proj_buttons.append(b)
        return b

    def _jump(self, w):
        self.tabs.setCurrentIndex(0)
        self._focus_pane(w)

    def _focus_pane(self, w):
        """Focus a Devices-tab pane; the form pane means its first field."""
        if w is self.form_host and self.form_widgets:
            w = self.form_widgets[0]
        w.setFocus()

    def _focus_filter(self):
        """Focus this tab's filter; pressing again cycles to the next one."""
        fs = self.tab_views[self.tabs.currentIndex()][1]
        cur = QApplication.focusWidget()
        i = fs.index(cur) + 1 if cur in fs else 0
        focus_field(fs[i % len(fs)])

    def eventFilter(self, w, ev):
        if ev.type() == QEvent.FocusIn and w.property('pref_id') is not None:
            # click = edit immediately; keyboard focus = navigation mode
            self._set_editing(w, ev.reason() == Qt.MouseFocusReason
                              and not isinstance(w, QComboBox))
        elif (ev.type() == QEvent.MouseButtonPress
                and w.property('pref_id') is not None
                and not isinstance(w, QComboBox)):
            # click on an already-focused field: no FocusIn fires, so enter
            # edit mode here to keep the click = edit promise
            self._set_editing(w, True)
        elif ev.type() == QEvent.FocusOut and w.property('pref_id') is not None:
            self._set_editing(w, False)
            if (isinstance(w, QPlainTextEdit) and self.dev
                    and w.property('pref_id') == 'info.comment'
                    and w.toPlainText() != self.dev.info.get('comment', '')):
                self.set_value('info.comment', w.toPlainText())
        if ev.type() == QEvent.KeyPress:
            key = ev.key()
            mod = ev.modifiers() & ~Qt.KeypadModifier   # mac arrows set it
            if w in self.panes and mod == Qt.NoModifier and key in (
                    Qt.Key_Left, Qt.Key_Right, Qt.Key_H, Qt.Key_L):
                d = -1 if key in (Qt.Key_Left, Qt.Key_H) else 1
                self._pane_jump(w, d)
                return True
            # bus tools tab: monitor <-> tools pane
            if w is self.mon and mod == Qt.NoModifier and key in (
                    Qt.Key_Left, Qt.Key_Right, Qt.Key_H, Qt.Key_L):
                focus_field(self.send_ga.lineEdit())
                return True
            if (w.property('bus_field') and mod == Qt.NoModifier
                    and self._bus_key(w, key)):
                return True
            # Return/F2 edits in the lists (macOS Qt does not activate on
            # Return): the name column; addresses go via the C / Set IAs
            # buttons, tags via T, tunnel slots edit their IA
            if (w is self.blocks and mod == Qt.NoModifier
                    and key in (Qt.Key_F2, Qt.Key_Return, Qt.Key_Enter)):
                self.rename_node()
                return True
            if (w in (self.dev_list, self.ga_list, self.objects)
                    and mod == Qt.NoModifier
                    and key in (Qt.Key_F2, Qt.Key_Return, Qt.Key_Enter)):
                it = w.currentItem()
                if it and w is self.objects:
                    self.edit_links(it, 0)
                elif it:
                    col = 0 if it.data(0, TUNNEL_ROLE) is not None else 1
                    w.editItem(it, col)
                return True
            if (w in (self.blocks, self.dev_list) and mod == Qt.NoModifier
                    and key == Qt.Key_Space):
                it = w.currentItem()
                if it and it.childCount():
                    it.setExpanded(not it.isExpanded())
                return True
            if w.property('combo_view') and key == Qt.Key_Space:
                QApplication.sendEvent(w, QKeyEvent(   # act like Enter:
                    QEvent.KeyPress, Qt.Key_Return, Qt.NoModifier))
                return True                      # commit current + close
            if w.property('pref_id') is not None and self._param_key(w, key, mod):
                return True
        return super().eventFilter(w, ev)

    def _param_key(self, w, key, mod):
        """Parameter fields are modal: navigation mode (default on keyboard
        focus) keeps the widget inert — arrows move, Left/Right leave the
        pane, typing is swallowed; Enter/Space starts editing (combo: popup),
        Esc leaves it. Returns True when the key was consumed."""
        spin = isinstance(w, (QSpinBox, QDoubleSpinBox))
        if isinstance(w, QPushButton):   # form buttons: activate, else navigate
            if mod == Qt.NoModifier and key in (Qt.Key_Return, Qt.Key_Enter,
                                                Qt.Key_Space):
                w.click()
                return True
        elif w.property('editing'):
            if key == Qt.Key_Escape or (key == Qt.Key_Space and spin):
                self._set_editing(w, False)
                return True
            if (key in (Qt.Key_Return, Qt.Key_Enter)
                    and isinstance(w, (QLineEdit, QAbstractSpinBox))):
                self._set_editing(w, False)      # Return commits and leaves
                return False                     # (editingFinished fires)
            return False                         # normal editing keys
        if mod == Qt.ShiftModifier and key in (Qt.Key_Up, Qt.Key_Down):
            d = -1 if key == Qt.Key_Up else 1    # change the value in place
            if spin:
                w.stepBy(-d)                     # up = bigger
            elif isinstance(w, QComboBox):
                i = w.currentIndex() + d
                if 0 <= i < w.count():
                    w.setCurrentIndex(i)
                    self.set_value(w.property('pref_id'), w.currentData())
            return True
        if mod != Qt.NoModifier or key in (Qt.Key_Tab, Qt.Key_Backtab):
            return False                         # shortcuts, tab order
        if key in (Qt.Key_Left, Qt.Key_H, Qt.Key_Right, Qt.Key_L):
            self._pane_jump(self.form_host,
                            -1 if key in (Qt.Key_Left, Qt.Key_H) else 1)
            return True
        if key in (Qt.Key_Up, Qt.Key_Down):      # navigate between fields
            ws = self.form_widgets
            if w in ws:
                d = -1 if key == Qt.Key_Up else 1
                i = ws.index(w) + d
                while 0 <= i < len(ws) and not ws[i].isEnabled():
                    i += d                       # skip disabled fields
                if 0 <= i < len(ws):
                    ws[i].setFocus()
            return True
        if key in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            if isinstance(w, QComboBox):
                w.showPopup()                    # Enter/Esc in popup close it
            elif isinstance(w, QRadioButton):
                w.click()
            elif isinstance(w, QCheckBox):
                w.toggle()
            else:
                self._set_editing(w, True)
                w.selectAll()
            return True
        return True                              # navigation mode: keys inert

    def _set_editing(self, w, on):
        """Edit-mode flag + visual. Navigation mode paints the field flat
        (window background) and the focused one in the selection green --
        the cursor, same colour as the current row in the trees; Fusion's
        own 1px ring is too faint on the dark ground. Editing restores the
        normal editable look."""
        w.setProperty('editing', bool(on))
        pal = QPalette()
        if not on:
            if w.hasFocus():
                for role in (QPalette.Base, QPalette.Button):
                    pal.setColor(role, theme.GREEN_DIM)
            elif not isinstance(w, QComboBox):
                pal.setColor(QPalette.Base, pal.color(QPalette.Window))
        w.setPalette(pal)
        if isinstance(w, QPlainTextEdit):    # viewport keeps its own palette
            w.viewport().setPalette(pal)

    def _register(self, w, pref_id, form=None, label=None):
        """Wire a form widget into the modal keyboard scheme (pane navigation,
        field movement, focus restore) and optionally add its form row."""
        assert w.focusPolicy() != Qt.NoFocus, pref_id
        w.setProperty('pref_id', pref_id)
        self._set_editing(w, False)
        w.installEventFilter(self)
        self.form_widgets.append(w)
        if form is not None:
            form.addRow(_plabel(label), w) if label else form.addRow(w)
        return w

    def _line(self, pref_id, val, form, label=None, pw=False, strip=True,
              **kw):
        """A text field storing into pref_id on editingFinished."""
        e = QLineEdit(val, **kw)
        if pw:
            password_edit(e)
        e.editingFinished.connect(lambda: self.set_value(
            pref_id, e.text().strip() if strip else e.text()))
        return self._register(e, pref_id, form, label)

    def _combo(self, pref_id, items, cur, form=None, label=None):
        """An enum field: (text, data) items; stores the picked data."""
        w = QComboBox()
        w.setFocusPolicy(Qt.StrongFocus)
        w.view().setProperty('combo_view', True)
        w.view().installEventFilter(self)   # space closes the popup
        for text, v in items:
            w.addItem(text, v)
        w.setCurrentIndex(max(w.findData(cur), 0))
        w.activated.connect(lambda _: self.set_value(pref_id, w.currentData()))
        return self._register(w, pref_id, form, label)

    def _check(self, pref_id, text, on, form=None):
        """A tick box storing a bool/int."""
        w = QCheckBox(text)
        w.setStyleSheet('border:none;')
        w.setChecked(on)
        w.clicked.connect(lambda on: self.set_value(pref_id, int(on)))
        return self._register(w, pref_id, form)

    def _form_btn(self, pref_id, label, fn, tip, form=None):
        """A navigable form button."""
        b = QPushButton(label)
        b.setToolTip(tip)
        b.clicked.connect(lambda _=0: fn())
        return self._register(b, pref_id, form)

    def _pane_jump(self, w, d):
        self._focus_pane(self.panes[(self.panes.index(w) + d) % len(self.panes)])

    def _bus_field(self, w):
        """Mark a Send-to-bus widget for Up/Down/Esc handling."""
        w.setProperty('bus_field', True)
        w.installEventFilter(self)
        return w

    def _bus_fields(self):
        """Send-to-bus pane, in visual order. The value widget is replaced
        whenever the type changes, so this is computed, not stored."""
        val = [w for w in self.send_value_host.findChildren(QWidget)
               if w.property('bus_field')]
        return ([self.send_ga, self.send_dpt] + val + self.bus_buttons
                + [self.scan_btn])

    def _bus_key(self, w, key):
        """Up/Down between the Send-to-bus fields, Esc back to the monitor —
        the same contract as the parameter form, without the modal editing:
        these fields hold no project value, so typing must type."""
        if key == Qt.Key_Escape:
            self.mon.setFocus()
            return True
        if (key in (Qt.Key_Return, Qt.Key_Enter) and isinstance(w, QComboBox)
                and not w.isEditable()):
            w.showPopup()                # Qt opens it on Space alone
            return True
        if key not in (Qt.Key_Up, Qt.Key_Down):
            return False
        fs = self._bus_fields()
        i = next(n for n, f in enumerate(fs) if f is w
                 or (isinstance(f, QComboBox) and f.lineEdit() is w))
        d = -1 if key == Qt.Key_Up else 1
        i += d
        while 0 <= i < len(fs) and not (fs[i].isEnabled()
                                        and fs[i].isVisible()):
            i += d          # Type hides when the GA already carries one
        if 0 <= i < len(fs):
            fs[i].setFocus()
        return True

    def _vimkey(self, key):
        w = QApplication.focusWidget()
        if w:
            QApplication.postEvent(
                w, QKeyEvent(QEvent.KeyPress, key, Qt.NoModifier))

    def toggle_hints(self, on):
        for b, label, key in self.hints:
            b.setText(f'{label} [{native(key)}]' if on else label)
            # a hinted label must not clip: claim its width, the splitter
            # panes give way (and get it back when hints go)
            b.setMinimumWidth(
                b.fontMetrics().horizontalAdvance(b.text()) + 24 if on else 0)
        for a, label, key in self.hint_acts:
            a.setText(f'{label} [{native(key)}]' if on else label)
        for lab, label, key in self.hint_labels:
            lab.setText(f'{label} [{native(key)}]' if on else label)
        for i, label in enumerate(['Devices', 'Group addresses', 'Bus tools']):
            self.tabs.setTabText(
                i, f'{label} [{native(f"Ctrl+{i + 1}")}]' if on else label)
        # the status bar carries only keys with no widget to sit behind
        if on:
            self.statusBar().showMessage(cheatsheet())
        else:
            self.statusBar().clearMessage()

    def maybe_save(self):
        """Prompt for unsaved changes. Returns True when it's ok to proceed."""
        if not self.dirty:
            return True
        r = QMessageBox.question(
            self, 'Unsaved changes', 'Save changes to the current project?',
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
        if r == QMessageBox.Save:
            self.save_project()
            return not self.dirty
        return r == QMessageBox.Discard

    def closeEvent(self, e):
        if self._task:
            e.ignore()                   # a bus task is mid-flight
            return
        if self.maybe_save():
            self.disconnect_bus('closed')
            e.accept()
        else:
            e.ignore()

    def new_project(self):
        if not self.maybe_save():
            return
        home = QStandardPaths.writableLocation(QStandardPaths.HomeLocation)
        path, _ = QFileDialog.getSaveFileName(self, 'New project folder', home,
                                              'Baccata project (*.baccata)')
        if not path:
            return
        self.proj = Project()
        self.proj.save(path)
        self.after_load()

    def open_project(self, path=None):
        if not self.maybe_save():
            return
        home = QStandardPaths.writableLocation(QStandardPaths.HomeLocation)
        path = path or QFileDialog.getExistingDirectory(self, 'Open project', home)
        if not path:
            return
        if not (Path(path) / 'project.json').exists():
            warn(self, f'Not a Baccata project (no project.json):\n{path}',
                 'Open project')
            return
        self.proj = Project(path)
        self.after_load()

    def import_ets(self):
        """An ETS project (.knxproj) into a new Baccata project folder. The
        vendor files it carries become the catalog; devices whose program is
        not in the file are kept and painted red."""
        if not self.maybe_save():
            return
        home = QStandardPaths.writableLocation(QStandardPaths.HomeLocation)
        src, _ = QFileDialog.getOpenFileName(self, 'Import ETS project', home,
                                             'ETS project (*.knxproj)')
        if not src:
            return
        dst, _ = QFileDialog.getSaveFileName(
            self, 'New project folder for the import',
            str(Path(home) / (Path(src).stem + '.baccata')),
            'Baccata project (*.baccata)')
        if not dst:
            return
        password, prompt = None, 'Project password:'
        while True:
            try:
                kp = KnxProj(src, password)
                break
            except (PasswordRequired, WrongPassword) as e:
                if isinstance(e, WrongPassword):
                    prompt = 'Wrong password. Project password:'
                password, ok = QInputDialog.getText(
                    self, 'Import ETS project', prompt, QLineEdit.Password)
                if not ok:
                    return
            except Exception as e:
                warn(self, f'Cannot read {src}:\n{e}', 'Import ETS project')
                return
        proj = Project()
        proj.save(dst)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            report = import_knxproj(proj, kp)
            proj.save()
        except Exception as e:
            warn(self, f'Import failed:\n{e}', 'Import ETS project')
            return
        finally:
            QApplication.restoreOverrideCursor()
        self.proj = proj
        self.after_load()
        info(self, '\n'.join(report), 'Import ETS project')

    def save_project(self):
        if not self.proj.path:
            return self.new_project()
        self.proj.save()
        self._saved = self._state = self.proj.state()
        self.dirty = False
        self.refresh_title()
        self.statusBar().showMessage(f'Saved {self.proj.path}', 3000)

    def reload_project(self):
        """Reload the saved state from disk, discarding edits."""
        if not (self.proj and self.proj.path):
            return
        if self.dirty and not ask(self, 'Reload project',
                                  'Discard all unsaved changes and reload '
                                  'the saved project?'):
            return
        self.proj = Project(self.proj.path)
        self.after_load()
        self.statusBar().showMessage(f'Reloaded {self.proj.path}', 3000)

    def about(self):
        box = QMessageBox(self)
        box.setWindowTitle('About Baccata')
        box.setIconPixmap(theme.pixmap(96))
        box.setText(
            f'<h3>Baccata</h3>'
            f'<p>Version {VERSION}</p>'
            '<p>A free KNX project editor and commissioning tool.</p>'
            '<p>License: GPL-3.0-or-later</p>'
            '<p><a href="https://github.com/b0bs0n/baccata">'
            'github.com/b0bs0n/baccata</a></p>')
        box.exec()

    def after_load(self):
        self.dev = self.prog = None
        self.disconnect_bus('not connected')
        self._reset_history()
        self.build_devices()
        self.build_gas()
        self.fill_connections()

    # ---- bus -------------------------------------------------------------

    def fill_connections(self):
        self.conn_combo.blockSignals(True)
        self.conn_combo.clear()
        for c in self.proj.connections:
            self.conn_combo.addItem(c['name'])
        if self.proj.active_connection:
            self.conn_combo.setCurrentText(self.proj.active_connection)
        self.conn_combo.blockSignals(False)

    def conn_picked(self, name):
        if name and name != self.proj.active_connection:
            self.proj.active_connection = name
            self.mark_dirty()

    def edit_connections(self):
        if ConnectionDialog(self, self.proj).exec():
            self.mark_dirty()
            self.fill_connections()

    def _connect_bus(self, c):
        """Create + connect the monitor bus from config `c`; raises on failure."""
        bus = make_bus(c, on_telegram=self.bridge.telegram.emit,
                       on_disconnect=self.bridge.lost.emit)
        bus.connect()
        self.bus, self.bus_conn = bus, c.get('name', '')
        self.connect_btn.setText('Disconnect')
        self._bus_state(f'connected — own address {ia_str(bus.ia)}')
        self._bus_ui(True)

    def toggle_bus(self):
        if self.bus:
            self.disconnect_bus('not connected')
            return
        c = self.proj.connection()
        if not c or not c.get('host'):
            info(self, 'Configure a connection first (Connections…).',
                 'Connect')
            return
        try:
            self._connect_bus(c)
        except (OSError, ConnectionError, ValueError) as e:
            warn(self, f'Connect failed: {e}', 'Connect')

    def _auto_reconnect(self, tries=10):
        """Bring the monitor back up after a task killed the borrowed session
        (typically the interface restarting to apply settings). Retries on a
        timer — the interface needs a while to reboot."""
        if self.bus:
            return
        c = self.proj.connection()
        if not (c and c.get('host')):
            return
        try:
            self._connect_bus(c)
        except (OSError, ConnectionError, ValueError):
            if tries > 1:
                self._bus_state('connection lost — reconnecting…')
                QTimer.singleShot(3000, lambda: self._auto_reconnect(tries - 1))
            else:
                self._bus_state('reconnect failed — connect manually '
                                '(interface IP may have changed)')

    def _bus_state(self, text):
        """Status label in the twig's colours: green on the bus, red when it
        was lost, muted when simply not connected."""
        self.bus_status.setText(f'\N{BLACK CIRCLE} {text}')
        pal = self.bus_status.palette()
        pal.setColor(QPalette.WindowText,
                     theme.GREEN.lighter(150) if text.startswith('connected') else
                     theme.INK_DIM if text == 'not connected' else theme.RED)
        self.bus_status.setPalette(pal)

    def disconnect_bus(self, reason):
        if self.bus:
            b, self.bus = self.bus, None
            b.disconnect()
        self.connect_btn.setText('Connect')
        self._bus_state(reason)
        self._bus_ui(False)

    def bus_lost(self, reason):
        self.disconnect_bus(f'connection lost: {reason}')   # idempotent

    def bus_row(self, t):
        if self.pause_btn.isChecked() or not t.group:
            return
        g = self.proj.gas.get(t.dst, {})
        src_dev = next((d.name for d in self.proj.devices
                        if d.ia == ia_str(t.src)), '')
        lock, val = '', ''
        if t.apci10 == S_A_DATA:          # Data Secure group telegram
            lock = '\U0001f512 '
            key = ks.group_key(self.proj, t.dst, mint=False)
            if key is None:
                t.apci = 'secure: no key'   # ciphertext stays in the data column
            else:
                try:
                    t = unsecure_group(key, t)
                except ValueError:
                    t.apci = 'secure: bad MAC'
        if t.apci10 != S_A_DATA and t.apci != 'read':
            val = decode_dpt(g.get('dpt', ''), t.data)
        it = QTreeWidgetItem([
            datetime.now().strftime('%H:%M:%S.%f')[:-3],
            f'{ia_str(t.src)} {src_dev}'.strip(), ga_str(t.dst),
            g.get('name', ''), lock + t.apci, val, t.data.hex(' ')])
        hide = not self._mon_match(it)
        it.setHidden(hide)
        self.mon.addTopLevelItem(it)
        if self.mon.topLevelItemCount() > 5000:
            self.mon.takeTopLevelItem(0)
        if not hide:
            self.mon.scrollToBottom()

    def _mon_match(self, it):
        q = self.mon_filter.text().strip().lower()
        return not q or any(q in it.text(c).lower() for c in (1, 2, 3, 5))

    def _mon_refilter(self):
        for i in range(self.mon.topLevelItemCount()):
            it = self.mon.topLevelItem(i)
            it.setHidden(not self._mon_match(it))

    # ---- bus tools pane --------------------------------------------------

    def _build_bus_tools(self):
        """Right pane of the Bus tools tab: send-to-bus + diagnostics."""
        self.send_ga = QComboBox()
        self.send_ga.setEditable(True)
        self.send_ga.setInsertPolicy(QComboBox.NoInsert)
        comp = self.send_ga.completer()
        comp.setCompletionMode(QCompleter.PopupCompletion)
        comp.setFilterMode(Qt.MatchContains)
        self.send_ga.lineEdit().setPlaceholderText('1/2/3 or pick…')
        self._bus_field(self.send_ga)   # keys land on the combo (Qt 6: the
        self._bus_field(self.send_ga.lineEdit())   # edit's focus proxy)
        self.send_ga.currentIndexChanged.connect(self._send_ga_changed)
        self.send_ga.lineEdit().editingFinished.connect(self._send_ga_changed)
        self.send_type = _mute(QLabel())         # locked type (GA has a DPT)
        self.send_dpt = QComboBox()              # manual pick (untyped GA)
        for dpt, label in SEND_DPTS:
            self.send_dpt.addItem(label, dpt)
        self.send_dpt.currentIndexChanged.connect(self._send_dpt_changed)
        type_host = QWidget()
        th = QVBoxLayout(type_host)
        th.setContentsMargins(0, 0, 0, 0)
        th.addWidget(self.send_type)
        th.addWidget(self.send_dpt)
        self.send_value_host = QWidget()
        QHBoxLayout(self.send_value_host).setContentsMargins(0, 0, 0, 0)
        self._send_get = lambda: None
        self._send_locked = self._send_shown = ''

        sform = QFormLayout()
        sform.addRow('Address', self.send_ga)
        sform.addRow('Type', type_host)
        sform.addRow('Value', self.send_value_host)
        write_btn = self._btn('Write', self.send_write, 'Alt+W', project=False)
        read_btn = self._btn('Read', self.send_read, 'Alt+D', project=False)
        read_btn.setToolTip('Send a group read — the answer shows up in '
                            'the monitor')
        self.bus_buttons = [write_btn, read_btn]
        self._bus_ui(False)
        srow = QHBoxLayout()
        srow.addWidget(write_btn)
        srow.addWidget(read_btn)
        srow.addStretch(1)

        self.scan_btn = self._btn('Scan addresses…', self.scan_addresses)

        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 0, 0, 0)
        lay.addWidget(_caption('Send to bus'))
        lay.addLayout(sform)
        lay.addLayout(srow)
        lay.addSpacing(12)
        lay.addWidget(_caption('Diagnostics'))
        lay.addWidget(self.scan_btn, 0, Qt.AlignLeft)
        lay.addStretch(1)
        for b in (self.send_dpt, *self.bus_buttons, self.scan_btn):
            self._bus_field(b)              # Up/Down/Esc in the tools pane
        self._send_ga_changed()
        return w

    def _bus_ui(self, connected):
        for b in self.bus_buttons:
            b.setEnabled(connected)

    def _fill_send_gas(self):
        cur = self.send_ga.currentText()
        self.send_ga.blockSignals(True)
        self.send_ga.clear()
        for ga in sorted(self.proj.gas):
            self.send_ga.addItem(
                f'{ga_str(ga)}  {self.proj.gas[ga]["name"]}'.rstrip(), ga)
        self.send_ga.setCurrentIndex(-1)
        self.send_ga.setEditText(cur)
        self.send_ga.blockSignals(False)
        self._send_ga_changed()

    def _send_ga_val(self):
        """The GA to send to (int), from the picked item or typed text."""
        t = self.send_ga.currentText().strip()
        if not t:
            return None
        try:
            return ga_int(t.split()[0])
        except ValueError:
            i = self.send_ga.currentIndex()
            return self.send_ga.itemData(i) if i >= 0 else None

    def _send_ga_changed(self, *_):
        ga = self._send_ga_val()
        dpt = self.proj.gas.get(ga, {}).get('dpt', '') if ga is not None else ''
        self._send_locked = dpt          # assigned type wins over the picker
        self.send_type.setVisible(bool(dpt))
        self.send_dpt.setVisible(not dpt)
        if dpt:
            self.send_type.setText(self.proj.dpt_name(dpt))
        self._send_dpt_changed()

    def _send_dpt(self):
        return self._send_locked or self.send_dpt.currentData()

    def _send_dpt_changed(self, *_):
        dpt = self._send_dpt()
        lay = self.send_value_host.layout()
        if dpt == self._send_shown and lay.count():   # keep the typed value
            return
        self._send_shown = dpt
        while lay.count():
            w = lay.takeAt(0).widget()
            if w:
                w.setParent(None)      # out of findChildren() before it dies
                w.deleteLater()
        w, self._send_get = self._send_value_widget(dpt)
        lay.addWidget(w)
        for v in w.findChildren(QWidget) + [w]:
            if (v.focusPolicy() != Qt.NoFocus
                    and not isinstance(v.parent(), QAbstractSpinBox)):
                self._bus_field(v)       # not a spin box's inner line edit

    def _send_value_widget(self, dpt):
        """(widget, getter) for entering a value of the given type. The getter
        returns what encode_dpt expects (hex text for the raw fallback)."""
        main = _dpt_main(dpt)
        if main == 1:
            c = QComboBox()
            c.addItem('off', False)
            c.addItem('on', True)
            return c, c.currentData
        if main == 3:
            c = QComboBox()
            c.addItems(['up', 'down', 'stop'])
            s = QSpinBox()
            s.setRange(1, 7)
            s.setToolTip('step code (1 = coarsest)')
            host = QWidget()
            h = QHBoxLayout(host)
            h.setContentsMargins(0, 0, 0, 0)
            h.addWidget(c)
            h.addWidget(s)
            return host, lambda: ((False, 0) if c.currentText() == 'stop'
                                  else (c.currentText() == 'up', s.value()))
        if main == 5:
            s = QSpinBox()
            if dpt == 'DPST-5-1':
                s.setRange(0, 100)
                s.setSuffix(' %')
            else:
                s.setRange(0, 255)
            return s, s.value
        if main in (6, 7, 8, 12, 13):
            s = QSpinBox()
            s.setRange(*{6: (-128, 127), 7: (0, 65535), 8: (-32768, 32767),
                         12: (0, 2**31 - 1), 13: (-2**31, 2**31 - 1)}[main])
            return s, s.value
        if main in (9, 14):
            s = QDoubleSpinBox()
            if main == 9:
                s.setRange(-671088.64, 670760.96)
                s.setDecimals(2)
            else:
                s.setRange(-1e12, 1e12)
                s.setDecimals(3)
            return s, s.value
        if main == 16:
            e = QLineEdit()
            e.setMaxLength(14)
            return e, e.text
        if main == 17:
            s = QSpinBox()
            s.setRange(1, 64)
            return s, s.value
        e = QLineEdit(placeholderText='hex bytes, e.g. 00 1a')
        return e, e.text

    def send_write(self):
        self._send(lambda ga: self.bus.group_write(
            ga, self._send_data(), key=self._send_key(ga),
            small=dpt_small(self._send_dpt()) if self._send_dpt() else None))

    def send_read(self):                      # the answer shows in the monitor
        self._send(lambda ga: self.bus.group_read(ga, key=self._send_key(ga)))

    def _send(self, op):
        ga = self._send_ga_val()
        if ga is None:
            info(self, 'Enter or pick a group address first.', 'Send to bus')
            return
        try:
            op(ga)
        except (ValueError, ConnectionError, OSError) as e:
            warn(self, str(e), 'Send to bus')

    def _send_data(self):
        data = encode_dpt(self._send_dpt(), self._send_get())
        if not data:
            raise ValueError('empty payload')
        return data

    def _send_key(self, ga):
        """The group key when `ga` resolves to secured (so the send matches
        what its devices expect), None for a plain address."""
        if not ks.resolve_ga(self.proj, ga):
            return None
        key = ks.group_key(self.proj, ga, mint=False)
        if key is None:
            raise ValueError(f'{ga_str(ga)} is secured but has no group key '
                             'yet — download a device on it first')
        return key

    # ---- device list -----------------------------------------------------

    def build_devices(self):
        cur = self.dev
        expanded = {it.data(0, Qt.UserRole).id for it in _items(self.dev_list)
                    if it.isExpanded()}
        selected = {i.data(0, Qt.UserRole).id
                    for i in self.dev_list.selectedItems()
                    if i.data(0, TUNNEL_ROLE) is None}
        self.dev_list.blockSignals(True)
        self.dev_list.clear()
        restore = None
        fp = {d.id: ks.device_fingerprint(self.proj, d)
              for d in self.proj.devices}
        unsynced = {d.id for d in self.proj.devices
                    if not d.ia_synced() or not d.app_synced(fp[d.id])}
        devs = sorted(self.proj.filter_devices(self.dev_filter.text(), unsynced),
                      key=lambda d: self._ia_key(d.ia))
        dim = self.dev_list.palette().brush(QPalette.Disabled, QPalette.Text)
        for d in devs:
            it = QTreeWidgetItem([d.ia, d.name, ', '.join(d.tags)])
            it.setToolTip(2, '\n'.join(d.tags))   # column clips long lists
            it.setFlags(it.flags() | Qt.ItemIsEditable)
            it.setData(0, Qt.UserRole, d)
            # what the device does not hold (yet, or any more) reads muted
            if not d.ia_synced():
                it.setForeground(0, dim)
            if not d.app_synced(fp[d.id]):
                it.setForeground(1, dim)
            prog = self.proj.program_or_none(d)
            if prog is None:        # imported without its application program
                it.setForeground(1, theme.RED)
                it.setToolTip(1, 'Product not in the project: its application '
                                 'program was not in the imported file')
            self.dev_list.addTopLevelItem(it)
            # interface tunnel slots: same address space, so ETS lists them
            # as collapsible children of the interface; addresses editable
            tuns = d.iface.get('tunnels', [])
            for i in range(prog.tunnels if prog else 0):
                ch = QTreeWidgetItem([tuns[i] if i < len(tuns) else '',
                                      f'Tunnel {i + 1}', ''])
                ch.setFlags(ch.flags() | Qt.ItemIsEditable)
                ch.setData(0, Qt.UserRole, d)
                ch.setData(0, TUNNEL_ROLE, i)
                ch.setForeground(1, dim)
                it.addChild(ch)
            it.setExpanded(d.id in expanded)
            it.setSelected(d.id in selected)
            if d is cur:
                restore = it
        self.dev_list.blockSignals(False)
        # fresh load selects the first device; a filter that hides the
        # current one selects nothing, so the context change is evident
        if len(selected) > 1:   # keep a multi-selection across rebuilds
            if restore:
                self.dev_list.setCurrentItem(restore, 0,
                                             QItemSelectionModel.NoUpdate)
        else:
            self.dev_list.setCurrentItem(
                restore or (None if cur else self.dev_list.topLevelItem(0)))
        if self.dev_list.currentItem() is None:   # nothing fired the signal
            self.select_device()
        else:
            self.dev_list.scrollToItem(self.dev_list.currentItem())

    @staticmethod
    def _ia_key(ia):
        try:
            return ia_int(ia)
        except (ValueError, AttributeError):
            return 1 << 24                # unparseable addresses sort last

    def _ia_error(self, ia, own):
        """Why `ia` cannot be taken by the row that currently holds `own`."""
        try:
            ia_parts(ia)
        except ValueError as e:
            return str(e)
        if ia != own and ia in self.proj.used_ias():
            return f'{ia} is already in use'

    def _revert(self, tree, it, col, text):
        """Undo a rejected in-place edit without re-firing itemChanged."""
        tree.blockSignals(True)
        it.setText(col, text)
        tree.blockSignals(False)

    @staticmethod
    def _set_tunnel(d, idx, ia):
        tuns = d.iface.setdefault('tunnels', [])
        tuns += [''] * (idx + 1 - len(tuns))
        tuns[idx] = ia                   # '' = keep the device's current one
        if not any(tuns):
            d.iface.pop('tunnels')

    def device_edited(self, it, col):
        d = it.data(0, Qt.UserRole)
        idx = it.data(0, TUNNEL_ROLE)
        if idx is not None:              # tunnel slot: only the IA is editable
            if col != 0:
                return
            old = self._row_ia(d, idx)
            ia = it.text(0).strip()
            err = ia and self._ia_error(ia, old)
            if err:
                warn(self, err, 'Address')
                self._revert(self.dev_list, it, 0, old)
                return
            self._set_tunnel(d, idx, ia)
            self.mark_dirty()
            self.refresh()               # Security page shows tunnel IAs
            return
        if col == 1:
            d.name = it.text(1)
        elif col == 0:
            ia = it.text(0).strip()
            err = self._ia_error(ia, d.ia)
            if err:
                warn(self, err, 'Address')
                self._revert(self.dev_list, it, 0, d.ia)
                return
            old = d.ia
            d.ia = ia
            self.mark_dirty()
            self._move_tunnels(d, old, ia)
            # deferred: build_devices clears the tree, destroying the edited
            # item while Qt's edit-commit path still holds it
            QTimer.singleShot(0, lambda: (self.build_devices(),   # re-sort
                                          self.build_gas(),
                                          self.refresh()))  # tunnel IA defaults
            return
        self.mark_dirty()
        self.build_gas()

    def device_dclick(self, it, col):
        if it.data(0, TUNNEL_ROLE) is not None:
            if col == 0:                  # tunnel slot: only the IA edits
                self.dev_list.editItem(it, 0)
            return
        if col == 2:                      # tags -> popup editor, whole selection
            self.edit_tags(it)
        else:
            self.dev_list.editItem(it, col)

    def edit_tags(self, it):
        devs = self._selected_devices()
        if it.data(0, Qt.UserRole) not in devs:
            devs = [it.data(0, Qt.UserRole)]
        dlg = TagDialog(self, self.proj, devs)
        if dlg.exec():
            self.mark_dirty()
            self.build_devices()
            self.build_gas()

    def tag_current(self):
        """T on the device list. Not device_dclick: a double-click on a tunnel
        row means "edit this slot's address", but T on one means "tag the
        interface it belongs to" — the row carries that device, so tag it."""
        it = self.dev_list.currentItem()
        if it:
            self.edit_tags(it)

    def select_device(self, *_):
        it = self.dev_list.currentItem()
        self.dev = it.data(0, Qt.UserRole) if it else None
        self._icons = {}
        self._expanded, self._collapsed = set(), set()
        if self.dev:
            self.prog = self.proj.program_or_none(self.dev)
            self.defaults = self.prog.defaults() if self.prog else {}
        else:
            self.prog, self.defaults = None, {}
        self.refresh()

    def add_device(self):
        dlg = AddDeviceDialog(self, self.proj)
        if not dlg.exec() or not dlg.result:
            return
        fn, apid, name = dlg.result
        self.dev = self.proj.add_device(self.proj.path / 'catalog' / fn, apid, name)
        self.mark_dirty()
        self.build_devices()

    def duplicate_device(self):
        """Copies of the selected device: settings, tags and links, fresh
        IAs in its line. The copies become the selection."""
        if not self.dev:
            return
        n, ok = QInputDialog.getInt(self, 'Duplicate device',
                                    f'Copies of "{self.dev.name}":', 1, 1, 255)
        if not ok:
            return
        try:
            copies = self.proj.duplicate(self.dev, n)
        except ValueError as e:                  # line full
            warn(self, str(e), 'Duplicate device')
            copies = []
        if not copies:
            return
        self.dev = copies[0]
        self.mark_dirty()
        self.build_devices()
        ids = {d.id for d in copies}
        for it in _items(self.dev_list):
            it.setSelected(it.data(0, Qt.UserRole).id in ids)
        self.build_gas()

    def _selected_devices(self):
        """Selected device rows in visual order (tunnel rows excluded)."""
        return [it.data(0, Qt.UserRole) for it in _items(self.dev_list)
                if it.isSelected()]

    def delete_device(self):
        devs = self._selected_devices()
        if not devs:
            return
        n = sum(len(v) for d in devs for v in d.links.values())
        for d in devs:
            self.proj.remove_device(d)
        self.dev = None
        self.mark_dirty()
        self.build_devices()
        self.build_gas()
        what = (f'"{devs[0].name}"' if len(devs) == 1
                else f'{len(devs)} devices')
        links = f', {n} link(s)' if n else ''
        self.statusBar().showMessage(   # no confirm: Ctrl+Z is the way back
            f'Deleted {what}{links} — {native("Ctrl+Z")} undoes', 5000)

    def _selected_rows(self):
        """Selected items in visual order — device rows and tunnel-slot
        rows alike."""
        return [it for it in _items(self.dev_list, children=True)
                if it.isSelected()]

    @staticmethod
    def _row_ia(d, idx):
        if idx is None:
            return d.ia
        tuns = d.iface.get('tunnels', [])
        return tuns[idx] if idx < len(tuns) else ''

    def set_addresses(self):
        """Renumber the selected rows (devices and tunnel slots) — a
        project-side edit; Program IA writes an address to hardware.
        Single row: inline edit. Multi: start address (sequential, skips
        used) or a template like 2.{n+2}.{x+3}."""
        items = self._selected_rows()
        if not items and self.dev_list.currentItem():
            items = [self.dev_list.currentItem()]
        if not items:
            info(self, 'Select one or more rows first.', 'Addresses')
            return
        if len(items) == 1:
            self.dev_list.editItem(items[0], 0)
            return
        rows = [(it.data(0, Qt.UserRole), it.data(0, TUNNEL_ROLE))
                for it in items]
        text, ok = QInputDialog.getText(
            self, 'Set IAs',
            f'Start address for {len(rows)} rows (sequential), or a\n'
            f'template: {{}} = math, n = row number, x = old part,\n'
            f'e.g. 2.{{n+2}}.{{x+3}}:',
            text=self.proj.free_ia())
        if not ok or not text.strip():
            return
        text = text.strip()
        olds = [self._row_ia(d, i) for d, i in rows]
        # numbers held by anything not being renumbered stay reserved
        used = self.proj.used_ias() - set(olds)
        if '{' in text:
            try:
                if '' in olds:
                    raise ValueError('a template needs a current address '
                                     'on every selected row')
                news = expand_addr_template(text, olds, '.')
                for ia in news:
                    ia_parts(ia)
                if len(set(news)) != len(news):
                    raise ValueError('duplicate target addresses')
                for ia in news:
                    if ia in used:
                        raise ValueError(f'{ia} is already in use')
            except ValueError as e:
                warn(self, str(e), 'Addresses')
                return
            mapping = [(d, idx, ia) for (d, idx), ia in zip(rows, news)]
        else:
            try:
                a, l, n = ia_parts(text)
            except ValueError as e:
                warn(self, str(e), 'Addresses')
                return
            mapping = []
            for d, idx in rows:
                while n < 256 and f'{a}.{l}.{n}' in used:
                    n += 1
                if n > 255:
                    warn(self, f'Line {a}.{l} has no free address', 'Addresses')
                    return                   # nothing applied
                mapping.append((d, idx, f'{a}.{l}.{n}'))
                n += 1
        for d, idx, ia in mapping:
            if idx is None:
                d.ia = ia
            else:
                self._set_tunnel(d, idx, ia)
        self.mark_dirty()
        # a renumbered interface should carry its explicit tunnels along —
        # unless the same renumber already set them
        touched = {id(d) for d, idx, _ in mapping if idx is not None}
        for (d, idx, ia), old in zip(mapping, olds):
            if idx is None and id(d) not in touched:
                self._move_tunnels(d, old, ia)
        self.build_devices()
        self.build_gas()

    def _move_tunnels(self, d, old_ia, new_ia):
        """Explicit tunnel addresses live in the interface's line — when the
        interface moves to another area/line, offer to move them along
        (keeping the last number). Empty entries already follow the default."""
        tuns = d.iface.get('tunnels', [])
        if not any(tuns):
            return
        try:
            oa, ol, _ = ia_parts(old_ia)
            na, nl, _ = ia_parts(new_ia)
        except ValueError:
            return
        if (oa, ol) == (na, nl):
            return
        used = self.proj.used_ias() - {t for t in tuns if t}
        moved, skipped = [], 0
        for t in tuns:
            try:
                tgt = f'{na}.{nl}.{ia_parts(t)[2]}'
            except ValueError:
                moved.append(t)              # '' = default, follows by itself
                continue
            if tgt in used:
                moved.append(t)
                skipped += 1
            else:
                moved.append(tgt)
        if moved == tuns:
            return
        msg = (f'"{d.name}" moved to line {na}.{nl}, but its tunnel '
               f'addresses are set explicitly.\n\nMove them into line '
               f'{na}.{nl} too (keeping the last number)?')
        if skipped:
            msg += f'\n\n({skipped} left unchanged — target already in use.)'
        if ask(self, 'Tunnel addresses', msg):
            d.iface['tunnels'] = moved

    def _stamp(self, key):
        """Record a successful write on the selected device: timestamp plus
        the sync marker (what the device now holds), and save — project.json
        follows the bus. Not an undo step: the write already cut the history."""
        self.dev.info[key] = datetime.now().isoformat(timespec='seconds')
        if key == 'programmed':
            self.dev.info['programmed_fp'] = ks.device_fingerprint(self.proj,
                                                                   self.dev)
        else:                                            # 'ia_assigned'
            self.dev.info['ia_written'] = self.dev.ia
        self._commit()
        self.build_devices()          # the row's muted IA/name follow info
        self.refresh()

    def _commit(self):
        """Record the outcome of a bus write: not an undo step (the write
        already cut the history) and saved — project.json follows the bus."""
        self._state = self.proj.state()
        self.save_project()

    def _conn_cfg(self):
        """Active connection config for a mgmt task, or None (with a hint)
        when neither a live bus nor a usable config exists."""
        c = self.proj.connection()
        if not self.bus and not (c and c.get('host')):
            info(self, 'Connect to the bus or configure a connection first '
                 '(Connections…).', 'Bus task')
            return None
        return c or {}

    def run_mgmt(self, title, task, done_msg, cancellable=False, tries=1,
                 write=False, on_report=None):
        """Run task(mgmt, dlg) in a MgmtDialog. Borrows the live monitor bus
        if it matches the selected connection (and leaves it up), else opens
        one from the active connection config. The mgmt task owns the bus via
        raw_hook while it runs — no concurrent mgmt tasks. `tries` > 1 retries
        connect+task on a fresh session — only for tasks that are safe to
        re-run. If the borrowed session dies during the task (interface
        restart), the monitor is reconnected afterwards. Returns True when
        the task finished without an error.

        The dialog is not modal: the log stays open, the app stays
        readable, and the project is locked (_task_lock) until the task is
        done. One task at a time. `write` = the task changes the device: the
        project is saved first (a key that reaches a device but not
        project.json is unrecoverable) and, as what went to the bus can't
        be undone, the undo history ends here. Read-only tasks keep it."""
        if self._task:
            info(self, 'A bus task is still running.', 'Bus task')
            return False
        c = self._conn_cfg()
        if c is None:
            return False
        bus = self.bus
        if bus and c.get('host') and c.get('name') != self.bus_conn:
            bus = None            # combo picks another interface: honor it
        if self._last_dlg:
            self._last_dlg.close()   # one finished log window at a time
            self._last_dlg.deleteLater()
        if write:
            self.save_project()
            if not self.proj.path:          # no folder chosen: nothing saved
                return False
            self._undo.clear()
            self._redo.clear()
        dlg = MgmtDialog(self, title, bus, lambda: make_bus(c),
                         task, done_msg, cancellable=cancellable, tries=tries,
                         on_report=on_report)
        self._task = self._last_dlg = dlg
        self._task_lock(True)
        if self.bus and bus is None:
            dlg.line.emit(f'using connection "{c.get("name", "")}" '
                          f'(monitor stays on "{self.bus_conn}")')
        try:
            dlg.run()
        finally:
            self._task = None
            self._task_lock(False)
        if bus is not None and self.bus is None:
            self._auto_reconnect()
        return dlg.err == ''

    def program_device(self):
        if not self.dev:
            return
        # Mint any missing group keys before writing — run_mgmt saves them:
        # a key that reaches a device but not project.json is unrecoverable,
        # and every other device on that address needs the same one.
        minted = ks.ensure_group_keys(self.proj)
        if minted:
            self.mark_dirty()
            self.build_gas()
        gsec = ''
        try:
            g = ks.device_group_security(self.proj, self.dev)
        except RuntimeError as e:               # e.g. a mixed group object
            warn(self, str(e), 'Program device')
            return
        if g and g['keys']:
            gsec = (f'\n\nSecures {len(g["keys"])} group address(es): '
                    + ', '.join(ga_str(x) for x in g['gas']) + '.')
        iface = bool(self.prog and self.prog.tunnels)
        if iface:
            gsec += ('\n\nIncludes the IP settings; a changed IP address may '
                     'require updating the connection host.')
        if not ask(self, 'Program device',
                   f'Download the current configuration into\n'
                   f'"{self.dev.name}" at {self.dev.ia}?\n\n'
                   'This overwrites the device\'s memory and restarts it.' + gsec):
            return
        from .knxiface import apply_device
        ia = ia_int(self.dev.ia)

        def task(m, d):
            if iface:        # IP settings first; program's restart applies them
                apply_device(m, ia, self.dev.iface, log=d.line.emit,
                             restart=False)
            m.program(self.proj, self.dev, log=d.line.emit)
        if self.run_mgmt(f'Program {self.dev.name} ({self.dev.ia})', task,
                         'DONE — device programmed and restarted.',
                         write=True):
            self._stamp('programmed')

    def verify_device(self):
        """Read-only check of the device against the project (no confirm —
        nothing is written). Differences are logged semantically."""
        if not self.dev or not self.dev.ia:
            return
        dev, res = self.dev, {}

        def task(m, d):
            try:
                m.verify(self.proj, dev, log=d.line.emit)
            finally:
                res['result'] = m.last_verify
        self.run_mgmt(f'Verify {dev.name} ({dev.ia})', task, 'DONE.',
                      cancellable=True,
                      on_report=lambda dlg: self.show_report(dev, res, dlg))

    def show_report(self, dev, res, dlg):
        """The verify report for `dev` (res['result'] from the task, or an
        error-only one when the connection failed before it ran)."""
        from . import report
        from .knxmgmt import VerifyResult
        result = res.get('result') or VerifyResult(error=dlg.err or '')
        title, body = report.verify_report(self.proj, dev, result,
                                           self.proj.connection())
        ReportDialog(self, body, report.github_issue_url(title, body)).exec()

    def read_device_state(self):
        """Read the device's programmed state and, on confirm, import it
        into the project (params, links, new GAs)."""
        if not self.dev or not self.dev.ia:
            return
        res = {}

        def task(m, d):
            st = m.read_device(self.proj, self.dev, log=d.line.emit)
            d.line.emit(f'decoded {len(st["params"])} parameter(s), '
                        f'{sum(len(g) for g in st["links"].values())} '
                        f'link(s) on {len(st["links"])} object(s)')
            res['state'] = st
        self.run_mgmt(f'Read {self.dev.name} ({self.dev.ia})', task,
                      'DONE — device state read.', cancellable=True)
        st = res.get('state')
        if st is None:
            return
        new_gas = ({g for gas in st['links'].values() for g in gas}
                   - set(self.proj.gas))
        if not ask(self, 'Read device',
                   f'Replace the project settings of "{self.dev.name}" with '
                   f'the device state?\n\n{len(st["params"])} parameter(s), '
                   f'{sum(len(g) for g in st["links"].values())} link(s), '
                   f'{len(new_gas)} new group address(es).'):
            return
        from .knxmgmt import apply_device_state
        skipped = apply_device_state(self.proj, self.dev, st)
        if skipped:
            warn(self, f'Links on object(s) {skipped} could not be mapped '
                 '(not visible under the imported parameters).', 'Read device')
        self.mark_dirty()
        self._undo.clear()        # what came from the device is not undone
        self._redo.clear()
        self.update_enabled()
        self.build_gas()
        self.select_device()

    def _secure_ready(self):
        """Guard: a selected KNX Secure product. Returns (sec, ia) or None.
        Gated on prog.secure (IsSecureEnabled), NOT on prog.tunnels — a secure
        actuator has no tunnels, and a pre-Secure IP interface has tunnels but no
        security object to write."""
        if not self.dev or not self.dev.ia:
            return None
        if not (self.prog and self.prog.secure):
            info(self, 'This product declares no KNX Secure support, so it '
                 'has no security object.', 'Security')
            return None
        return dict(self.dev.sec or {}), ia_int(self.dev.ia)

    def _fdsk(self, sec, required=True):
        """The FDSK from the stored cert; None (after a warning) when it is
        missing or bad."""
        if not sec.get('cert'):
            if required:
                info(self, 'Enter the factory cert (FDSK) first.', 'Security')
            return None
        try:
            return decode_fdsk(sec['cert'])[1]
        except Exception as e:
            warn(self, f'Not a valid factory cert: {e}', 'Security')
            return None

    def secure_read(self):
        """Read the live security state over the bus (read-only)."""
        ready = self._secure_ready()
        if not ready:
            return
        sec, ia = ready
        stored = bytes.fromhex(sec['tool_key']) if sec.get('tool_key') else None
        fdsk = self._fdsk(sec, required=False)

        def task(m, d):
            st = ks.read_state(m, ia, fdsk=fdsk, tool_key=stored,
                               log=d.line.emit)
            # the point of a read: say when project and device disagree
            if stored and not st['mode']:
                d.line.emit('MISMATCH — project holds a tool key, device is '
                            'not secured (Apply with commissioning off to '
                            'drop it)')
            elif not stored and st['mode']:
                d.line.emit('MISMATCH — device is secured, project has no '
                            'tool key (needs that key or a factory reset)')
        self.run_mgmt(f'Security — {self.dev.name}', task, 'DONE.', tries=3,
                      cancellable=True)

    def _tunnel_ias(self, n):
        """The tunnel IAs for this interface: the user's iface['tunnels'] where
        set, else defaults in the interface's own line counting down from .255
        (ETS scheme — interface 1.1.10 → tunnels 1.1.255, 1.1.254, …), skipping
        the interface's own address and any address already used in the project."""
        own = self.dev.ia
        tuns = self.dev.iface.get('tunnels', [])
        try:
            a, l, _ = ia_parts(own)
        except Exception:
            return [tuns[i] if i < len(tuns) else '' for i in range(n)]
        used = {d.ia for d in self.proj.devices if d.ia}
        out, host = [], 255
        for i in range(n):
            if i < len(tuns) and tuns[i]:
                out.append(tuns[i])
                continue
            while host > 0:
                cand = f'{a}.{l}.{host}'
                host -= 1
                if cand != own and cand not in used and cand not in out:
                    out.append(cand)
                    break
            else:
                out.append('')
        return out

    def secure_scan(self):
        """Fill the factory cert from the QR code on the device label."""
        dlg = ScanQrDialog(self)
        if dlg.exec() and dlg.cert:
            self.set_value('sec.cert', dlg.cert)

    def secure_generate(self):
        """Fill the device auth code + one password per tunnel slot with strong
        random secrets. The tool key + backbone key are generated by commission
        itself, so this covers everything a user must choose."""
        import secrets
        ready = self._secure_ready()
        if not ready:
            return
        n = self.prog.tunnels
        if ((self.dev.sec.get('auth_code') or self.dev.sec.get('tunnel_passwords'))
                and not ask(self, 'Generate passwords',
                            'Replace the existing auth code and tunnel '
                            'passwords with new random ones?')):
            return
        gen = lambda: secrets.token_urlsafe(12)      # ~16 readable chars
        self.dev.sec['auth_code'] = gen()
        self.dev.sec['mgmt_password'] = gen()
        self.dev.sec['tunnel_passwords'] = [gen() for _ in range(n)]
        self.mark_dirty()
        self.build_form()                            # re-render with the values
        info(self, f'Generated a device auth code, a management password and '
             f'{n} tunnel password(s), saved with the project.\n\n'
             'Show passwords (toolbar) reveals them.', 'Generate passwords')

    def secure_apply(self):
        """Drive the device to match the two Security-page switches. Rules (like
        ETS): secure tunnelling requires secure commissioning; turning
        commissioning off also turns tunnelling off."""
        ready = self._secure_ready()
        if not ready:
            return
        sec, ia = ready
        # Everything below the tool key + security mode lives on the KNXnet/IP
        # Parameter Object, which only an interface has. On a plain secure device
        # these all stay empty and commission()/write_credentials() reduce to the
        # generic three writes.
        iface = bool(self.prog.tunnels)
        want_comm = bool(sec.get('commissioning'))
        want_tun = bool(sec.get('tunnelling')) and want_comm and iface
        # 'pending' means a tool key was generated and saved but the commission
        # that followed did not confirm. The device may or may not be running on
        # that key, so it is neither commissioned nor untouched — it goes back
        # through branch 1, which knows how to resume.
        pending = bool(sec.get('pending'))
        commissioned = bool(sec.get('tool_key')) and not pending
        # Snapshot the APPLIED state before anything changes: commissioning a
        # device shifts which group addresses resolve to secured, and that only
        # reaches the bus on the next download (see _report_download_impact).
        # The switch has already written its intent into sec['commissioning'],
        # which device_secured() honours — so resolve with the switch reverted,
        # or before and after could never differ.
        self.dev.sec = dict(sec, commissioning=commissioned)
        before = ks.resolve_all(self.proj)
        self.dev.sec = sec
        auth = sec.get('auth_code', '') if iface else ''
        mgmt = sec.get('mgmt_password', '') if iface else ''
        pws = list(sec.get('tunnel_passwords', [])) if iface else []
        fams = [3, 4, 5] if want_tun else []
        res = {}

        # 1) commission a not-yet-secured device
        if want_comm and not commissioned:
            fdsk = self._fdsk(sec)
            if fdsk is None:
                return
            if iface and not self._preflight_ia(ia):
                return
            # a resumed attempt must reuse the SAVED key — minting a new one
            # would strand a device that already took the first
            tool_key = (bytes.fromhex(sec['tool_key']) if pending
                        else ks.gen_key())
            backbone = (bytes.fromhex(sec['backbone_key'])
                        if pending and sec.get('backbone_key') else ks.gen_key())
            all_ias = self._tunnel_ias(self.prog.tunnels)
            ia_strs = all_ias[:len(pws)]                  # one per tunnel password
            cfg = ks.SecureConfig(tool_key=tool_key, backbone_key=backbone,
                                  auth_code=auth, mgmt_password=mgmt,
                                  tunnel_passwords=pws,
                                  tunnel_ias=[ia_int(s) for s in ia_strs if s],
                                  secured_families=fams)
            if not ask(self, 'Apply security',
                       f'Commission "{self.dev.name}" with secure commissioning'
                       f'{" + secure tunnelling" if want_tun else ""} ON?\n\n'
                       f'Writes a new tool key, the passwords and {len(pws)} '
                       f'tunnel address(es) ({", ".join(ia_strs) or "—"}), then '
                       'enables security. Keep the cert to recover the FDSK.'):
                return

            # SAVE THE TOOL KEY BEFORE WRITING IT (run_mgmt write=True does).
            # If the write lands and a later step dies, the device is on the
            # new key and only that key can reach it again — a project without
            # it has lost the device on any product with no factory reset.
            # run_commission's own recovery (re-run under the new key) depends
            # on it too, so persist first and keep it on failure rather than
            # recording it only on success.
            sec.update(tool_key=tool_key.hex(), backbone_key=backbone.hex(),
                       secured_families=fams, commissioning=True,
                       tunnelling=want_tun, pending=True)
            self.dev.sec = sec
            if all_ias:                                  # record the tunnel IAs
                self.dev.iface['tunnels'] = all_ias
            self.mark_dirty()

            def task(m, d):
                d.line.emit(f'tool key {tool_key.hex()} saved to the project '
                            '— keep it, it is the only way back')
                ks.run_commission(m, ia, cfg, fdsk, resume=pending,
                                  log=d.line.emit)
                res['ok'] = True
            self.run_mgmt(f'Apply security — {self.dev.name}', task,
                          'DONE — commissioned.', write=True)
            if res.get('ok'):
                sec.pop('pending', None)         # confirmed on the device now
                self.dev.sec = sec
                self._commit()
                self._report_download_impact(before)
                if want_tun:
                    self._offer_secure_connection({'auth_code': auth,
                                                   'mgmt_password': mgmt,
                                                   'tunnel_passwords': pws})
            else:
                warn(self, 'Commissioning did not finish. The new tool key is '
                     'saved in the project — the device may already be using '
                     'it, so do not clear it.\n\nApply again to resume.',
                     'Apply security')
            return

        # 2) already commissioned: adjust tunnelling + push any credential edits.
        #    Both happen on ONE management session — the 732 won't carry a second
        #    Conn on the same IP-secure tunnel, so the old two-helper path failed
        #    the second op (that was the "change password fails on Apply" bug).
        #    Only toggle the families when tunnelling actually changes; the last
        #    applied state is whether any families are recorded.
        if want_comm and commissioned:
            if not iface:
                # Everything this branch writes lives on the KNXnet/IP object,
                # which a sensor or actuator does not have — it would open a
                # management session and write nothing.
                info(self, f'"{self.dev.name}" is already commissioned — '
                     'nothing to apply.\n\nCommissioning secures management '
                     'only; which group addresses are encrypted is written by '
                     'Program.', 'Security')
                return
            tk = bytes.fromhex(sec['tool_key'])
            cfg = ks.SecureConfig(tool_key=tk, auth_code=auth,
                                  mgmt_password=mgmt, tunnel_passwords=pws)
            tun_now = bool(sec.get('secured_families'))
            toggle = want_tun if want_tun != tun_now else None

            def task(m, d):
                ks.run_update(m, ia, tk, cfg, set_tunnelling=toggle,
                              log=d.line.emit)
                res['ok'] = True
            # run_update has no mid-flow rekey and its writes are idempotent, so
            # a fresh-session retry is safe — this rides out the churn where a
            # freshly-brought-up IP-secure tunnel can't carry management.
            self.run_mgmt(f'Apply security — {self.dev.name}', task,
                          'DONE — updated.', tries=3, write=True)
            if res.get('ok'):
                sec.update(secured_families=fams, tunnelling=want_tun)
                self.dev.sec = sec
                self._commit()
            return

        # 3) turn commissioning off (also turns tunnelling off) + restore FDSK.
        #    A `pending` device counts here too: it may be running on the saved
        #    key, and refusing to decommission it would strand it.
        if not want_comm and (commissioned or pending):
            fdsk = self._fdsk(sec)
            if fdsk is None:
                return
            tk = bytes.fromhex(sec['tool_key'])
            if not ask(self, 'Apply security',
                       f'Turn secure commissioning OFF on "{self.dev.name}" and '
                       'restore the factory tool key?\n\nSecure tunnelling '
                       'turns off too.'):
                return

            def task(m, d):
                # families only on an interface — a plain secure device has no
                # OT 11 to switch off
                ks.run_decommission(m, ia, tk, fdsk=fdsk,
                                    families=[3, 4, 5] if iface else (),
                                    log=d.line.emit)
                res['ok'] = True
            self.run_mgmt(f'Apply security — {self.dev.name}', task,
                          'DONE — security off, FDSK restored.', write=True)
            if res.get('ok'):
                for k in ('tool_key', 'backbone_key', 'secured_families',
                          'pending'):
                    sec.pop(k, None)
                sec.update(commissioning=False, tunnelling=False)
                self.dev.sec = sec
                self._commit()
                self._report_download_impact(before)
            return

        info(self, 'Nothing to change — the device already matches the '
             'switches.', 'Security')

    def _report_download_impact(self, before):
        """After a security change, say which downloads it just made necessary.

        Commissioning secures MANAGEMENT — it does not change a single telegram.
        The group keys and per-object flags travel in the next download, so until
        then the project says one thing and the bus does another. Decommissioning
        is the same in reverse, and it can strand OTHER devices: a group address
        shared with the device that just left resolves back to plain, and
        everyone still holding a key for it needs a download too."""
        impact = ks.download_impact(self.proj, before,
                                    ks.resolve_all(self.proj))
        if not impact:
            return
        self.build_gas()                     # the Security column moved
        mine = impact.pop(self.dev, None)
        lines = []
        if mine:
            lines.append(
                f'{len(mine)} group address(es) change on "{self.dev.name}": '
                + ', '.join(ga_str(g) for g in mine) + ' — it needs a Program.')
        if impact:
            lines.append(
                'These devices share an affected address and need a Program '
                'too:\n\n  '
                + '\n  '.join(f'{d.name} ({d.ia})' for d in impact))
        info(self, '\n\n'.join(lines), 'Downloads needed')

    def _preflight_ia(self, ia):
        """Before commissioning: a factory interface still sits at its default
        IA (15.15.255), so management to the project IA dead-ends in timeouts.
        Discover the connection interface's real IA and offer to assign the
        project one first. Returns False to abort the commission."""
        from .knxiface import assign_ia, interface_ia
        host = (self.proj.connection() or {}).get('host', '')
        if not host:
            return True
        try:
            live = interface_ia(host)
        except LookupError:
            return True                       # no discovery answer — proceed
        if live == ia:
            return True
        r = QMessageBox.question(
            self, 'Interface address',
            f'The interface at {host} has address {ia_str(live)}, the project '
            f'says {ia_str(ia)}.\n\nProgram {ia_str(ia)} to the interface '
            'first? It restarts to apply.',
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
        if r == QMessageBox.Cancel:
            return False
        if r == QMessageBox.Yes:
            res = {}

            def task(m, d):
                assign_ia(m, live, ia, host, log=d.line.emit)
                res['ok'] = True
            self.run_mgmt(f'Program IA {ia_str(ia)} — {self.dev.name}', task,
                          'DONE — address assigned.', write=True)
            return bool(res.get('ok'))
        return True                           # No: they know better — proceed

    def _offer_secure_connection(self, v):
        """After commissioning / a password change, offer to save an ip-secure
        connection with these credentials — the management user (1) if a
        management password is set, else tunnel user 2 (slot 1)."""
        if v.get('mgmt_password'):
            user, pw = 1, v['mgmt_password']
        elif v['tunnel_passwords']:
            user, pw = 2, v['tunnel_passwords'][0]
        else:
            return
        host = (self.proj.connection() or {}).get('host', '')
        name = f'{self.dev.name} (secure)'
        if not ask(self, 'Secure tunnel',
                   f'Save an ip-secure connection "{name}" (user {user}) with '
                   'these credentials?'):
            return
        conn = {'name': name, 'type': 'ip-secure', 'host': host, 'port': 3671,
                'user': user, 'password': pw, 'auth_code': v['auth_code']}
        self.proj.connections = [c for c in self.proj.connections
                                 if c.get('name') != name] + [conn]
        self.proj.active_connection = name
        self.fill_connections()
        self.mark_dirty()

    def scan_addresses(self):
        """Probe an IA range for live devices (T_Connect + descriptor read)."""
        text, ok = QInputDialog.getText(self, 'Scan addresses', 'Range:',
                                        text='1.1.0-1.1.255')
        if not ok or not text.strip():
            return
        try:
            lo, hi = (s.strip() for s in text.split('-'))
            first, last = ia_int(lo), ia_int(hi)
            if first > last:
                raise ValueError
        except ValueError:
            warn(self, f'Not a valid range: {text.strip()} — use '
                 'a.l.d-a.l.d', 'Scan')
            return
        names = {d.ia: d.name for d in self.proj.devices if d.ia}
        self.run_mgmt(f'Scan {lo}-{hi}',
                      lambda m, d: m.scan(first, last, log=d.line.emit,
                                          cancelled=lambda: d.cancelled,
                                          names=names),
                      'DONE — scan complete.', cancellable=True)

    def assign_address(self):
        """ETS-style IA assignment: wait for the device's programming button,
        then write the selected device's address. The connection's own
        interface can be assigned directly instead — its IA is a property
        (OT-11 PID 52), no programming mode needed."""
        if not self.dev:
            return
        ia = ia_int(self.dev.ia)
        if self.prog and self.prog.tunnels and self._assign_direct(ia):
            return
        if self.dev.sec.get('cert') and self._assign_by_serial(ia):
            return
        # the programming-button flow writes to whichever device is in
        # programming mode, so confirm first — P does, and I is one keypress
        # away from it on the device list
        if not ask(self, 'Program IA',
                   f'Write {self.dev.ia} to "{self.dev.name}"?\n\n'
                   'Put the device into programming mode — the address goes '
                   'to whichever device is in that mode.'):
            return
        if self.run_mgmt(f'Program IA {self.dev.ia} — {self.dev.name}',
                         lambda m, d: m.assign(ia, log=d.line.emit,
                                               cancelled=lambda: d.cancelled),
                         f'DONE — device is now {self.dev.ia}.',
                         cancellable=True, write=True):
            self._stamp('ia_assigned')

    def _assign_direct(self, ia):
        """Offer direct PID-52 assignment for the connection's interface.
        Returns True when handled (assigned or nothing to do); False falls
        back to the programming-button flow."""
        from .knxiface import assign_ia, interface_ia
        c = self.proj.connection()
        if not c or not c.get('host'):
            return not self._no_direct(
                'This connection has no IP host, so the interface cannot be '
                'written directly.')
        try:
            with busy():
                cur = interface_ia(c['host'])
        except LookupError:
            cur = None
        if cur is None:
            # silence here reads as "the direct path is gone" — say why
            return not self._no_direct(
                f'The interface at {c["host"]} did not answer discovery, so '
                'it cannot be written directly (a VPN or firewall can block '
                'the reply even when the tunnel works).')
        if cur == ia:
            info(self, f'The interface already has {self.dev.ia}.', 'Program IA')
            return True
        if not ask(self, 'Program IA',
                   f'The interface at {c["host"]} has address {ia_str(cur)}.'
                   f'\n\nWrite {self.dev.ia} directly (no programming button)? '
                   'It restarts to apply. Choose No for a different device.',
                   default_no=True):
            return False
        host = c['host']
        if self.run_mgmt(f'Program IA {self.dev.ia} — {self.dev.name}',
                         lambda m, d: assign_ia(m, cur, ia, host,
                                                log=d.line.emit),
                         f'DONE — interface is now {self.dev.ia}.',
                         write=True):
            self._stamp('ia_assigned')
        return True

    def _assign_by_serial(self, ia):
        """Offer assignment by KNX serial number — the factory cert names
        the device, so no programming button. Returns True when handled;
        False falls back to the programming-button flow."""
        try:
            serial, _ = decode_fdsk(self.dev.sec['cert'])
        except ValueError as e:
            return not self._no_direct(f'Not a valid factory cert: {e}.')
        sn = serial.hex()
        # a secure-commissioned device drops the plain write: go Data Secure
        # under its tool key
        tk = (bytes.fromhex(self.dev.sec['tool_key'])
              if self.dev.sec.get('tool_key') else None)
        if not ask(self, 'Program IA',
                   f'Write {self.dev.ia} to the device with serial {sn} '
                   '(from its factory cert), no programming button?\n\n'
                   'Choose No to use the programming button instead.'):
            return False
        if self.run_mgmt(f'Program IA {self.dev.ia} — {self.dev.name}',
                         lambda m, d: m.assign_by_serial(serial, ia, tk,
                                                         log=d.line.emit),
                         f'DONE — device is now {self.dev.ia}.',
                         write=True):
            self._stamp('ia_assigned')
        return True

    def _no_direct(self, why):
        """Explain why the no-programming-button route is unavailable for this
        interface and ask whether to use the programming button instead.
        Returns True to continue with that flow, False to give up."""
        return ask(self, 'Program IA',
                   f'{why}\n\nUse the programming button instead?')

    # ---- parameter state -------------------------------------------------

    def set_value(self, pref_id, value, focus_id=None):
        v = str(value)
        page, _, key = pref_id.partition('.')
        # synthetic pages store into a device dict; '' means unset / keep
        store = {'iface': self.dev.iface, 'sec': self.dev.sec,
                 'info': self.dev.info}.get(page) if key else None
        if store is not None:
            if key in ('commissioning', 'tunnelling'):   # switches (bool)
                store[key] = bool(value)
            elif key.startswith('tunnel_pw.'):   # per-tunnel password, keyed by slot
                idx = int(key.split('.', 1)[1])
                pws = store.setdefault('tunnel_passwords', [])
                pws += [''] * (idx + 1 - len(pws))
                pws[idx] = v
                while pws and not pws[-1]:        # trim trailing empties
                    pws.pop()
                if not pws:
                    store.pop('tunnel_passwords', None)
            elif v:
                store[key] = v
            else:
                store.pop(key, None)
        elif v == self.defaults.get(pref_id):
            self.dev.values.pop(pref_id, None)   # store deviations only
        else:
            self.dev.values[pref_id] = v
        # rebuild returns focus to this field (radio rows share a pref_id,
        # so they pass the id of the button that was clicked)
        self._focus_pid = focus_id or pref_id
        self.mark_dirty()
        # deferred: refresh() deletes the form widgets, and the sender
        # (combo/spinbox) is still inside its own event when this runs
        QTimer.singleShot(0, self.refresh)

    def resolve(self, text, text_param_ref):
        """Fill {{0:default}} placeholders from the text parameter's value."""
        if not text or '{{' not in text:
            return text
        tp = (self.values.get(text_param_ref) or '').strip() if text_param_ref else ''
        out = TP_RE.sub(lambda m: tp or m.group(1) or '', text)
        # a template arg that expands to nothing leaves a double space behind
        lead = len(out) - len(out.lstrip(' '))      # (leading spaces are an
        return ' ' * lead + re.sub(r' {2,}', ' ', out[lead:]).rstrip()  # indent)

    def _is_page(self, n):
        """A ParameterBlock is a nav page only with a non-empty title and no
        Inline/Layout: an untitled or inline block belongs to the parent page,
        and a Table block's title is its corner header, not a page name."""
        if n.inline or n.layout:
            return False
        return bool(self.resolve(n.text, n.text_param_ref).strip())

    def form_nodes(self, nodes):
        """Form rows for a page: its direct nodes plus the rows of any inline
        (untitled) descendant blocks; titled sub-blocks are their own pages, so
        recursion stops there."""
        for n in iter_visible(nodes, self.values, into_blocks=False):
            if isinstance(n, Block):
                if n.access == 'None':
                    continue                 # internal helper block, hidden
                if n.layout in ('Grid', 'Table'):
                    yield n                  # one row: a grid or a table
                elif not self._is_page(n):
                    yield from self.form_nodes(n.children)
            else:
                yield n

    def _page_has_rows(self, block):
        return any(self._shows(n) for n in self.form_nodes(block.children))

    # ---- parameter views -------------------------------------------------

    def refresh(self):
        # prog.values() also runs the product's ParameterCalculations, which
        # decide the visibility of whole pages (see knxcalc)
        self.values = self.prog.values(self.dev) if self.dev and self.prog else {}
        cur = self.blocks.currentItem()
        cur_id = cur.data(0, Qt.UserRole).id if cur else None
        self.blocks.blockSignals(True)
        self.blocks.clear()
        restore = first = None
        if self.prog:
            for page in device_pages(self.prog):
                it = QTreeWidgetItem([page.text])
                it.setData(0, Qt.UserRole, page)
                self.blocks.addTopLevelItem(it)
            self.add_blocks(self.prog.dynamic, self.blocks.invisibleRootItem())
            stack = [self.blocks.topLevelItem(i)
                     for i in range(self.blocks.topLevelItemCount())]
            while stack:
                it = stack.pop(0)                # document order
                node = it.data(0, Qt.UserRole)
                if node.id == cur_id:
                    restore = it
                if (first is None and not it.data(0, HEADER_ROLE)
                        and node is not INFO_PAGE):
                    first = it       # skip group headers + the Info page
                # the pages under a group header start collapsed (ETS does
                # the same — a 24-output actuator is otherwise a wall of
                # rows); the user's own expand/collapse survives a rebuild
                par = it.parent()
                if par is not None and par.data(0, HEADER_ROLE):
                    it.setExpanded(node.id in self._expanded)
                else:
                    it.setExpanded(node.id not in self._collapsed)
                stack[:0] = [it.child(j) for j in range(it.childCount())]
        self.blocks.blockSignals(False)
        cur = restore or first or self.blocks.topLevelItem(0)
        anc = cur.parent() if cur else None
        while anc:                               # reveal the selected page
            anc.setExpanded(True)
            anc = anc.parent()
        self.blocks.setCurrentItem(cur)
        self.build_form()
        self.build_objects()

    def _shows(self, n):
        """Would add_row render this node as a form row?"""
        if isinstance(n, Block):             # grid: rows are its cells
            return any(self._shows(c) for c in self.form_nodes(n.children))
        if not isinstance(n, PRef):
            return False
        pr = self.prog.prefs[n.ref_id]
        par = self.prog.params[pr.param_id]
        return ((pr.access or par.access) != 'None'
                and self.prog.types[par.type_id].kind != 'hidden')

    def rename_node(self, *_):
        """Name the channel behind the current Settings row (ETS's channel
        name). A product marks the spot with a {{0:...}} placeholder in the
        channel, page and object texts and points it at a text parameter, so
        setting that one parameter renames everything that shows it."""
        it = self.blocks.currentItem()
        node = it.data(0, Qt.UserRole) if it else None
        tp = getattr(node, 'text_param_ref', None)
        if not tp or tp not in self.prog.prefs:
            return
        # the label reads a module-internal parameter that an <Assign> feeds
        # from the field on the page; write to that field, or the assignment
        # would overwrite the name on the next rebuild
        tp = self.prog.source_of(self.values, tp)
        name, ok = QInputDialog.getText(self, 'Name', 'Channel name:',
                                        text=self.values.get(tp) or '')
        if ok:
            self.set_value(tp, name.strip())

    def _note_open(self, item, open_):
        """Remember the user's expand/collapse so a rebuild keeps it."""
        nid = item.data(0, Qt.UserRole).id
        (self._expanded if open_ else self._collapsed).add(nid)
        (self._collapsed if open_ else self._expanded).discard(nid)

    def _set_icon(self, item, name):
        ic = self.icon(name)
        if ic:
            item.setIcon(0, ic)

    def add_blocks(self, nodes, parent, grouped=False):
        for n in nodes:
            if isinstance(n, Channel):
                # a Channel is a nav header ("Inputs A-B", "Logic") — unless a
                # titled block already groups it, as on a 24-output actuator
                # where "Relay outputs" holds one channel per output: there
                # ETS drops the channel row and lists the pages themselves
                if grouped:
                    self.add_blocks(n.children, parent, True)
                    continue
                it = QTreeWidgetItem(
                    [self.resolve(n.text, n.text_param_ref).strip()])
                it.setData(0, Qt.UserRole, n)
                self._set_icon(it, n.icon)
                self.add_blocks(n.children, it, True)
                if it.childCount() == 0:
                    continue
                self._as_header(it)
                parent.addChild(it)
            elif isinstance(n, Block):
                # a titled block is a nav node: a page when it has rows of its
                # own, otherwise a header for the pages under it. Untitled and
                # inline blocks fold into the parent; Access=None blocks are
                # internal helpers ETS hides (ditto their rows, via form_nodes)
                if n.access == 'None':
                    continue
                if not self._is_page(n):
                    self.add_blocks(n.children, parent, grouped)
                    continue
                it = QTreeWidgetItem(
                    [self.resolve(n.text, n.text_param_ref).strip()])
                it.setData(0, Qt.UserRole, n)
                self._set_icon(it, n.icon)
                self.add_blocks(n.children, it, True)
                if not self._page_has_rows(n):
                    if it.childCount() == 0:
                        continue          # no rows, no pages: not a node
                    self._as_header(it)
                parent.addChild(it)
            elif isinstance(n, Choose):
                self.add_blocks(active_children(n, self.values), parent, grouped)

    def _as_header(self, it):
        """A node that groups pages but has none of its own: ETS greys it."""
        it.setData(0, HEADER_ROLE, True)
        f = it.font(0)
        f.setBold(True)
        it.setFont(0, f)
        it.setForeground(0, self.blocks.palette().brush(
            QPalette.Disabled, QPalette.Text))

    def build_form(self, *_):
        # keep scroll position and focus across the rebuild
        scroll = self.form_host.verticalScrollBar().value()
        focus = QApplication.focusWidget()
        focus_pid = focus.property('pref_id') if focus else None
        editing = bool(focus.property('editing')) if focus else False
        if focus is None or focus.property('combo_view'):
            # a closing combo popup leaves focus dangling: return it to
            # the field whose value was just set
            focus_pid = focus_pid or self._focus_pid
        self._focus_pid = None

        it = self.blocks.currentItem()
        self.form_widgets.clear()
        w = QWidget()
        form = QFormLayout(w)
        form.setContentsMargins(12, 8, 12, 8)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldsStayAtSizeHint)
        if it and self.prog:
            node = it.data(0, Qt.UserRole)
            if node is INFO_PAGE:
                self.info_form(form)
            elif node is IFACE_PAGE:
                self.iface_form(form)
            elif node is SECURITY_PAGE:
                self.security_form(form)
            else:
                for n in self.form_nodes(node.children):
                    self.add_row(form, n)
        elif self.dev:                  # imported without its program
            lab = QLabel('Product not in the project.\n\n'
                         'The ETS file did not carry this device\'s '
                         'application program\n'
                         f'({self.dev.variant or "unknown"}), so its settings '
                         'cannot be shown\nand nothing can be sent to it.')
            lab.setStyleSheet(f'color: {theme.RED.name()}')
            lab.setAlignment(Qt.AlignCenter)
            form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
            form.addRow(lab)
        elif not self.proj.path:
            lab = _mute(QLabel('No project open.\n\n'
                               'Use New (Ctrl+N) or Open… (Ctrl+O) to start.\n'
                               'Press Ctrl+/ for keyboard shortcuts.'))
            lab.setAlignment(Qt.AlignCenter)
            form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
            form.addRow(lab)
        w.setEnabled(not self._task)             # read-only during a task
        self.form_host.setWidget(w)

        def restore():
            # look up live widgets: a second rebuild may have replaced the
            # form before this deferred call runs (captured w = deleted)
            self.form_host.verticalScrollBar().setValue(scroll)
            if focus_pid:
                for ww in self.form_widgets:
                    if ww.property('pref_id') == focus_pid:
                        ww.setFocus()
                        if editing:      # keep edit mode across the rebuild
                            self._set_editing(ww, True)
                        break
        QTimer.singleShot(0, restore)

    def add_row(self, form, n):
        p = self.prog
        if isinstance(n, Block):
            form.addRow(self.table(n) if n.layout == 'Table' else self.grid(n))
        elif isinstance(n, Separator):
            form.addRow(self.separator(n))
        elif isinstance(n, PRef):
            if not self._shows(n):
                return
            pr = p.prefs[n.ref_id]
            par = p.params[pr.param_id]
            t = p.types[par.type_id]
            text = pr.text if pr.text is not None else par.text
            if t.kind == 'picture':
                form.addRow(self.picture(t))
            elif t.kind == 'none':
                form.addRow(_plabel(text))
            else:
                form.addRow(_plabel(text), self.widget(n.ref_id, par))

    def separator(self, n):
        """Render a ParameterSeparator per its UIHint (matches ETS)."""
        if n.uihint == 'HorizontalRuler':
            line = QFrame()                       # one hairline, not the
            line.setFixedHeight(1)                # sunken double of HLine
            line.setStyleSheet('background:#404b42;')
            return line
        if not n.text.strip():                    # blank line, ETS-style spacer
            gap = QWidget()
            gap.setFixedHeight(8)
            return gap
        if n.uihint == 'Headline':
            return _headline(n.text, self.icon(n.icon))
        if n.uihint in ('Information', 'Error'):
            return _notebox(n.text.strip(), n.uihint == 'Error')
        lab = QLabel(n.text.strip())
        lab.setWordWrap(True)
        return _mute(lab)                         # plain group label / note

    def icon(self, name):
        """QIcon from the application program's IconFile zip, or None."""
        if not name or not self.prog or not self.prog.icon_file:
            return None
        if name not in self._icons:
            data = self.proj.prod(self.dev.product).icons(
                self.prog.icon_file).get(name)
            pix = QPixmap()
            if data:
                pix.loadFromData(data)
            if not pix.isNull() and _dark(self.palette()):
                pix = _lighten(pix)     # black line art on a dark background
            self._icons[name] = QIcon(pix) if not pix.isNull() else None
        return self._icons[name]

    def grid(self, b):
        """An inline Layout="Grid" ParameterBlock: cells placed by their
        "row,col" into columns weighted by the block's <Column Width="n%">.
        ETS uses these for picture-beside-note rows."""
        w = QWidget()
        g = QGridLayout(w)
        g.setContentsMargins(0, 2, 0, 6)
        total = sum(b.cols) or 1
        for i, pct in enumerate(b.cols):
            g.setColumnStretch(i, max(int(pct * 100 / total), 1))
        avail = max(self.form_host.viewport().width() - 48, 200)
        for n in iter_visible(b.children, self.values, into_blocks=False):
            try:
                r, c = (int(x) - 1 for x in n.cell.split(','))
            except (AttributeError, ValueError):
                continue
            cw = int(avail * b.cols[c] / total) if c < len(b.cols) else avail
            cell = self.cell(n, cw)
            if cell is not None:
                g.addWidget(cell, r, c, Qt.AlignTop | self._halign(n))
        return w

    def table(self, b):
        """An inline Layout="Table" ParameterBlock: ETS draws these as a real
        table — the block title is the corner header, <Row Text> the row
        headers, <Column Text> the column headers, and every cell says where
        it sits with Cell="row,col"."""
        line = self.palette().color(QPalette.Mid).name()
        wrap = QFrame()
        wrap.setStyleSheet(f'QFrame#tbl{{border:1px solid {line};}}')
        wrap.setObjectName('tbl')
        wrap.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        g = QGridLayout(wrap)
        g.setContentsMargins(0, 0, 0, 0)
        g.setSpacing(0)
        nrow, ncol = len(b.rows), len(b.cols)
        head = (100 - sum(b.cols)) or 20     # the row-header column is implicit
        g.setColumnStretch(0, max(int(head), 1))
        for i, pct in enumerate(b.cols):
            g.setColumnStretch(i + 1, max(int(pct), 1))

        def put(w, r, c, hdr=False):
            edge = ('' if c == ncol else f'border-right:1px solid {line};') + \
                   ('' if r == nrow else f'border-bottom:1px solid {line};')
            box = QWidget()
            box.setStyleSheet(f'QWidget{{{edge}}}')
            lay = QHBoxLayout(box)
            lay.setContentsMargins(8, 4, 8, 4)
            if hdr:
                f = w.font()
                f.setBold(True)
                w.setFont(f)
            lay.addWidget(w, 0, Qt.AlignLeft | Qt.AlignVCenter)
            lay.addStretch(1)
            g.addWidget(box, r, c)

        put(QLabel(b.text.strip()), 0, 0, True)
        for i, text in enumerate(b.heads):
            put(QLabel(text), 0, i + 1, True)
        for i, text in enumerate(b.rows):
            put(QLabel(text), i + 1, 0, True)
        for n in iter_visible(b.children, self.values, into_blocks=False):
            try:
                r, c = (int(x) for x in n.cell.split(','))
            except (AttributeError, ValueError):
                continue
            cell = self.cell(n, 0, radio=True)
            if cell is not None:
                put(cell, r, c)
        return wrap

    def _halign(self, n):
        """A picture cell follows its type's HorizontalAlignment; ETS centres
        the pictures in these grids."""
        if isinstance(n, PRef):
            pr = self.prog.prefs.get(n.ref_id)
            t = pr and self.prog.types[self.prog.params[pr.param_id].type_id]
            if t and t.kind == 'picture':
                return {'Middle': Qt.AlignHCenter,
                        'Right': Qt.AlignRight}.get(t.align, Qt.AlignLeft)
        return Qt.Alignment()

    def cell(self, n, width, radio=False):
        """One grid/table cell, sized to fit `width` px. In a table the cell
        carries the field alone — its meaning comes from the row and column
        headers — and a short enum becomes a radio row, as ETS shows it."""
        if isinstance(n, Separator):
            return self.separator(n)
        if isinstance(n, Block):
            return self.grid(n)
        if not isinstance(n, PRef) or not self._shows(n):
            return None
        pr = self.prog.prefs[n.ref_id]
        par = self.prog.params[pr.param_id]
        t = self.prog.types[par.type_id]
        if t.kind == 'picture':
            return self.picture(t, width)
        text = pr.text if pr.text is not None else par.text
        if t.kind == 'none':
            return _plabel(text)
        if radio and t.kind == 'enum' and len(t.enums) <= 3:
            return self.radios(n.ref_id, t)
        w = self.widget(n.ref_id, par)
        if radio:
            return w
        box = QWidget()
        lay = QHBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_plabel(text))
        lay.addWidget(w, 1)
        return box

    def radios(self, pref_id, t):
        """A two- or three-way enum as a row of radio buttons (ETS uses these
        inside tables). Each button is its own navigable field."""
        box = QWidget()
        lay = QHBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        try:
            cur = int(self.values[pref_id])
        except ValueError:
            cur = None
        for v, text in t.enums:
            b = QRadioButton(text)
            b.setChecked(v == cur)
            b.setStyleSheet('border:none;')
            b.clicked.connect(lambda _=0, v=v, fid=f'{pref_id}#{v}':
                              self.set_value(pref_id, v, fid))
            lay.addWidget(self._register(b, f'{pref_id}#{v}'))
        return box

    def picture(self, t, max_w=360):
        lab = QLabel()
        data = self.proj.prod(self.dev.product).baggage(t.ref)
        if data:
            pix = QPixmap()
            pix.loadFromData(data)
            if pix.width() > max_w:      # fit the column; never upscale
                pix = pix.scaledToWidth(max_w, Qt.SmoothTransformation)
            lab.setPixmap(pix)
        lab.setAlignment(Qt.AlignRight if t.align == 'Right'
                         else Qt.AlignHCenter if t.align == 'Middle'
                         else Qt.AlignLeft)
        return lab

    def widget(self, pref_id, par):
        t = self.prog.types[par.type_id]
        val = self.values[pref_id]
        if t.uihint == 'CheckBox':          # 0/1 flag, ETS draws a tick box
            return self._check(pref_id, '', str(val) not in ('0', ''))
        if t.kind == 'enum':
            try:
                cur = int(val)
            except ValueError:
                cur = None
            return self._combo(pref_id, [(text, v) for v, text in t.enums], cur)
        if t.kind in ('int', 'float'):
            w = QSpinBox() if t.kind == 'int' else QDoubleSpinBox()
            w.setRange(t.min, t.max)
            try:
                w.setValue(int(float(val)) if t.kind == 'int' else float(val))
            except ValueError:               # '' or junk: stays at the minimum
                pass
            if par.suffix:
                w.setSuffix(' ' + par.suffix)
            w.editingFinished.connect(lambda w=w: self.set_value(pref_id, w.value()))
        else:
            w = QLineEdit(val)
            w.editingFinished.connect(lambda w=w: self.set_value(pref_id, w.text()))
        return self._register(w, pref_id)

    # ---- device info page ------------------------------------------------

    @staticmethod
    def _fmt_ts(ts):
        return ts.replace('T', ' ') if ts else 'never'

    def info_form(self, form):
        """Per-device notes + management timestamps (dev.info)."""
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        info = self.dev.info
        form.addRow(_mute(_plabel('Product')), _Elided(self.dev.product))
        for key, label in [('programmed', 'Last programmed'),
                           ('ia_assigned', 'IA last assigned')]:
            form.addRow(_mute(_plabel(label)),
                        QLabel(self._fmt_ts(info.get(key))))
        form.addRow(_mute(_plabel('Comment')))
        comment = QPlainTextEdit(info.get('comment', ''))
        comment.setTabChangesFocus(True)   # spans the form width, takes the
        self._register(comment, 'info.comment', form)   # remaining height

    # ---- interface IP settings (KNXnet/IP devices) -----------------------

    def iface_form(self, form):
        """IP-settings page of a KNXnet/IP interface. Only set fields are
        stored; empty / 'keep current' leaves the device value untouched
        when programming."""
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        fi = self.dev.iface
        self._line('iface.name', fi.get('name', ''), form, 'Friendly name',
                   placeholderText='keep current')
        self._combo('iface.assign', [('keep current', ''), ('DHCP', 'dhcp'),
                                     ('Static IP', 'static')],
                    fi.get('assign', ''), form, 'IP assignment')
        if fi.get('assign') == 'static':
            for key, label, hint in [
                    ('ip', 'IP address', '192.168.1.20'),
                    ('mask', 'Subnet mask', '255.255.255.0'),
                    ('gw', 'Default gateway', '192.168.1.1')]:
                self._line('iface.' + key, fi.get(key, ''), form, label,
                           placeholderText=hint)
        self._form_btn('iface.__status', 'Get status…', self.iface_status,
                       'Read the current configuration from the interface '
                       '(Program writes these settings along with the app)',
                       form)

    def iface_status(self):
        """Read this interface device's live IP config over the bus (works for
        another interface reached through the active connection too). A
        discovery probe cross-checks the IA against the connection interface."""
        from .knxiface import check_ia, read_status
        host = (self.proj.connection() or {}).get('host', '')
        ia = ia_int(self.dev.ia)

        def task(m, d):
            check_ia(host, ia, d.line.emit)
            read_status(m, ia, log=d.line.emit)
        self.run_mgmt(f'Interface status — {self.dev.name} ({self.dev.ia})',
                      task, 'DONE.', cancellable=True)

    def security_form(self, form):
        """KNX Secure page of any product declaring IsSecureEnabled.

        Two halves. The GENERIC half applies to every secure device: the factory
        cert (FDSK) and the 'Secure commissioning' switch — KNX Data Secure, i.e.
        the tool key (OT 17 PID 56) + security mode (PID 51), committed to NVM.
        The INTERFACE half (only when prog.tunnels) adds everything that lives on
        the KNXnet/IP Parameter Object (OT 11), which a sensor or actuator simply
        does not have: the device auth code, the IP-Secure user passwords and the
        'Secure tunnelling' switch (secured service families, PID 94).

        Tunnelling requires commissioning; turning commissioning off also turns
        tunnelling off. Fields persist to dev.sec; 'Apply…' drives the device to
        match the switches over the active connection."""
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        sec = self.dev.sec
        iface = bool(self.prog.tunnels)
        commissioned = bool(sec.get('tool_key'))
        cap = _mute(_bold(QLabel(
            'Tool key stored but the last Apply did not confirm — the device '
            'may already be on it. Apply again to resume; keep the key.'
            if sec.get('pending') else
            'Commissioned by this project (tool key stored).' if commissioned
            else 'Not commissioned yet — set the factory cert, tick the '
                 'switches, then Apply.')))
        form.addRow(cap)                 # display row, not keyboard-navigable
        # The split between this page and "Program" is not obvious, so say it.
        # Apply changes what the device IS (secured, under which key); Program
        # changes what it DOES, and group-address encryption travels with the
        # download because the keys ride in it.
        form.addRow(_note(
            'Apply writes the tool key and the security mode'
            + (', the device auth code and the user passwords.' if iface
               else '. It secures management only and changes no telegram.')
            + ' Which group addresses are encrypted is written by "Program".'))

        self._line('sec.cert', sec.get('cert', ''), form, 'Factory cert (FDSK)',
                   placeholderText='ADCQCB-ZBDN2Z-…  (from the device label)'
                   ).setToolTip('Factory certificate (FDSK) — saved with this '
                                'device')
        scan = self._form_btn('sec.__Scan', 'Scan QR code…', self.secure_scan,
                              'Scan the factory-cert QR code on the device '
                              'label with a camera')
        scan.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        form.addRow('', scan)         # under the cert field, natural width

        # --- OT 11 half: only a KNXnet/IP interface has these objects -------
        if iface:
            self._line('sec.auth_code', sec.get('auth_code', ''), form,
                       'Device auth code', pw=True, strip=False)
            # IP-secure user 1 — ETS's "commissioning password". Management
            # access; the per-tunnel users below are ids 2, 3, … mapped to slots.
            self._line('sec.mgmt_password', sec.get('mgmt_password', ''), form,
                       'Management password (user 1)', pw=True, strip=False
                       ).setToolTip('IP Secure user 1 — management access, '
                                    'ETS calls this the commissioning password')
            # one password per tunnel slot (each tunnel is its own IP-secure
            # user), labelled by the tunnel's IA — the user's if set, else default
            pws = sec.get('tunnel_passwords', [])
            ias = self._tunnel_ias(self.prog.tunnels)
            for i in range(self.prog.tunnels):
                # tunnel slot i+1 = IP Secure user i+2 (user 1 is management) —
                # the user id is what a client app asks for, so put it in the label
                self._line(f'sec.tunnel_pw.{i}', pws[i] if i < len(pws) else '',
                           form, f'Tunnel {ias[i] or i + 1} password (user {i + 2})',
                           pw=True, strip=False)

        # consistent initial state BEFORE wiring signals (tunnelling ⟹ commissioning)
        comm_on = bool(sec.get('commissioning'))
        comm = self._check('sec.commissioning',
                           'Secure commissioning (KNX Data Secure)', comm_on, form)

        # Secure tunnelling is the secured KNXnet/IP service families (OT 11
        # PID 94) — an interface-only switch, so it is not even built otherwise.
        if iface:
            tun = self._check('sec.tunnelling', 'Secure tunnelling (IP Secure)',
                              bool(sec.get('tunnelling')) and comm_on, form)
            tun.setEnabled(comm_on)

            def on_comm(on):                 # tunnelling requires commissioning
                tun.setEnabled(on)
                if not on and tun.isChecked():
                    tun.setChecked(False)
                    self.set_value('sec.tunnelling', 0)   # persist it off
            comm.clicked.connect(on_comm)

        buttons = [('Apply…', self.secure_apply,
                    'Drive the device to match the switches above'),
                   ('Read state', self.secure_read,
                    'Read the live security mode over the bus')]
        if iface:                            # nothing to generate without OT 11
            buttons.insert(0, ('Generate', self.secure_generate,
                               'Fill the device auth code + every tunnel '
                               'password with strong random secrets'))
        wrap = QWidget()
        row = QHBoxLayout(wrap)
        row.setContentsMargins(0, 6, 0, 0)
        for label, fn, tip in buttons:
            row.addWidget(self._form_btn('sec.__' + label.strip('… '), label,
                                         fn, tip))
        row.addStretch(1)
        form.addRow(wrap)

    # ---- group objects ---------------------------------------------------

    def build_objects(self):
        cur = self.objects.currentItem()
        cur_id = cur.data(0, Qt.UserRole) if cur else None
        self.objects.clear()
        if not self.prog:
            return
        seen = set()
        for n in iter_visible(self.prog.dynamic, self.values):
            if not isinstance(n, CRef) or n.ref_id in seen:
                continue
            seen.add(n.ref_id)
            cr = self.prog.corefs[n.ref_id]
            co = self.prog.comobjs[cr.obj_id]
            text = self.resolve(cr.text if cr.text is not None else co.text,
                                cr.text_param_ref)
            gas = ', '.join(ga_str(g) for g in self.dev.links.get(n.ref_id, []))
            it = QTreeWidgetItem(['', gas, text,
                                  cr.function_text or co.function_text,
                                  cr.size or co.size,
                                  self.proj.dpt_name(cr.dpt or co.dpt or ''),
                                  co.flags])
            it.setData(0, Qt.DisplayRole, co.number)   # numeric sort
            it.setData(0, Qt.UserRole, n.ref_id)
            self.objects.addTopLevelItem(it)
        # links on refs the current settings hide: keep visible so the
        # user can find and remove them (grayed, "not active")
        for cid in self.dev.links:
            if cid in seen or cid not in self.prog.corefs:
                continue
            cr = self.prog.corefs[cid]
            co = self.prog.comobjs[cr.obj_id]
            gas = ', '.join(ga_str(g) for g in self.dev.links[cid])
            it = QTreeWidgetItem(['', gas, self.resolve(cr.text or co.text, None),
                                  '(not active)', cr.size or co.size,
                                  self.proj.dpt_name(cr.dpt or co.dpt or ''),
                                  co.flags])
            it.setData(0, Qt.DisplayRole, co.number)
            it.setData(0, Qt.UserRole, cid)
            dim = self.objects.palette().brush(QPalette.Disabled, QPalette.Text)
            for c in range(7):
                it.setForeground(c, dim)     # theme-aware "inactive" gray
            self.objects.addTopLevelItem(it)
        self.objects.sortItems(0, Qt.AscendingOrder)
        items = list(_items(self.objects))
        self.objects.setCurrentItem(next(
            (it for it in items if it.data(0, Qt.UserRole) == cur_id),
            items[0] if items else None))
        for i in range(7):
            self.objects.resizeColumnToContents(i)

    def objects_menu(self, pos):
        it = self.objects.itemAt(pos)
        if not it:                        # keyboard menu key: use the current
            it = self.objects.currentItem()   # row and pop the menu on it
            if not it:
                return
            pos = self.objects.visualItemRect(it).center()
        m = QMenu(self)
        m.addAction('&Link group addresses…', lambda: self.edit_links(it, 0))
        m.addAction('&Unlink all', lambda: self.unlink_all(it))
        m.exec(self.objects.viewport().mapToGlobal(pos))

    def link_current(self):
        it = self.objects.currentItem()
        if it:
            self.edit_links(it, 0)

    def unlink_all(self, it):
        cid = it.data(0, Qt.UserRole)
        for g in list(self.dev.links.get(cid, [])):
            self.proj.unlink(self.dev, cid, g)
        self.mark_dirty()
        self.build_objects()
        self.build_gas()

    def edit_links(self, it, _col):
        coref_id = it.data(0, Qt.UserRole)
        cr = self.prog.corefs[coref_id]
        dpt = cr.dpt or self.prog.comobjs[cr.obj_id].dpt or ''
        dlg = LinkDialog(self, self.proj, self.dev.links.get(coref_id, []), dpt)
        if not dlg.exec():
            return
        for g in list(self.dev.links.get(coref_id, [])):
            self.proj.unlink(self.dev, coref_id, g)
        for g in dlg.linked:
            self.proj.link(self.dev, coref_id, g)
            if not self.proj.gas[g]['dpt']:      # inherit type from the object
                self.proj.gas[g]['dpt'] = dpt
        self.mark_dirty()
        self.build_objects()
        self.build_gas()

    # ---- group address tab -----------------------------------------------

    def build_gas(self):
        used = {'all': None, 'used': True, 'unused': False}[self.ga_used.currentText()]
        self.ga_list.blockSignals(True)
        self.ga_list.clear()
        users_map = self.proj.ga_users_map()
        secured = ks.resolve_all(self.proj)
        for ga in self.proj.filter_gas(self.ga_pattern.text().strip(), used,
                                       self.ga_tag.text().strip()):
            g = self.proj.gas[ga]
            users = ', '.join(d.name for d in users_map.get(ga, []))
            it = QTreeWidgetItem([ga_str(ga), g['name'],
                                  self.proj.dpt_name(g['dpt']), users,
                                  _ga_sec_text(g, secured.get(ga))])
            it.setFlags(it.flags() | Qt.ItemIsEditable)
            it.setData(0, Qt.UserRole, ga)
            self.ga_list.addTopLevelItem(it)
        self.ga_list.blockSignals(False)
        for i in range(5):
            self.ga_list.resizeColumnToContents(i)
        self._fill_send_gas()

    def ga_edited(self, it, col):
        old = it.data(0, Qt.UserRole)
        if col == 0:
            try:
                new = ga_int(it.text(0))
                if new != old:
                    self.proj.rename_ga(old, new)
            except ValueError as e:
                warn(self, str(e), 'Group address')
                self._revert(self.ga_list, it, 0, ga_str(old))
                return
            self.mark_dirty()
            # deferred: build_gas clears the tree, destroying the edited
            # item while Qt's edit-commit path still holds it
            QTimer.singleShot(0, lambda: (self.build_gas(),
                                          self.build_objects()))
        elif col == 1:
            self.proj.gas[old]['name'] = it.text(1)
            self.mark_dirty()

    def _selected_gas(self):
        """Selected GA rows in visual order, else the current one."""
        sel = [it for it in _items(self.ga_list) if it.isSelected()]
        return sel or [it for it in [self.ga_list.currentItem()] if it]

    def ga_security(self):
        """Set the security of the selected group addresses. Three states, as
        ETS has: Auto (secured when every device on the address can be), or a
        forced Secured / Plain. Auto is planning state — what actually reaches a
        device is one flag per group object, resolved at download."""
        sel = self._selected_gas()
        if not sel:
            return
        gas = [it.data(0, Qt.UserRole) for it in sel]
        modes = [('Auto', 'auto'), ('Secured (forced)', 'on'),
                 ('Plain (forced)', 'off')]
        cur = self.proj.gas[gas[0]].get('security', 'auto')
        what = (ga_str(gas[0]) if len(gas) == 1
                else f'{len(gas)} group addresses')
        choice, ok = QInputDialog.getItem(
            self, 'Group address security', f'Security for {what}:',
            [m[0] for m in modes], [m[1] for m in modes].index(cur), False)
        if not ok:
            return
        mode = dict(modes)[choice]

        if mode == 'on':
            # forcing a GA secured breaks any device on it that cannot do
            # secure group communication — auto is exactly the rule that avoids
            # this, so say so rather than let the download fail later
            bad = {d.name for ga in gas for d in ks.force_on_conflicts(self.proj, ga)}
            if bad:
                warn(self, 'These devices cannot do secure group communication '
                     'and would stop working on a forced-secure address:\n\n  '
                     + '\n  '.join(sorted(bad))
                     + '\n\nCommission them first, or leave the address on '
                       'Auto.', 'Group address security')
                return
        for ga in gas:
            self.proj.gas[ga]['security'] = mode
        minted = ks.ensure_group_keys(self.proj)
        self.mark_dirty()
        self.build_gas()
        if minted:
            self.statusBar().showMessage(
                f'{len(minted)} group key(s) generated — affected devices '
                'need a Program', 5000)

    def bulk_add_ga(self):
        dlg = BulkGaDialog(self, self.proj)
        if dlg.exec():
            self.mark_dirty()
            self.build_gas()
            self.statusBar().showMessage(dlg.summary, 5000)

    def ga_dclick(self, it, col):
        if col in (0, 1):
            self.ga_list.editItem(it, col)

    def change_ga(self):
        """Single selection: inline edit. Multi: address template popup."""
        sel = self._selected_gas()
        if not sel:
            return
        if len(sel) == 1:
            self.ga_list.editItem(sel[0], 0)
            return
        olds = [it.data(0, Qt.UserRole) for it in sel]
        text, ok = QInputDialog.getText(
            self, 'Change addresses',
            f'Template for {len(olds)} addresses. {{}} = math expression,\n'
            f'n = row number, x = old part, e.g. 2/{{n+2}}/{{x+3}}:',
            text=ga_str(olds[0]))
        if not ok or not text.strip():
            return
        try:
            news = [ga_int(s) for s in expand_addr_template(
                text, [ga_str(g) for g in olds], '/')]
            self.proj.rename_gas(dict(zip(olds, news)))
        except ValueError as e:
            warn(self, str(e), 'Group addresses')
            return
        self.mark_dirty()
        self.build_gas()
        self.build_objects()

    def add_ga(self):
        if AddGaDialog(self, self.proj).exec():
            self.mark_dirty()
            self.build_gas()

    def delete_ga(self):
        gas = [it.data(0, Qt.UserRole) for it in self._selected_gas()]
        if not gas:
            return
        users = {d.name for ga in gas for d in self.proj.ga_users(ga)}
        for ga in gas:
            self.proj.delete_ga(ga)
        self.mark_dirty()
        self.build_gas()
        self.build_objects()
        what = (ga_str(gas[0]) if len(gas) == 1
                else f'{len(gas)} group addresses')
        used = (' (links on ' + ', '.join(sorted(users)) + ' removed)'
                if users else '')
        self.statusBar().showMessage(   # no confirm: Ctrl+Z is the way back
            f'Deleted {what}{used} — {native("Ctrl+Z")} undoes', 5000)


def main():
    app = QApplication(sys.argv)
    theme.apply(app)
    keyboard_cursor(app)
    ed = Editor()
    ed.show()
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_dir():
        ed.open_project(sys.argv[1])
    sys.exit(app.exec())

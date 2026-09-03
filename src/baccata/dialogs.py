"""Popup dialogs: add device, tag editor, GA assignment, bulk GA add."""
import contextlib, fnmatch, sys
from PySide6.QtCore import QEvent, QStandardPaths, Qt, QTimer
from PySide6.QtGui import QCursor, QImage, QKeySequence, QPalette, QShortcut
from PySide6.QtMultimedia import QCamera, QMediaCaptureSession, QMediaDevices
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (
    QApplication, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMessageBox, QPushButton, QSpinBox, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout)

from . import knxip
from .keymap import bridge, button, escape_to, vim_arrows
from .knxdatasec import cert_from_text, decode_fdsk
from .knxsec import make_bus
from .project import ga_str, ga_int
from .theme import RED as MISMATCH


def ask(parent, title, text, default_no=False):
    """Yes/No question; True on Yes."""
    return QMessageBox.question(
        parent, title, text, QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No if default_no else QMessageBox.Yes) == QMessageBox.Yes


def warn(parent, text, title='Baccata'):
    """Popups are sentence case: lower-layer errors get their first letter
    raised so 'bad address: x' from a ValueError reads as prose."""
    QMessageBox.warning(parent, title, text[:1].upper() + text[1:])


def info(parent, text, title='Baccata'):
    QMessageBox.information(parent, title, text[:1].upper() + text[1:])


@contextlib.contextmanager
def busy():
    """Wait cursor for a blocking bus call; restored before any dialog."""
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    try:
        yield
    finally:
        QApplication.restoreOverrideCursor()

_PW_SHOWN = False                   # global show-passwords state


def password_edit(edit):
    """Mark a QLineEdit as a password field. It follows the global
    show-passwords toggle (set_passwords_shown), also at creation time."""
    edit.setProperty('pw_edit', True)
    edit.setEchoMode(QLineEdit.Normal if _PW_SHOWN else QLineEdit.Password)


def set_passwords_shown(on):
    """Flip every password field in the app (and all future ones)."""
    global _PW_SHOWN
    _PW_SHOWN = bool(on)
    for w in QApplication.allWidgets():
        if isinstance(w, QLineEdit) and w.property('pw_edit'):
            w.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)


def _buttons(dlg, lay):
    bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    bb.accepted.connect(dlg.accept)
    bb.rejected.connect(dlg.reject)
    bb.button(QDialogButtonBox.Ok).setDefault(True)   # Enter's target
    lay.addWidget(bb)
    # QDialog hands "default" to the first autoDefault button shown, which
    # would make Enter anywhere in the dialog click a row button (e.g. Add)
    # instead of OK. Only the box's buttons may own Enter.
    for b in dlg.findChildren(QPushButton):
        if b.parent() is not bb:
            b.setAutoDefault(False)


class AddDeviceDialog(QDialog):
    """Searchable list of all variants in the project catalog; import knxprods."""

    def __init__(self, parent, proj):
        super().__init__(parent)
        self.setWindowTitle('Add device')
        self.resize(560, 450)
        self.proj = proj
        self.result = None       # (product_file, apid, name)

        lay = QVBoxLayout(self)
        self.search = QLineEdit(placeholderText='search…')
        self.search.textChanged.connect(self.build)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(['Variant', 'Product file'])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemActivated.connect(lambda *_: self.accept())
        imp = button('Import knxprod…', self.import_prod, 'Alt+I')
        lay.addWidget(self.search)
        lay.addWidget(self.tree)
        lay.addWidget(imp, 0, Qt.AlignLeft)
        _buttons(self, lay)
        bridge(self.search, self.tree)
        vim_arrows(self)
        self.search.setFocus()
        self.build()

    def build(self):
        q = self.search.text().lower()
        self.tree.clear()
        for fn in self.proj.catalog_files():
            for name, apid in self.proj.prod(fn).items:
                if q and q not in name.lower():
                    continue
                it = QTreeWidgetItem([name, fn])
                it.setData(0, Qt.UserRole, (fn, apid, name))
                it.setForeground(1, self.tree.palette().brush(
                    QPalette.Disabled, QPalette.Text))   # filename recedes
                self.tree.addTopLevelItem(it)
        self.tree.resizeColumnToContents(0)
        self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def import_prod(self):
        downloads = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
        path, _ = QFileDialog.getOpenFileName(self, 'Import product', downloads,
                                              'KNX product (*.knxprod)')
        if path:
            self.proj.import_product(path)
            self.build()

    def accept(self):
        it = self.tree.currentItem()
        if not it:
            return
        fn, apid, name = it.data(0, Qt.UserRole)
        from .knxmgmt import unsupported_reason
        try:
            reason = unsupported_reason(self.proj.prod(fn).load_program(apid))
        except Exception:
            reason = None                # let unparseable products through
        if reason:
            warn(self, f'"{name}" can\'t be added — {reason}.\n\nBaccata only '
                 'takes devices it can fully program and read back without ETS.',
                 'Incompatible device')
            return
        self.result = (fn, apid, name)
        super().accept()


class TagDialog(QDialog):
    """Project tag pool with checkboxes for the selected devices' assignment.
    With several devices a tag on only some of them starts partially checked;
    checking puts it on all, unchecking removes it from all, partial leaves
    each device as it is. The edit filters the list; Enter/Add creates the
    typed tag and assigns it. All changes are staged; Cancel discards
    everything."""

    def __init__(self, parent, proj, devs):
        super().__init__(parent)
        self.setWindowTitle(f'Tags — {devs[0].name}' if len(devs) == 1
                            else f'Tags — {len(devs)} devices')
        self.resize(300, 400)
        self.proj, self.devs = proj, devs
        self.pool = list(proj.tags)
        self.deleted = set()
        # per-tag state; survives filtering, unlike item check state
        self.state = {}
        for t in self.pool:
            n = sum(t in d.tags for d in devs)
            self.state[t] = (Qt.Checked if n == len(devs) else
                             Qt.PartiallyChecked if n else Qt.Unchecked)
        # only tags that start mixed get the third state to cycle back to
        self.tri = {t for t, s in self.state.items()
                    if s == Qt.PartiallyChecked}

        lay = QVBoxLayout(self)
        self.list = QListWidget()
        self.list.itemChanged.connect(self.toggled)
        self.list.itemActivated.connect(lambda *_: self.toggle_current())
        self.list.installEventFilter(self)   # Return: macOS Qt won't activate
        lay.addWidget(self.list)
        row = QHBoxLayout()
        self.new_tag = QLineEdit(placeholderText='filter / new tag…')
        self.new_tag.textChanged.connect(self.build)
        self.new_tag.returnPressed.connect(self.create)
        row.addWidget(self.new_tag)
        row.addWidget(button('Add', self.create, 'Alt+A'))
        row.addWidget(button('Delete tag', self.delete, 'Alt+D'))
        lay.addLayout(row)
        _buttons(self, lay)
        QShortcut(QKeySequence('Ctrl+Return'), self, self.accept)
        bridge(self.new_tag, self.list, consume_return=True, edit_below=True)
        vim_arrows(self)
        self.build()
        if self.pool:
            self.list.setCurrentRow(0)
            self.list.setFocus()
        else:
            self.new_tag.setFocus()

    def build(self):
        cur = (self.list.currentItem().data(Qt.UserRole)
               if self.list.currentItem() else None)
        q = self.new_tag.text().strip().lower()
        used = {}
        for d in self.proj.devices:
            for t in d.tags:
                used[t] = used.get(t, 0) + 1
        self.list.blockSignals(True)   # re-render must not echo into sel
        self.list.clear()
        for t in self.pool:
            if q and q not in t.lower():
                continue
            n = used.get(t, 0)
            it = QListWidgetItem(f'{t}  ({n})' if n else t)
            it.setData(Qt.UserRole, t)
            f = it.flags() | Qt.ItemIsUserCheckable
            if t in self.tri:
                f |= Qt.ItemIsUserTristate
            it.setFlags(f)
            it.setCheckState(self.state[t])
            self.list.addItem(it)
        self.list.blockSignals(False)
        self.select(cur)

    def select(self, tag):
        """Keep the highlighted tag across a rebuild -- clear() drops the
        current row, so without this the selection snapped back to the top on
        every keystroke in the filter."""
        for i in range(self.list.count()):
            if self.list.item(i).data(Qt.UserRole) == tag:
                self.list.setCurrentRow(i)
                return
        if self.list.count() and not self.list.currentItem():
            self.list.setCurrentRow(0)

    def toggled(self, it):
        self.state[it.data(Qt.UserRole)] = it.checkState()

    def eventFilter(self, w, ev):
        if (w is self.list and ev.type() == QEvent.KeyPress
                and ev.key() in (Qt.Key_Return, Qt.Key_Enter)
                and not ev.modifiers() & ~Qt.KeypadModifier):
            self.toggle_current()
            return True
        return super().eventFilter(w, ev)

    def toggle_current(self):
        """Enter cycles the row's check, like Space. Only tags that started
        mixed keep the partial state in the cycle."""
        it = self.list.currentItem()
        if not it:
            return
        order = ([Qt.Unchecked, Qt.PartiallyChecked, Qt.Checked]
                 if it.data(Qt.UserRole) in self.tri else
                 [Qt.Unchecked, Qt.Checked])
        it.setCheckState(order[(order.index(it.checkState()) + 1) % len(order)])

    def create(self):
        t = self.new_tag.text().strip()
        if not t:
            self.list.setFocus()      # Return in the empty edit = back to list
            return
        if t not in self.pool:
            self.pool.append(t)
            self.pool.sort()
            self.deleted.discard(t)
            self.state[t] = Qt.Checked   # created here -> assigned here
        self.new_tag.clear()         # resets the filter; rebuilds via textChanged
        self.select(t)               # land on it: the list is alphabetical
        self.list.setFocus()

    def delete(self):
        it = self.list.currentItem()
        if not it:
            return
        t = it.data(Qt.UserRole)
        n = sum(t in d.tags for d in self.proj.devices)
        if n and not ask(self, 'Delete tag',
                         f'"{t}" is used by {n} device(s). Remove everywhere on OK?'):
            return
        self.pool.remove(t)
        self.deleted.add(t)
        self.state.pop(t, None)
        self.build()

    def accept(self):
        for t in self.deleted:
            self.proj.delete_tag(t)
        self.proj.tags = list(self.pool)
        on = {t for t, s in self.state.items() if s == Qt.Checked}
        for d in self.devs:
            keep = on | {t for t in d.tags
                         if self.state.get(t) == Qt.PartiallyChecked}
            d.tags = [t for t in self.pool if t in keep]
        super().accept()


class LinkDialog(QDialog):
    """Assign group addresses to one group object; create new GAs inline.
    Created GAs are staged and only added to the project on OK."""

    def __init__(self, parent, proj, linked, obj_dpt=''):
        super().__init__(parent)
        self.setWindowTitle('Group addresses')
        self.resize(420, 480)
        self.proj = proj
        self.linked = set(linked)
        self.obj_dpt = obj_dpt
        self.created = {}                # staged new GAs: ga -> {name, dpt}

        lay = QVBoxLayout(self)
        if obj_dpt:
            lay.addWidget(QLabel(f'Object type: {proj.dpt_name(obj_dpt)}'))
        self.filter = QLineEdit(placeholderText='filter (1/2/* or name)…')
        self.filter.textChanged.connect(self.build)
        self.list = QListWidget()
        row = QHBoxLayout()
        self.new_ga = QLineEdit(placeholderText='new GA, e.g. 1/2/3 name…')
        self.new_ga.returnPressed.connect(self.create)
        add = button('Create', self.create, 'Alt+R')
        row.addWidget(self.new_ga)
        row.addWidget(add)
        lay.addWidget(self.filter)
        lay.addWidget(self.list)
        lay.addLayout(row)
        _buttons(self, lay)
        bridge(self.filter, self.list)
        bridge(self.new_ga, self.list, consume_return=True,
               edit_below=True, slash=False)   # filter owns "/"
        vim_arrows(self)
        self.filter.setFocus()
        self.build()

    def build(self):
        self.linked = self.checked() if self.list.count() else self.linked
        q = self.filter.text().strip().lower()
        self.list.clear()
        gas = {**self.proj.gas, **self.created}
        for ga in sorted(gas):
            g = gas[ga]
            mismatch = bool(self.obj_dpt and g['dpt'] and g['dpt'] != self.obj_dpt)
            label = f"{ga_str(ga)}  {g['name']}"
            if g['dpt']:
                label += f"  [{self.proj.dpt_name(g['dpt'])}]"
            if mismatch:
                label += '  ⚠ type mismatch'
            if q and not (fnmatch.fnmatch(ga_str(ga), q) or q in label.lower()):
                continue
            it = QListWidgetItem(label)
            it.setData(Qt.UserRole, ga)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if ga in self.linked else Qt.Unchecked)
            if mismatch:
                it.setForeground(MISMATCH)   # warn, don't fade
            self.list.addItem(it)

    def checked(self):
        got = {self.list.item(i).data(Qt.UserRole)
               for i in range(self.list.count())
               if self.list.item(i).checkState() == Qt.Checked}
        # keep linked GAs hidden by the filter
        shown = {self.list.item(i).data(Qt.UserRole)
                 for i in range(self.list.count())}
        return got | (self.linked - shown)

    def create(self):
        parts = self.new_ga.text().strip().split(None, 1)
        if not parts:
            return
        try:
            ga = ga_int(parts[0])
        except (ValueError, TypeError):
            warn(self, f'Not a valid address: {parts[0]}', 'Group address')
            return
        if ga not in self.proj.gas:
            self.created[ga] = {'name': parts[1] if len(parts) > 1 else '',
                                'dpt': self.obj_dpt}
        self.linked.add(ga)
        self.new_ga.clear()
        self.build()

    def accept(self):
        self.linked = self.checked()
        gas = {**self.proj.gas, **self.created}
        bad = [g for g in self.linked
               if self.obj_dpt and gas[g]['dpt'] and gas[g]['dpt'] != self.obj_dpt]
        if bad and not ask(self, 'Type mismatch',
                           'Some selected addresses have a different datapoint '
                           'type than this object. Link anyway?'):
            return
        for ga, g in self.created.items():
            self.proj.gas.setdefault(ga, g)
        super().accept()


class ConnectionDialog(QDialog):
    """Manage the project's bus connections. Staged; Cancel discards."""

    def __init__(self, parent, proj):
        super().__init__(parent)
        self.setWindowTitle('Bus connections')
        self.resize(560, 340)
        self.proj = proj
        self.conns = [dict(c) for c in proj.connections]
        self.current = None
        self._loading = False

        lay = QHBoxLayout(self)
        left = QVBoxLayout()
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self.pick)
        row = QHBoxLayout()
        btns = []
        for label, fn, key in [('Add', self.add, 'Alt+A'),
                               ('Remove', self.remove, 'Alt+R'),
                               ('Discover…', self.discover, 'Alt+D'),
                               ('Test', self.test, 'Alt+T')]:
            btns.append(button(label, fn, key))
            row.addWidget(btns[-1])
        left.addWidget(self.list)
        left.addLayout(row)
        lay.addLayout(left, 1)

        right = QVBoxLayout()
        form = QFormLayout()
        self.f_name = QLineEdit()
        self.f_type = QComboBox()
        self.f_type.addItems(['ip', 'ip-secure'])
        self.f_host = QLineEdit()
        self.f_port = QSpinBox()
        self.f_port.setRange(1, 65535)
        self.f_port.setValue(3671)
        self.f_user = QSpinBox()
        self.f_user.setRange(1, 127)
        self.f_user.setValue(2)
        self.f_pw = QLineEdit()
        password_edit(self.f_pw)
        self.f_auth = QLineEdit()
        password_edit(self.f_auth)
        form.addRow('Name', self.f_name)
        form.addRow('Type', self.f_type)
        form.addRow('Host', self.f_host)
        form.addRow('Port', self.f_port)
        form.addRow('User id', self.f_user)
        self.f_user.setToolTip('User 1 is the management user: not bound '
                               'to a tunnel, so the gateway assigns any '
                               'free tunnel address. Users 2+ each get '
                               'their fixed one.')
        form.addRow('User password', self.f_pw)
        form.addRow('Device auth code', self.f_auth)
        self.f_type.currentTextChanged.connect(self.type_changed)
        for w in (self.f_name, self.f_host, self.f_pw, self.f_auth):
            w.editingFinished.connect(self.store)
        self.f_port.valueChanged.connect(self.store)
        self.f_user.valueChanged.connect(self.store)
        right.addLayout(form)
        right.addStretch(1)
        lay.addLayout(right, 2)
        _buttons(self, right)          # shared: strips autoDefault, so Enter
        fields = (self.f_name, self.f_type, self.f_host, self.f_port,
                  self.f_user, self.f_pw, self.f_auth)
        chain = (self.list, *fields, *btns)   # list, form, row buttons, OK
        for a, b in zip(chain, chain[1:]):
            self.setTabOrder(a, b)
        escape_to(self.list, *fields)
        self.list.installEventFilter(self)     # Right: into the form
        vim_arrows(self)
        self.build()
        self.type_changed(self.f_type.currentText())
        self.list.setFocus()

    def eventFilter(self, w, ev):
        if (w is self.list and ev.type() == QEvent.KeyPress
                and ev.key() == Qt.Key_Right and self.conns):
            self.f_name.setFocus()
            return True
        return super().eventFilter(w, ev)

    def build(self):
        self.list.clear()
        for c in self.conns:
            self.list.addItem(self._label(c))
        if self.conns:
            self.list.setCurrentRow(0)

    @staticmethod
    def _label(c):
        return f"{c['name']}  ({c['type']} {c.get('host', '')})"

    def type_changed(self, t):
        secure = t == 'ip-secure'
        for w in (self.f_user, self.f_pw, self.f_auth):
            w.setEnabled(secure)
        self.store()

    def pick(self, row):
        self.current = self.conns[row] if 0 <= row < len(self.conns) else None
        c = self.current
        if not c:
            return
        self._loading = True
        self.f_name.setText(c['name'])
        self.f_type.setCurrentText(c.get('type', 'ip'))
        self.f_host.setText(c.get('host', ''))
        self.f_port.setValue(c.get('port', 3671))
        self.f_user.setValue(c.get('user', 2))
        self.f_pw.setText(c.get('password', ''))
        self.f_auth.setText(c.get('auth_code', ''))
        self._loading = False

    def store(self, *_):
        c = self.current
        if self._loading or not c:
            return
        c.update(name=self.f_name.text().strip() or c['name'],
                 type=self.f_type.currentText(), host=self.f_host.text().strip(),
                 port=self.f_port.value(), user=self.f_user.value(),
                 password=self.f_pw.text(), auth_code=self.f_auth.text())
        row = self.list.currentRow()
        if row >= 0:
            self.list.item(row).setText(self._label(c))

    def add(self, c=None):
        self.conns.append(c or {'name': f'Connection {len(self.conns) + 1}',
                                'type': 'ip', 'host': '', 'port': 3671})
        self.build()
        self.list.setCurrentRow(len(self.conns) - 1)

    def remove(self):
        row = self.list.currentRow()
        if row >= 0:
            del self.conns[row]
            self.current = None
            self.build()

    def discover(self):
        hosts = {c.get('host', '') for c in self.conns}
        hosts.add(self.f_host.text().strip())
        with busy():
            found = knxip.discover(hosts=hosts - {''})
        if not found:
            info(self, 'No KNXnet/IP gateways found.\n\nMulticast does not '
                 'cross subnets — enter the host and Discover again.',
                 'Discover')
            return
        items = [f"{g['name']} — {g['ip']}:{g['port']}"
                 + (' 🔒 secure' if g.get('secure') else '') for g in found]
        pick, ok = QInputDialog.getItem(self, 'Discover', 'Found gateways:',
                                        items, 0, False)
        if not ok:
            return
        g = found[items.index(pick)]
        self.add({'name': g['name'] or g['ip'],
                  'type': 'ip-secure' if g.get('secure') else 'ip',
                  'host': g['ip'], 'port': g['port']})

    def test(self):
        """Open a tunnel with the edited settings, report the result."""
        self.store()
        c = self.current
        if not c or not c.get('host'):
            info(self, 'Select a connection with a host first.', 'Test connection')
            return
        try:
            with busy():
                bus = make_bus(c)
                bus.connect()
                ia = bus.ia
                bus.disconnect()
        except Exception as e:
            warn(self, f'Connection failed: {e}', 'Test connection')
            return
        info(self, f'Connected to {c["host"]}, own address '
             f'{knxip.ia_str(ia)}.', 'Test connection')

    def accept(self):
        self.store()
        self.proj.connections = self.conns
        super().accept()


class AddGaDialog(QDialog):
    """Add a single group address with an optional name."""

    def __init__(self, parent, proj):
        super().__init__(parent)
        self.setWindowTitle('Add group address')
        self.setMinimumWidth(320)
        self.proj = proj
        self.ga = None
        lay = QVBoxLayout(self)
        self.addr = QLineEdit(placeholderText='main/middle/sub')
        self.name = QLineEdit(placeholderText='name (optional)')
        form = QFormLayout()
        form.addRow('Address', self.addr)
        form.addRow('Name', self.name)
        lay.addLayout(form)
        _buttons(self, lay)
        self.addr.setFocus()

    def accept(self):
        try:
            ga = ga_int(self.addr.text())
        except (ValueError, TypeError) as e:
            warn(self, str(e) or 'Not a valid address', 'Group address')
            return
        entry = self.proj.gas.setdefault(ga, {'name': '', 'dpt': ''})
        entry['name'] = self.name.text().strip() or entry['name']
        self.ga = ga
        super().accept()


class BulkGaDialog(QDialog):
    """Create a run of sequential group addresses."""

    def __init__(self, parent, proj):
        super().__init__(parent)
        self.setWindowTitle('Bulk add group addresses')
        self.setMinimumWidth(340)
        self.proj = proj
        lay = QVBoxLayout(self)
        self.start = QLineEdit(placeholderText='e.g. 1/0/1')
        self.count = QSpinBox()
        self.count.setRange(1, 255)
        self.count.setValue(10)
        self.template = QLineEdit(placeholderText='e.g. Light {n} or Dim {n*2}')
        form = QFormLayout()
        form.addRow('Start address', self.start)
        form.addRow('Count', self.count)
        form.addRow('Name template ({} = math, n = number)', self.template)
        lay.addLayout(form)
        _buttons(self, lay)
        self.start.setFocus()

    def accept(self):
        try:
            start = ga_int(self.start.text())
        except (ValueError, TypeError):
            warn(self, 'Not a valid start address', 'Group addresses')
            return
        n = self.count.value()
        try:
            created, skipped = self.proj.bulk_add_gas(start, n,
                                                      self.template.text())
        except ValueError as e:
            warn(self, str(e), 'Group addresses')
            return
        self.summary = f'Created {created} group address(es)'
        if skipped:
            self.summary += f', skipped {skipped} existing'
        if (start >> 8) != ((start + n - 1) >> 8):
            self.summary += ' — range crosses a middle-group boundary'
        super().accept()


# macOS camera permission. Qt won't raise the TCC prompt from a plain python
# process (qt.permissions demands NSCameraUsageDescription in an Info.plist we
# don't have), so ask AVFoundation directly like any unbundled CLI tool — the
# prompt is then attributed to the user's terminal. QtMultimedia already links
# AVFoundation, so the CDLLs below are free.
if sys.platform == 'darwin':
    import ctypes
    from ctypes import (CFUNCTYPE, POINTER, Structure, byref, c_bool,
                        c_char_p, c_int, c_long, c_ulong, c_void_p)
    _objc = ctypes.CDLL('/usr/lib/libobjc.A.dylib')
    _avf = ctypes.CDLL(
        '/System/Library/Frameworks/AVFoundation.framework/AVFoundation')
    _objc.objc_getClass.restype = c_void_p
    _objc.objc_getClass.argtypes = [c_char_p]
    _objc.sel_registerName.restype = c_void_p
    _objc.sel_registerName.argtypes = [c_char_p]
    _avc = _objc.objc_getClass(b'AVCaptureDevice')
    _video = c_void_p.in_dll(_avf, 'AVMediaTypeVideo')

    _BlockFn = CFUNCTYPE(None, c_void_p, c_bool)

    class _BlockDesc(Structure):
        _fields_ = [('reserved', c_ulong), ('size', c_ulong)]

    class _Block(Structure):    # ObjC block literal for the completion handler
        _fields_ = [('isa', c_void_p), ('flags', c_int), ('reserved', c_int),
                    ('invoke', _BlockFn), ('descriptor', POINTER(_BlockDesc))]

    _block_fn = _BlockFn(lambda _blk, _granted: None)  # result seen via poll()
    _block_desc = _BlockDesc(0, ctypes.sizeof(_Block))
    _block = _Block(
        c_void_p.in_dll(ctypes.CDLL(None), '_NSConcreteGlobalBlock').value,
        0x10000000, 0, _block_fn, ctypes.pointer(_block_desc))

    def camera_auth():
        """TCC camera status: 0 undetermined, 3 authorized, else denied."""
        f = ctypes.cast(_objc.objc_msgSend,
                        CFUNCTYPE(c_long, c_void_p, c_void_p, c_void_p))
        return f(_avc,
                 _objc.sel_registerName(b'authorizationStatusForMediaType:'),
                 _video)

    def camera_request():
        """Pop the macOS camera permission prompt (async)."""
        f = ctypes.cast(
            _objc.objc_msgSend,
            CFUNCTYPE(None, c_void_p, c_void_p, c_void_p, c_void_p))
        f(_avc, _objc.sel_registerName(
            b'requestAccessForMediaType:completionHandler:'),
          _video, ctypes.cast(byref(_block), c_void_p))
else:
    camera_auth = lambda: 3
    camera_request = lambda: None


_CAM_DENIED = ('Camera access denied — allow your terminal in System '
               'Settings → Privacy & Security → Camera, or use "From image…".')


class ScanQrDialog(QDialog):
    """Scan a device's factory cert (FDSK) QR from a webcam or an image file.
    On success self.cert holds the normalized dashed base32 string."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle('Scan factory certificate')
        self.resize(480, 420)
        self.cert = None
        self.camera = None
        self._rejected = set()
        lay = QVBoxLayout(self)
        cams = QMediaDevices.videoInputs()
        if len(cams) > 1:                       # e.g. built-in + iPhone
            pick = QComboBox()
            for c in cams:
                pick.addItem(c.description())
            pick.currentIndexChanged.connect(lambda i: self._start(cams[i]))
            lay.addWidget(pick)
        self.view = QVideoWidget()
        self.status = QLabel('Point the camera at the QR code on the '
                             'device label.')
        self.status.setWordWrap(True)
        lay.addWidget(self.view, 1)
        lay.addWidget(self.status)
        row = QHBoxLayout()
        img = button('From image…', self.from_image, 'Alt+I')
        cancel = QPushButton('Cancel')
        cancel.clicked.connect(self.reject)
        for b in (img, cancel):
            b.setAutoDefault(False)   # else Enter clicks "From image…"
        row.addWidget(img)
        row.addStretch(1)
        row.addWidget(cancel)
        lay.addLayout(row)
        self.session = QMediaCaptureSession(self)
        self.session.setVideoOutput(self.view)
        self.timer = QTimer(self, interval=200)  # ~5 Hz decode; GUI stays live
        self.timer.timeout.connect(self.poll)
        self._cams = cams
        if not cams:
            self.status.setText('No camera found — use "From image…".')
        elif camera_auth() == 3:
            self._start(cams[0])
        elif camera_auth() == 0:
            camera_request()                     # poll() starts once granted
            self.status.setText('Waiting for camera permission…')
            self.timer.start()
        else:
            self.status.setText(_CAM_DENIED)

    def _start(self, dev):
        if self.camera:
            self.camera.stop()
        self.status.setText('Point the camera at the QR code on the '
                            'device label.')
        self.camera = QCamera(dev, self)
        self.camera.errorOccurred.connect(       # e.g. permission denied
            lambda _e, s: self.status.setText(s or 'camera error'))
        self.session.setCamera(self.camera)
        self.camera.start()                      # async on macOS
        self.timer.start()

    def poll(self):
        if not self.camera:                      # waiting for the TCC prompt
            st = camera_auth()
            if st == 3:
                self._start(self._cams[0])
            elif st != 0:
                self.timer.stop()
                self.status.setText(_CAM_DENIED)
            return
        frame = self.view.videoSink().videoFrame()
        if frame.isValid():                      # startup frames are invalid
            self._decode(frame.toImage())

    def from_image(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, 'QR code image', '', 'Images (*.png *.jpg *.jpeg *.bmp)')
        if not fn:
            return
        img = QImage(fn)
        if img.isNull():
            self.status.setText('could not read image')
        elif not self._decode(img):
            self.status.setText('no QR code with an FDSK cert in that image')

    def _decode(self, img):
        import zxingcpp                          # hard dep, lazy for startup
        # zxing's own format fallback calls convertToFormat(int), which
        # PySide6 rejects — hand it Grayscale8, which it maps natively
        img = img.convertToFormat(QImage.Format.Format_Grayscale8)
        res = zxingcpp.read_barcode(img, formats=zxingcpp.BarcodeFormat.QRCode)
        if not (res and res.valid):
            return False
        try:
            cert = cert_from_text(res.text)
        except ValueError as e:
            self.status.setText(f'{e}: {res.text[:60]}')
            return False
        if cert not in self._rejected:
            self.timer.stop()                    # freeze while asking
            serial, _ = decode_fdsk(cert)
            sn = '-'.join(f'{b:02X}' for b in serial)
            if ask(self, 'Scan factory certificate',
                   f'Found certificate\n{cert}\nof device serial {sn} — use it?'):
                self.cert = cert
                self.accept()
                return True
            self._rejected.add(cert)             # don't re-ask for this code
            self.status.setText('Rejected — point at another label.')
            if self.camera:
                self.timer.start()
        return True

    def done(self, r):                           # every close path
        self.timer.stop()
        if self.camera:
            self.camera.stop()
        super().done(r)

"""ETS project (.knxproj) import.

A .knxproj is a zip: knx_master.xml, one M-xxxx/ folder per manufacturer
holding the very files a .knxprod carries (Catalog.xml, Hardware.xml, the
application programs), and the project itself under P-xxxx/ — or, password
protected, inside P-xxxx.zip (ETS6: AES, key = PBKDF2 of the password; ETS5:
ZipCrypto with the password itself). Format pinned against xknxproject
(zip/extractor.py, loader/project_loader.py) and a real ETS 6.3 export.

Each M-xxxx/ folder + knx_master.xml is re-packed into a knxprod in the
project's catalog/, so everything downstream (Project.program, the editor,
verify) runs the same code path as a hand-imported product. The vendor files
go nowhere but into the user's own project folder.

The device's ids in 0.xml are ETS-relative: ComObjectInstanceRef RefIds lack
the application prefix ('O-6_R-134'), Links name group addresses by the tail
of their id ('GA-18'), and a module instance carries an '_MI-n' segment the
knxprod's own ids do not ('MD-3_M-12_MI-1_O-2-19_R-1' is our
'..._MD-3_M-12_O-2-19_R-1'). All of that is undone here.
"""
import base64, hashlib, io, re, zipfile
from datetime import datetime
import xml.etree.ElementTree as ET

import pyzipper

_MI = re.compile(r'_MI-(\d+)_')
_APID = re.compile(r'(M-[0-9A-F]{4}_A-[^_]+)_')   # the program a ref id belongs to


class PasswordRequired(Exception):
    """The project is password protected and no password was given."""


class WrongPassword(ValueError):
    pass


def _ets6_zip_key(password):
    """ETS6 protects P-xxxx.zip with AES; the zip password is the base64 of
    PBKDF2-HMAC-SHA256(password as UTF-16LE, '21.project.ets.knx.org')."""
    return base64.b64encode(hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-16-le'), b'21.project.ets.knx.org',
        65536, 32))


def _ns(root):
    return root.tag.split('}')[0] + '}' if root.tag.startswith('{') else ''


def _tag(e):
    return e.tag.split('}')[-1]


def _local(ts):
    """An ETS UTC stamp ('…T05:46:35.3502995Z') the way Editor._stamp writes
    them: local time, whole seconds."""
    try:
        return (datetime.fromisoformat(ts).astimezone().replace(tzinfo=None)
                .isoformat(timespec='seconds'))
    except ValueError:
        return ts


def _seg(name):
    """A space/trade name as one path segment ('/' is the separator)."""
    return name.replace('/', '\\/')


class KnxProj:
    """One .knxproj archive: the project XML (decrypted when needed) and the
    manufacturer folders."""

    def __init__(self, path, password=None):
        self.path = path
        self.zf = zipfile.ZipFile(path)
        names = self.zf.namelist()
        self.pid = next((n.split('.')[0].split('/')[0] for n in names
                         if re.match(r'P-[0-9A-F]{4}(\.zip|/)', n)), None)
        if not self.pid:
            raise ValueError(f'{path}: no P-xxxx project inside — not a knxproj?')
        self.mdirs = sorted({n.split('/')[0] for n in names
                             if re.match(r'M-[0-9A-F]{4}/', n)})
        files = self._project_files(password)
        self.root = ET.fromstring(files['0.xml'])
        pinfo = files.get('project.xml') or files.get('Project.xml')
        self.proj_root = ET.fromstring(pinfo) if pinfo else None
        self.ns = _ns(self.root)
        self.tool_version = self.root.get('ToolVersion', '')

    def _project_files(self, password):
        """{'0.xml': bytes, 'project.xml': bytes}."""
        inner = f'{self.pid}.zip'
        if inner not in self.zf.namelist():             # plain ETS4/5 layout
            return {n.split('/')[-1]: self.zf.read(n)
                    for n in self.zf.namelist()
                    if n.startswith(self.pid + '/') and n.endswith('.xml')}
        data = io.BytesIO(self.zf.read(inner))
        if password is None:
            raise PasswordRequired(self.path)
        probe = zipfile.ZipFile(data)
        aes = any(i.compress_type == 99 for i in probe.infolist())
        data.seek(0)
        z = pyzipper.AESZipFile(data) if aes else zipfile.ZipFile(data)
        z.setpassword(_ets6_zip_key(password) if aes
                      else password.encode('utf-8'))
        try:
            return {n: z.read(n) for n in z.namelist() if n.endswith('.xml')}
        except (RuntimeError, zipfile.BadZipFile) as e:   # pyzipper: RuntimeError
            raise WrongPassword(str(e))

    @property
    def name(self):
        if self.proj_root is not None:
            pi = self.proj_root.find(f'.//{_ns(self.proj_root)}ProjectInformation')
            if pi is not None and pi.get('Name'):
                return pi.get('Name')
        return self.pid

    def knxprod_bytes(self, mdir):
        """That manufacturer's folder + knx_master.xml, zipped: a knxprod."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            for n in self.zf.namelist():
                if ((n.startswith(mdir + '/') and not n.endswith('/'))
                        or n == 'knx_master.xml'):
                    # the source entry's own timestamp: the same input packs
                    # to the same bytes, so the catalog dedups a re-import
                    zi = zipfile.ZipInfo(n, self.zf.getinfo(n).date_time)
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(zi, self.zf.read(n))
        return buf.getvalue()

    def hardware(self):
        """From every Hardware.xml: {Hardware2Program id: [apid]} and
        {product id: (product text, order number)}."""
        h2p, products = {}, {}
        for mdir in self.mdirs:
            try:
                hw = ET.fromstring(self.zf.read(f'{mdir}/Hardware.xml'))
            except KeyError:
                continue
            ns = _ns(hw)
            for hp in hw.iter(f'{ns}Hardware2Program'):
                h2p[hp.get('Id')] = [r.get('RefId') for r in
                                     hp.iter(f'{ns}ApplicationProgramRef')]
            for p in hw.iter(f'{ns}Product'):
                products[p.get('Id')] = (p.get('Text', ''),
                                         p.get('OrderNumber', ''))
        return h2p, products

    def program_type(self, apid):
        """ProgramType of an application program file, or None when the
        archive lacks it. Reads the head only: the files run to tens of MB."""
        try:
            with self.zf.open(f'{apid.split("_")[0]}/{apid}.xml') as f:
                head = f.read(4096).decode('utf-8', 'replace')
        except KeyError:
            return None
        m = re.search(r'ProgramType="([^"]*)"', head)
        return m.group(1) if m else 'ApplicationProgram'


def import_knxproj(project, kp, log=None):
    """Fill `project` (saved: catalog/ must exist) from `kp`. Returns the
    import report, a list of lines: the counts, then everything that did not
    map. Devices whose application program is not in the archive are kept
    with product '' — the editor paints them red, nothing on the bus works
    for them until the product is added."""
    from . import knxsecure as ks           # fingerprint of the imported state
    report = []
    note = report.append
    ns = kp.ns
    root = kp.root
    project.name = kp.name

    # products: one knxprod per manufacturer folder, into catalog/
    prodfile = {}                           # mdir -> catalog filename
    for mdir in kp.mdirs:
        prodfile[mdir] = project.import_product_bytes(
            f'{kp.name}-{mdir}.knxprod', kp.knxprod_bytes(mdir))
    h2p, products = kp.hardware()

    # group addresses: id tail ('GA-18') -> 16-bit address
    ga_by_tail = {}
    for g in root.iter(f'{ns}GroupAddress'):
        ga = int(g.get('Address'))
        ga_by_tail[g.get('Id').split('_')[-1]] = ga
        entry = {'name': g.get('Name', ''),
                 'dpt': g.get('DatapointType', ''),
                 'security': g.get('Security', 'auto').lower(),
                 'key': ''}
        if g.get('Key'):
            entry['key'] = base64.b64decode(g.get('Key')).hex()
        project.gas[ga] = entry

    # locations / trades -> tags on the devices, the trees on the project
    loc_tags = {}                           # DeviceInstance id -> [tag]
    def walk(node, path, prefix, store):
        for c in node:
            t = _tag(c)
            if t in ('Space', 'BuildingPart', 'Trade'):
                p = path + [_seg(c.get('Name', ''))]
                key = '/'.join(p)
                store[key] = {k: v for k, v in (
                    ('type', c.get('Type', '')), ('number', c.get('Number', '')),
                    ('usage', c.get('Usage', '')),
                    ('description', c.get('Description', ''))) if v}
                walk(c, p, prefix, store)
            elif t == 'DeviceInstanceRef' and path:
                loc_tags.setdefault(c.get('RefId'), []).append(
                    f'{prefix}{"/".join(path)}')
    locs = root.find(f'.//{ns}Locations')
    if locs is not None:
        walk(locs, [], '@loc:', project.spaces)
    trades = root.find(f'.//{ns}Trades')
    if trades is not None:
        walk(trades, [], '@trade:', project.trades)
    if root.find(f'.//{ns}Function') is not None:
        note('Functions are not imported (Baccata has no place for them yet)')

    # devices
    ndev = 0
    for area in root.iter(f'{ns}Area'):
        for line in area.findall(f'{ns}Line'):
            for di in line.iter(f'{ns}DeviceInstance'):
                if di.get('Address') is None:
                    note(f'{di.get("Name") or di.get("Id")}: no individual '
                         f'address — skipped')
                    continue
                ia = f'{area.get("Address")}.{line.get("Address")}.{di.get("Address")}'
                dev = _device(project, kp, di, ia, ndev + 1, h2p, products,
                              prodfile, ga_by_tail, loc_tags, note)
                ndev += 1
                project.devices.append(dev)
                if dev.product and di.get('ApplicationProgramLoaded') == 'true':
                    dev.info['programmed_fp'] = ks.device_fingerprint(project, dev)

    # the interface's own connection, so verify has a bus to run on
    for di in root.iter(f'{ns}DeviceInstance'):
        ip = di.find(f'{ns}IPConfig')
        if ip is None or not ip.get('IPAddress'):
            continue
        dev = next((d for d in project.devices
                    if d.info.get('ets_id') == di.get('Id')), None)
        if dev is None:
            continue
        sec = dev.sec
        secure = di.find(f'{ns}Security') is not None and bool(
            di.find(f'{ns}Security').get('LoadedDeviceAuthenticationCodeHash'))
        pws = sec.get('tunnel_passwords', [])
        project.connections.append({
            'name': dev.name, 'type': 'ip-secure' if secure else 'ip',
            'host': ip.get('IPAddress'), 'port': 3671, 'user': 2,
            'password': pws[0] if pws else '',
            'auth_code': sec.get('auth_code', '')})
        project.active_connection = project.active_connection or dev.name
    project.tags = sorted({*project.tags, *(t for d in project.devices for t in d.tags)})

    inst = root.find(f'.//{ns}Installation')
    if inst is not None and inst.get('BCUKey') not in (None, '4294967295'):
        note('the installation has a BCU key (legacy access protection) — '
             'not imported')
    missing = [d.ia for d in project.devices if not d.product]
    report.insert(0, f'{ndev} devices, {len(project.gas)} group addresses, '
                     f'{len(project.spaces)} spaces, '
                     f'{len(project.connections)} connections')
    if missing:
        report.insert(1, f'{len(missing)} device(s) without their product '
                         f'in the file (shown red): {", ".join(missing)}')
    if log:
        for l in report:
            log(l)
    return report


def _device(project, kp, di, ia, did, h2p, products, prodfile, ga_by_tail,
            loc_tags, note):
    from .project import Device
    ns = kp.ns
    prefs = [(p.get('RefId'), p.get('Value', ''))
             for p in di.iter(f'{ns}ParameterInstanceRef')]
    # application program: the one the parameter ids name, else the
    # Hardware2Program's ApplicationProgram (its PeiProgram is not it)
    apid = next((m.group(1) for r, _ in prefs
                 if (m := _APID.match(r))), None)
    cands = h2p.get(di.get('Hardware2ProgramRefId', ''), [])
    if not apid:
        apid = next((a for a in cands
                     if kp.program_type(a) == 'ApplicationProgram'),
                    cands[0] if cands else '')
    ptext, order_no = products.get(di.get('ProductRefId', ''), ('', ''))
    name = di.get('Name') or ptext or f'Device {did}'
    mdir = apid.split('_')[0] if apid else ''
    product = prodfile.get(mdir, '') if kp.program_type(apid) else ''
    dev = Device({'id': did, 'name': name, 'product': product,
                  'variant': apid, 'ia': ia})
    dev.tags = loc_tags.get(di.get('Id'), [])
    dev.info['ets_id'] = di.get('Id')
    if ptext:
        dev.info['product'] = ptext
    if order_no:
        dev.info['order_no'] = order_no
    # provenance for a verify report: the ETS build, whether ETS says the
    # program is on the device, and whether the project changed since
    dev.info['ets'] = {
        'tool': kp.tool_version,
        'loaded': di.get('ApplicationProgramLoaded') == 'true',
        'drift': (di.get('LastModified', '') > di.get('LastDownload', ''))}
    if di.get('Comment') or di.get('Description'):
        dev.info['comment'] = di.get('Comment') or di.get('Description')
    if di.get('LastDownload'):
        stamp = _local(di.get('LastDownload'))
        dev.info['programmed'] = stamp
        if di.get('IndividualAddressLoaded') == 'true':
            dev.info['ia_assigned'] = stamp
            dev.info['ia_written'] = ia
    prog = project.program_or_none(dev) if product else None
    if not product:
        note(f'{ia} {name}: application program {apid or "?"} is not in '
             f'the file')

    def full(ref):
        """An ETS-relative id as the knxprod's."""
        if not ref.startswith('M-'):
            ref = f'{apid}_{ref}'
        return _MI.sub(lambda m: '_' if m.group(1) == '1' else m.group(0), ref)

    dropped_p, dropped_o = [], []
    for ref, val in prefs:
        pid = full(ref)
        if prog is not None:
            if pid not in prog.prefs:
                dropped_p.append(ref)
                continue
            if val == prog.default(pid):
                continue
        dev.values[pid] = val
    for co in di.iter(f'{ns}ComObjectInstanceRef'):
        cid = full(co.get('RefId'))
        gas = [ga_by_tail[t.split('_')[-1]] for t in co.get('Links', '').split()
               if t.split('_')[-1] in ga_by_tail]
        for con in co.iter(f'{ns}Connectors'):        # pre-ETS5.7 links
            for c in con:
                t = c.get('GroupAddressRefId', '').split('_')[-1]
                if t in ga_by_tail:
                    gas.append(ga_by_tail[t])
        if not gas:
            continue
        if prog is not None and cid not in prog.corefs:
            dropped_o.append(co.get('RefId'))
            continue
        dev.links[cid] = sorted(set(gas))
    if dropped_p or dropped_o:
        note(f'{ia} {name}: not in its application program — '
             f'{len(dropped_p)} parameter(s), {len(dropped_o)} object link(s) '
             f'dropped: {", ".join((dropped_p + dropped_o)[:4])}')

    # KNXnet/IP interface: tunnel addresses, users' passwords
    tunnels = [f'{ia.rsplit(".", 1)[0]}.{a.get("Address")}'
               for aa in di.findall(f'{ns}AdditionalAddresses')
               for a in aa.findall(f'{ns}Address')]
    if tunnels:
        dev.iface['tunnels'] = tunnels
    pws = [b.get('Password', '') for bi in di.findall(f'{ns}BusInterfaces')
           for b in bi.findall(f'{ns}BusInterface')]
    sec = di.find(f'{ns}Security')
    if sec is not None and sec.get('LoadedToolKey'):
        # what ETS loaded onto the device: only then does Baccata talk
        # Data Secure to it. The Security page's switches mirror the loaded
        # state — 'commissioning' = the tool key is on the device, and, for
        # an interface, 'tunnelling' = the device authentication code was
        # loaded, which ETS only does with the secured KNXnet/IP service
        # families (OT 11 PID 94) switched on. Without the switches set, the
        # page reads "deactivated" and Apply would decommission the device.
        dev.sec['tool_key'] = base64.b64decode(sec.get('LoadedToolKey')).hex()
        dev.sec['commissioning'] = True
        if sec.get('DeviceAuthenticationCode'):
            dev.sec['auth_code'] = sec.get('DeviceAuthenticationCode')
        if sec.get('DeviceManagementPassword'):
            dev.sec['mgmt_password'] = sec.get('DeviceManagementPassword')
        if any(pws):
            dev.sec['tunnel_passwords'] = pws
        if tunnels and sec.get('LoadedDeviceAuthenticationCodeHash'):
            dev.sec['tunnelling'] = True
            dev.sec['secured_families'] = [3, 4, 5]
    elif any(pws):
        dev.sec['tunnel_passwords'] = pws
    return dev

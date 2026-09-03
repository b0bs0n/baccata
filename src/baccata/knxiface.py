"""KNXnet/IP interface configuration.

Reads/writes the interface's own KNXnet/IP Parameter Object (interface object
type 11) via CONNECTIONLESS A_PropertyValue addressed to the interface's own
individual address. This is how ETS configures IP settings; it works plaintext
while the interface's KNX Security mode is off (a factory / non-secure device);
a secured interface needs a Data Secure session under its tool key.
"""
import socket, struct, time

from .knxip import discover, ia_int, ia_str, OT_KNXIP, PID_ADDITIONAL_IAS
from .knxmgmt import Conn

# KNXnet/IP Parameter Object (OT 11) property ids (KNX master, standard).
# Kept as a complete reference table for the object — a few are not read or
# written yet (CUR_ASSIGN, MCAST, TTL).
PID_IA = 52
PID_CUR_ASSIGN = 54          # current IP assignment method (bitset)
PID_CFG_ASSIGN = 55          # configured IP assignment method: 1=manual 4=DHCP
PID_CUR_IP, PID_CUR_MASK, PID_CUR_GW = 57, 58, 59       # read-only
PID_IP, PID_MASK, PID_GW = 60, 61, 62                   # configured (static)
PID_MAC = 64
PID_MCAST = 66
PID_TTL = 67
PID_NAME = 76                # friendly name, 30 chars, ISO-8859-1, zero-padded

ASSIGN_MANUAL, ASSIGN_DHCP = 1, 4


class Iface(Conn):
    """Connectionless property access to an interface's own individual address
    (`ia`, from discovery) over a Mgmt — the KNXnet/IP parameter object lives
    there. Plaintext by default; pass a DataSecure session as `sec` for a
    secured interface (Conn.sync() first)."""

    def __init__(self, mgmt, ia, sec=None):
        super().__init__(mgmt, ia, timeout=1.5, sec=sec, co=False)

    read, write = Conn.prop_read, Conn.prop_write

    def read_array(self, oi, pid, count):
        """Read a `count`-element 1-byte array, chunked (NoE field is 4 bits)."""
        out, start = b'', 1
        while count:
            n = min(count, 15)
            out += self.read(oi, pid, n, start)
            start, count = start + n, count - n
        return out

    def write_array(self, oi, pid, data):
        """Write a 1-byte-per-element array in chunks of 15."""
        for i in range(0, len(data), 15):
            chunk = data[i:i + 15]
            self.write(oi, pid, chunk, len(chunk), i + 1)

    def find_object(self, obj_type, limit=16):
        """Interface-object index whose PID_OBJECT_TYPE == obj_type. Raises
        LookupError when the device answered but has no such object. A device
        that does not answer at all raises TimeoutError from the first read —
        that is a better diagnostic than reporting the object as missing.
        (Object-type reads answer only while security mode is off.)"""
        for oi in range(limit):
            v = self.read(oi, 1)
            if len(v) >= 2 and struct.unpack('!H', v[:2])[0] == obj_type:
                return oi
        raise LookupError(f'object type {obj_type} not found '
                          '(is the interface in secure mode?)')

    # ---- KNXnet/IP config ------------------------------------------------

    def read_config(self):
        """Read the interface's IP configuration into a dict of display values.
        Raises LookupError if the KNXnet/IP object can't be found (e.g. security
        mode is on and object-type reads are blocked)."""
        oi = self.find_object(OT_KNXIP)

        def ip(pid):
            v = self.read(oi, pid)
            return socket.inet_ntoa(v) if len(v) == 4 else ''

        assign = self.read(oi, PID_CFG_ASSIGN)
        name = self.read_array(oi, PID_NAME, 30).split(b'\0', 1)[0]
        mac = self.read(oi, PID_MAC)
        return {
            'oi': oi,
            'name': name.decode('latin-1', 'replace'),
            'dhcp': bool(assign and assign[0] & ASSIGN_DHCP),  # bitset: 4=DHCP
            'cur_ip': ip(PID_CUR_IP), 'cur_mask': ip(PID_CUR_MASK),
            'cur_gw': ip(PID_CUR_GW),
            'ip': ip(PID_IP), 'mask': ip(PID_MASK), 'gw': ip(PID_GW),
            'mac': '-'.join(f'{b:02X}' for b in mac) if mac else '',
        }

    def apply_config(self, oi, cfg, log=print):
        """Write changed IP settings. `cfg` keys: name, dhcp (True switches to
        DHCP), and for a static setup ip/mask/gw (dotted strings). Only writes
        what's given: no 'dhcp' and no 'ip' means the assignment is untouched."""
        if 'name' in cfg:
            data = cfg['name'].encode('latin-1', 'replace')[:30].ljust(30, b'\0')
            self.write_array(oi, PID_NAME, data)
            log(f'friendly name -> {cfg["name"]!r}')
        if cfg.get('dhcp'):
            self.write(oi, PID_CFG_ASSIGN, bytes([ASSIGN_DHCP]))
            log('IP assignment -> DHCP')
        elif 'ip' in cfg:
            for pid, key in ((PID_IP, 'ip'), (PID_MASK, 'mask'), (PID_GW, 'gw')):
                self.write(oi, pid, socket.inet_aton(cfg[key]))
            self.write(oi, PID_CFG_ASSIGN, bytes([ASSIGN_MANUAL]))
            log(f'IP assignment -> static {cfg["ip"]}/{cfg["mask"]} gw {cfg["gw"]}')


def interface_ia(host):
    """The connection interface's own individual address, from a discovery
    probe of the connection host (discover() reports a route-back answer
    under the address it came from, so the host matches either way)."""
    try:
        ip = socket.gethostbyname(host)      # conn host may be a hostname
    except OSError:
        ip = host
    for g in discover(hosts=[ip]):
        if g.get('ia') and g['ip'] == ip:
            return g['ia']
    raise LookupError(f'{host}: interface did not answer discovery')


def check_ia(host, ia, log=print):
    """Advisory: note when `ia` (the targeted device) differs from the
    connection interface's discovered IA — either the project IA is stale,
    or the target is genuinely another interface reached over the bus."""
    try:
        real = interface_ia(host)
    except LookupError:
        return
    if real != ia:
        log(f'note: the connection interface reports {ia_str(real)}; '
            f'targeting {ia_str(ia)} over the bus — if this device row IS '
            f'the connection interface, correct its IA to {ia_str(real)}')


def assign_ia(m, cur_ia, new_ia, host='', log=print, tries=10, delay=3.0):
    """Set a directly reachable interface's own individual address by writing
    OT-11 PID 52 — no programming mode needed. Like the IP settings, the
    address applies on RESTART (verified live: the device keeps answering at
    the old IA until rebooted), so: write, read back at the old address,
    restart, then poll discovery of `host` until it reports the new address
    (discovery is tunnel-independent — the restart kills our tunnel when we
    are connected through this very interface)."""
    want = struct.pack('!H', new_ia)
    f = Iface(m, cur_ia)
    oi = f.find_object(OT_KNXIP)
    log(f'writing address {ia_str(new_ia)} (was {ia_str(cur_ia)})')
    f.write(oi, PID_IA, want)
    got = f.read(oi, PID_IA)
    log('read-back: ' + (ia_str(struct.unpack('!H', got)[0])
                         if len(got) == 2 else 'no data'))
    log('restarting the interface to apply…')
    f.restart()
    if not host:
        return
    log('waiting for the interface to come back…')
    for _ in range(tries):
        time.sleep(delay)
        try:
            if interface_ia(host) == new_ia:
                log(f'verified — interface reports {ia_str(new_ia)}')
                return
        except LookupError:
            continue                     # still rebooting
    raise RuntimeError('interface did not report the new address '
                       f'{ia_str(new_ia)} after restart')


def read_status(m, ia, log=print):
    """Read and log the interface's live IP configuration."""
    f = Iface(m, ia)
    cfg = f.read_config()
    tuns = []
    for i in range(1, 17):           # PID 53 array, 2-byte elements
        v = f.read(cfg['oi'], PID_ADDITIONAL_IAS, 1, i)
        if len(v) < 2:
            break
        tuns.append(ia_str(struct.unpack('!H', v)[0]))
    log(f'friendly name   {cfg["name"] or "—"}')
    log(f'IP assignment   {"DHCP" if cfg["dhcp"] else "static"}')
    log(f'current IP      {cfg["cur_ip"]} / {cfg["cur_mask"]}  '
        f'gw {cfg["cur_gw"]}')
    log(f'configured IP   {cfg["ip"]} / {cfg["mask"]}  gw {cfg["gw"]}')
    log(f'MAC             {cfg["mac"]}')
    if tuns:
        log('tunnel slots    ' + ', '.join(tuns))


def apply_device(m, ia, cfg, log=print, restart=True):
    """Program a project's stored interface settings to the interface at `ia`.
    `cfg` holds deviations only (editor IP-settings page): name, assign
    ('dhcp'|'static'), ip/mask/gw. Reads the current config, writes only the
    differences, restarts the interface when anything changed (`restart=False`
    when the caller restarts anyway, e.g. an app download follows)."""
    f = Iface(m, ia)
    cur = f.read_config()
    changes = {}
    name = cfg.get('name', '')
    if name and name != cur['name']:
        changes['name'] = name
    assign = cfg.get('assign', '')
    if assign == 'dhcp' and not cur['dhcp']:
        changes['dhcp'] = True
    elif assign == 'static':
        ip, mask, gw = (cfg.get(k, '') for k in ('ip', 'mask', 'gw'))
        if not (ip and mask and gw):
            raise ValueError('static IP needs address, mask and gateway')
        if cur['dhcp'] or (ip, mask, gw) != (cur['ip'], cur['mask'],
                                             cur['gw']):
            changes.update(ip=ip, mask=mask, gw=gw)
    # tunnel slot addresses (PID 53, 2-byte elements, diffed per slot)
    tun_writes = []
    for i, t in enumerate(cfg.get('tunnels', [])):
        if not t:
            continue                 # empty slot = keep current
        want = struct.pack('!H', ia_int(t))
        if f.read(cur['oi'], PID_ADDITIONAL_IAS, 1, i + 1) != want:
            tun_writes.append((i, want, t))
    if not changes and not tun_writes:
        log('no changes — interface already matches the project')
        return
    f.apply_config(cur['oi'], changes, log)
    for i, want, t in tun_writes:
        f.write(cur['oi'], PID_ADDITIONAL_IAS, want, 1, i + 1)
        log(f'tunnel slot {i + 1} -> {t}')
    if restart:
        log('restarting the interface…')
        f.restart()

"""Minimal KNXnet/IP: gateway discovery, tunneling client, cEMI, DPT decode.

No Qt in here. The reader thread calls on_telegram(Telegram) / on_disconnect()
directly — marshal into your UI toolkit yourself.
"""
import queue, socket, struct, threading, time
from dataclasses import dataclass

PORT = 3671
MCAST = '224.0.23.12'

# service types
SEARCH_REQ, SEARCH_RES = 0x0201, 0x0202
SEARCH_REQ_EXT, SEARCH_RES_EXT = 0x020B, 0x020C
DESCR_REQ, DESCR_RES = 0x0203, 0x0204
CONNECT_REQ, CONNECT_RES = 0x0205, 0x0206
STATE_REQ, STATE_RES = 0x0207, 0x0208
DISC_REQ, DISC_RES = 0x0209, 0x020A
TUNNEL_REQ, TUNNEL_ACK = 0x0420, 0x0421
DEVCFG_REQ, DEVCFG_ACK = 0x0310, 0x0311


def frame(service, body):
    return struct.pack('!BBHH', 0x06, 0x10, service, 6 + len(body)) + body


def parse_frame(data):
    if len(data) < 6 or data[0] != 0x06:
        return None, b''
    service, total = struct.unpack('!HH', data[2:6])
    if not 6 <= total <= len(data):      # truncated: body would be silently short
        return None, b''
    return service, data[6:total]


def hpai(ip='0.0.0.0', port=0):
    return struct.pack('!BB4sH', 8, 0x01, socket.inet_aton(ip), port)


def ia_str(raw):
    return f'{raw >> 12}.{(raw >> 8) & 15}.{raw & 255}'


def ga_str(ga):
    return f'{ga >> 11}/{(ga >> 8) & 7}/{ga & 255}'


def ia_parts(s):
    try:
        a, l, d = (int(x) for x in s.split('.'))
    except ValueError:
        raise ValueError(f'bad individual address: {s} '
                         '(want area.line.device)') from None
    if not (0 <= a < 16 and 0 <= l < 16 and 0 <= d < 256):
        raise ValueError(f'address out of range: {s}')
    return a, l, d


def ia_int(s):
    a, l, d = ia_parts(s)
    return a << 12 | l << 8 | d


# ---- cEMI ----------------------------------------------------------------

@dataclass
class Telegram:
    src: int                 # individual address, raw
    dst: int                 # destination, raw (group or individual)
    apci: str                # 'read' | 'write' | 'response' | 'tpci' | hex
    data: bytes              # payload (decoded small values -> 1 byte)
    group: bool = True       # dst is a group address (ctrl2 bit 7)
    confirm: bool = False    # L_Data.con (our own send, confirmed) vs .ind
    tpci: int = 0            # raw TPCI/APCI-high octet
    apci10: int | None = None  # 10-bit APCI, None for control TPDUs
    tpdu: bytes = b''        # raw TPDU (TPCI/APCI octets + data), for Data Secure


def cemi_ldata(dst, tpdu, src=0, group=True):
    """L_Data.req with a raw TPDU (TPCI/APCI octets). NPDU length = len(tpdu)-1.
    Standard frame for NPDU length <= 15, else an extended frame (ctrl1 bit7=0)
    — a TP device behind a coupler needs the extended format for long APDUs
    (e.g. System B ext-memory writes)."""
    ctrl1 = 0xBC if len(tpdu) - 1 <= 15 else 0x3C   # bit7: 1=standard 0=extended
    ctrl2 = 0xE0 if group else 0x60      # group flag + hop count 6
    return struct.pack('!BBBBHHB', 0x11, 0, ctrl1, ctrl2, src, dst,
                       len(tpdu) - 1) + tpdu


def group_tpdu(data, apci=0x080, small=None):
    """TPDU for a group write (0x080) / response (0x040) / read (0x000).
    `small` packs the payload into the APCI's low 6 bits (None = pack any
    single byte < 0x40, a heuristic; use dpt_small(dpt) when the type is
    known — e.g. DPT 5 value 32 must NOT be packed). A read carries no data:
    pass b'' so the APDU stays the required 2 octets."""
    if small is None:
        small = len(data) == 1 and data[0] < 0x40
    if small and len(data) == 1 and data[0] < 0x40:
        return struct.pack('!BB', 0x00, apci | data[0])
    return struct.pack('!BB', 0x00, apci) + data


def cemi_group(dst, data, apci=0x080, src=0, small=None, key=None):
    """L_Data.req for a group write/response/read (see group_tpdu). With a
    16-byte group `key` the TPDU goes out Data Secure (S-A_Data, group SCF)."""
    tpdu = group_tpdu(data, apci, small)
    if key:
        from .knxdatasec import secure, next_seq
        tpdu = secure(key, tpdu, src, dst, next_seq(), tool=False, group=True)
    return cemi_ldata(dst, tpdu, src, group=True)


def parse_cemi(cemi):
    """L_Data.ind/.con -> Telegram (group or individual, data or control), else None."""
    if len(cemi) < 2:
        return None
    code, addil = cemi[0], cemi[1]
    if code not in (0x29, 0x2E):         # L_Data.ind / .con
        return None
    p = cemi[2 + addil:]
    if len(p) < 8:
        return None
    src, dst = struct.unpack('!HH', p[2:6])
    npdu_len = p[6]
    group, confirm = bool(p[1] & 0x80), code == 0x2E
    return parse_tpdu(src, dst, bytes(p[7:8 + npdu_len]), group, confirm)


def parse_tpdu(src, dst, tpdu, group=True, confirm=False):
    """TPDU (TPCI/APCI octets + data) -> Telegram, or None if truncated."""
    if not tpdu:
        return None
    tpci = tpdu[0]
    if tpci & 0x80:                      # control TPDU (T_Connect/Disconnect/ACK)
        return Telegram(src, dst, 'tpci', b'', group, confirm, tpci, None, tpdu)
    if len(tpdu) < 2:
        return None
    apci10 = ((tpci & 0x03) << 8) | tpdu[1]
    kind = apci10 & 0x3C0
    name = {0x000: 'read', 0x040: 'response', 0x080: 'write'}.get(
        kind, f'apci {apci10:#x}')
    data = tpdu[2:] if len(tpdu) > 2 else bytes([apci10 & 0x3F])
    return Telegram(src, dst, name, bytes(data), group, confirm, tpci, apci10, tpdu)


# ---- cEMI device management (M_Prop*, local interface config) ------------

MC_PROPREAD_REQ, MC_PROPREAD_CON = 0xFC, 0xFB
MC_PROPWRITE_REQ, MC_PROPWRITE_CON = 0xF6, 0xF5

PROP_ERRS = {0x01: 'out of range', 0x04: 'memory error', 0x05: 'read only',
             0x06: 'illegal command', 0x07: 'non-existing property',
             0x08: 'type conflict', 0x09: 'index range error',
             0x0A: 'temporarily not writable'}


def cemi_mprop(mc, obj_type, pid, data=b'', count=1, start=1, instance=1):
    """M_PropRead/Write body: addresses an interface object by TYPE+instance
    (no object-index scan needed, unlike A_PropertyValue on the bus)."""
    return struct.pack('!BHBBH', mc, obj_type, instance, pid,
                       count << 12 | start) + data


def parse_mprop(body):
    """-> (mc, obj_type, instance, pid, count, start, data) or None."""
    if len(body) < 7:
        return None
    mc, obj_type, instance, pid, cs = struct.unpack('!BHBBH', body[:7])
    return mc, obj_type, instance, pid, cs >> 12, cs & 0xFFF, body[7:]


# ---- application layer: APCIs and object ids used by more than one module -
# The rest of the APCI table (memory, descriptor, authorize, individual
# address) is management-only and lives in knxmgmt.

A_PROP_READ, A_PROP_RESP, A_PROP_WRITE = 0x3D5, 0x3D6, 0x3D7
A_RESTART = 0x380
# extended property services: interface object addressed by TYPE, not index
A_PROPEXT_READ, A_PROPEXT_RESP = 0x1CC, 0x1CD
A_PROPEXT_WRITE, A_PROPEXT_WRITE_RESP = 0x1CE, 0x1CF

# interface object types
OT_KNXIP, OT_SECURITY = 11, 17
# OT 11 PID 53: additional individual addresses = the tunnel slots. Read as
# interface config (knxiface), written as the tunnel users (knxsecure).
PID_ADDITIONAL_IAS = 53


# ---- DPT encode/decode ---------------------------------------------------

SMALL_DPT_MAINS = {1, 2, 3, 23}      # payload rides in the APCI's low 6 bits


def _dpt_main(dpt):
    try:
        return int((dpt or '').split('-')[1])
    except (IndexError, ValueError):
        return 0


def dpt_small(dpt):
    """True when the type's payload is packed into the APCI octet."""
    return _dpt_main(dpt) in SMALL_DPT_MAINS


def dpt9_word(v):
    """Encode a float as a KNX DPT 9 16-bit word: sign|exp:4|mant:11,
    value = 0.01 * mant * 2^exp, mantissa two's complement."""
    mant, exp = round(v * 100), 0
    while not -2048 <= mant <= 2047:
        mant >>= 1
        exp += 1
        if exp > 15:
            raise ValueError(f'{v} out of DPT 9 range')
    return ((mant < 0) << 15) | (exp << 11) | (mant & 0x7FF)


def dpt9_value(w):
    """Decode a 16-bit DPT 9 word to its float value (inverse of dpt9_word)."""
    mant = w & 0x7FF
    if w & 0x8000:
        mant -= 0x800
    return mant * 0.01 * (1 << ((w >> 11) & 0x0F))


def encode_dpt(dpt, value):
    """Value -> payload bytes for the common datapoint types (inverse of
    decode_dpt). DPT 1: truthy; 3: (up, step) tuple; 16: str; rest: numbers.
    Any other type takes hex text (what decode_dpt falls back to). Raises
    ValueError for a bad value."""
    main = _dpt_main(dpt)
    try:
        if main == 1:
            return b'\x01' if value else b'\x00'
        if main == 3:
            up, step = value
            if not 0 <= int(step) <= 7:
                raise ValueError
            return bytes([(8 if up else 0) | int(step)])
        if main == 5:
            v = int(value)
            if dpt == 'DPST-5-1':
                if not 0 <= v <= 100:
                    raise ValueError
                v = round(v * 255 / 100)
            return bytes([v])
        if main == 6:
            return struct.pack('!b', int(value))
        if main == 7:
            return struct.pack('!H', int(value))
        if main == 8:
            return struct.pack('!h', int(value))
        if main == 9:
            return struct.pack('!H', dpt9_word(float(value)))
        if main == 12:
            return struct.pack('!I', int(value))
        if main == 13:
            return struct.pack('!i', int(value))
        if main == 14:
            return struct.pack('!f', float(value))
        if main == 16:
            b = str(value).encode('latin-1')
            if len(b) > 14:
                raise ValueError(f'text too long ({len(b)} > 14 chars)')
            return b.ljust(14, b'\0')
        if main == 17:
            n = int(value)
            if not 1 <= n <= 64:
                raise ValueError
            return bytes([n - 1])
        return bytes.fromhex(value)
    except (TypeError, ValueError, struct.error) as e:
        raise ValueError(f'bad value for {dpt}: {value!r}') from e


def decode_dpt(dpt, data):
    """Human-readable value for common datapoint types; hex fallback."""
    main = _dpt_main(dpt)
    try:
        if main == 1:
            return 'on' if data[0] & 1 else 'off'
        if main == 3:
            d = data[0]
            step = d & 7
            return f"dim {'up' if d & 8 else 'down'} {step}" if step else 'dim stop'
        if main == 5:
            if dpt == 'DPST-5-1':
                return f'{data[0] * 100 // 255} %'
            return str(data[0])
        if main == 6:
            return str(struct.unpack('b', data[:1])[0])
        if main == 7:
            return str(struct.unpack('!H', data[:2])[0])
        if main == 8:
            return str(struct.unpack('!h', data[:2])[0])
        if main == 9:
            raw, = struct.unpack('!H', data[:2])
            return f'{dpt9_value(raw):.2f}'
        if main == 12:
            return str(struct.unpack('!I', data[:4])[0])
        if main == 13:
            return str(struct.unpack('!i', data[:4])[0])
        if main == 14:
            return f'{struct.unpack("!f", data[:4])[0]:.3f}'
        if main == 16:
            return data.rstrip(b'\0').decode('latin-1')
        if main == 17:
            return f'scene {data[0] + 1}'
    except (IndexError, struct.error):
        pass
    return data.hex(' ')


# ---- discovery -----------------------------------------------------------

def parse_dibs(p):
    """DIB list (from a search/description response) -> info dict."""
    d = {}
    while len(p) >= 2:
        ln, typ = p[0], p[1]
        if ln < 2 or ln > len(p):
            break
        b = p[2:ln]
        if typ == 0x01 and ln >= 54:         # device info
            d['ia'] = struct.unpack('!H', b[2:4])[0]
            d['name'] = b[22:52].rstrip(b'\0').decode('latin-1', 'replace')
        elif typ == 0x02:                    # supported service families
            d['families'] = {b[i]: b[i + 1] for i in range(0, len(b) - 1, 2)}
        elif typ == 0x03 and ln >= 16:       # configured IP
            d['cfg_ip'], d['cfg_mask'], d['cfg_gw'] = (
                socket.inet_ntoa(b[i:i + 4]) for i in (0, 4, 8))
            d['cfg_method'] = b[13]          # bitset: 1=manual 4=DHCP
        elif typ == 0x04 and ln >= 20:       # current IP
            d['cur_ip'], d['cur_mask'], d['cur_gw'], d['dhcp_server'] = (
                socket.inet_ntoa(b[i:i + 4]) for i in (0, 4, 8, 12))
            d['cur_method'] = b[16]
        elif typ == 0x06:                    # secured service families
            d['secure_families'] = {b[i]: b[i + 1]
                                    for i in range(0, len(b) - 1, 2)}
        p = p[ln:]
    # secure if any service is in the secured set, or the Security service
    # family (9) is supported (the 732 advertises only the latter)
    d['secure'] = bool(d.get('secure_families')) or 9 in d.get('families', {})
    return d


def discover(timeout=2.0, hosts=()):
    """SEARCH_REQUEST (plain + extended) via multicast plus unicast probes to
    `hosts` (multicast does not cross subnets). Returns dicts with at least
    {'name','ip','port','ia','secure'} plus parse_dibs extras when present.
    A device that replies with a zeroed HPAI (route-back mode) is reported
    under the address the answer actually came from.

    The request carries the address the device must send its answer TO, so it
    has to be OUR address on the route to THAT destination — a VPN'd interface
    and a LAN one need different ones, hence the per-destination HPAI."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found = {}
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        s.bind(('', 0))
        port = s.getsockname()[1]
        mine = {}
        for dest in [(MCAST, PORT)] + [(h, PORT) for h in hosts]:
            if dest[0] not in mine:
                mine[dest[0]] = hpai(_local_ip(dest[0]), port)
            for req in (frame(SEARCH_REQ, mine[dest[0]]),
                        frame(SEARCH_REQ_EXT, mine[dest[0]])):
                try:
                    s.sendto(req, dest)
                except OSError:
                    pass
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, peer = s.recvfrom(4096)
            except socket.timeout:
                break
            service, body = parse_frame(data)
            if service not in (SEARCH_RES, SEARCH_RES_EXT) or len(body) < 8:
                continue
            gw_ip = socket.inet_ntoa(body[2:6])
            gw_port = struct.unpack('!H', body[6:8])[0]
            if gw_ip == '0.0.0.0':
                gw_ip, gw_port = peer
            key = (gw_ip, gw_port)
            ext = service == SEARCH_RES_EXT      # extended answer wins
            if key in found and found[key]['ext'] >= ext:
                continue
            info = {'name': '', 'ia': 0, 'ip': gw_ip, 'port': gw_port,
                    'ext': ext}
            info.update(parse_dibs(body[8:]))
            found[key] = info
    finally:
        s.close()
    return list(found.values())


def _local_ip(dest='192.0.2.1'):
    """Our source address on the route to `dest`. Connecting a UDP socket sends
    nothing but makes the kernel pick the route, so a destination behind a VPN
    yields the tunnel address rather than the default interface's."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest, 1))                 # no traffic sent
        return s.getsockname()[0]
    except OSError:
        return '0.0.0.0'
    finally:
        s.close()


# ---- tunneling client ----------------------------------------------------

class TunnelClient:
    """Plain KNXnet/IP tunneling. connect() blocks; reader runs in a thread."""

    CRI = struct.pack('!BBBB', 4, 0x04, 0x02, 0x00)   # tunnel, LinkLayer
    REQ_SVC = TUNNEL_REQ
    CTRL_HPAI = hpai()          # our endpoint in connect/disconnect/keepalive

    def __init__(self, host, port=PORT, on_telegram=None, on_disconnect=None):
        self.addr = (host, port)
        self.on_telegram = on_telegram or (lambda t: None)
        self.on_disconnect = on_disconnect or (lambda reason: None)
        self.sock = None
        self.channel = None
        self.seq_send = 0
        self.seq_recv = None                 # last seq processed (None = none yet)
        self.ia = 0                          # assigned by the gateway
        self.raw_hook = None                 # set by mgmt layer; returns True to swallow
        self._mprops = queue.Queue()         # M_Prop confirmations (DM conns)
        self._acked = threading.Event()
        self._txlock = threading.RLock()     # serialises seq_send across senders
        self._alive = False
        self._state_ok = False               # set by the reader on STATE_RESPONSE

    CONNECT_ERRS = {0x21: 'connection type not supported',
                    0x22: 'connection option not supported '
                          '(secure-only device? use ip-secure)',
                    0x23: 'no free tunnel connection',
                    0x29: 'authorisation error'}

    # subclass hooks for IP Secure
    def _tx(self, data):
        self.sock.sendto(data, self.addr)

    def _unwrap(self, data):
        return data

    def _handshake(self):
        pass

    def connect(self, timeout=3.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))
        self.sock.settimeout(timeout)
        self._handshake()                    # IP Secure session setup
        self._connect_loop(self.CTRL_HPAI * 2, timeout)

    def _connect_loop(self, hpais, timeout):
        """Send CONNECT_REQUEST, await the response (channel + assigned IA),
        start the reader and keepalive threads."""
        body = hpais + self.CRI
        self._tx(frame(CONNECT_REQ, body))
        end = time.time() + timeout
        while time.time() < end:
            service, b = self._rx(timeout)
            if service == CONNECT_RES:
                if b[1] != 0:
                    why = self.CONNECT_ERRS.get(b[1], '')
                    raise ConnectionError(
                        f'gateway refused: status {b[1]:#x} {why}'.strip())
                self.channel = b[0]
                if len(b) >= 14:             # CRD with assigned address
                    self.ia = struct.unpack('!H', b[12:14])[0]
                break
        else:
            raise ConnectionError('no CONNECT_RESPONSE')
        self._alive = True
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _rx(self, timeout):
        self.sock.settimeout(timeout)
        try:
            data, _ = self.sock.recvfrom(1024)
        except socket.timeout:
            return None, b''
        return parse_frame(self._unwrap(data))

    def disconnect(self):
        alive, self._alive = self._alive, False
        if alive and self.channel is not None:
            body = struct.pack('!BB', self.channel, 0) + self.CTRL_HPAI
            try:
                self._tx(frame(DISC_REQ, body))
            except OSError:
                pass
        if self.sock:
            self.sock.close()
            self.sock = None

    def group_write(self, ga, data, small=None, key=None):
        self.send_cemi(cemi_group(ga, data, 0x080, self.ia, small=small,
                                  key=key))

    def group_read(self, ga, key=None):
        self.send_cemi(cemi_group(ga, b'', 0x000, self.ia, key=key))

    def send_cemi(self, cemi):
        if not self._alive:
            raise ConnectionError('not connected')
        with self._txlock:
            head = struct.pack('!BBBB', 4, self.channel, self.seq_send, 0)
            pkt = frame(self.REQ_SVC, head + cemi)
            self._acked.clear()
            for _ in range(2):               # send + one retry
                self._tx(pkt)
                if self._acked.wait(1.0):
                    self.seq_send = (self.seq_send + 1) & 0xFF
                    return
            self._die('no TUNNELING_ACK')
            raise ConnectionError('no TUNNELING_ACK')   # the frame never left

    def _reader(self):
        while self._alive:
            service, body = self._rx(1.0)
            if service is None:
                continue
            if service == TUNNEL_REQ and len(body) >= 4:
                channel, seq = body[1], body[2]
                self._tx(frame(TUNNEL_ACK, struct.pack('!BBBB', 4, channel, seq, 0)))
                if seq == self.seq_recv:
                    continue                       # duplicate, our ack was lost
                self.seq_recv = seq
                t = parse_cemi(body[4:])
                if t and not (self.raw_hook and self.raw_hook(t)):
                    self.on_telegram(t)
            elif service in (TUNNEL_ACK, DEVCFG_ACK):
                self._acked.set()
            elif service == DEVCFG_REQ and len(body) >= 4:
                self._tx(frame(DEVCFG_ACK,
                               struct.pack('!BBBB', 4, body[1], body[2], 0)))
                self._mprops.put(body[4:])
            elif service == STATE_RES:
                self._state_ok = True
            elif service == DISC_REQ:
                self._tx(frame(DISC_RES, struct.pack('!BB', body[0], 0)))
                self._die('gateway closed the connection')

    def _keepalive(self):
        while self._alive:
            for _ in range(60):
                if not self._alive:
                    return
                time.sleep(1)
            self._state_ok = False
            body = struct.pack('!BB', self.channel, 0) + self.CTRL_HPAI
            for _ in range(2):
                try:
                    self._tx(frame(STATE_REQ, body))
                except OSError:
                    return
                time.sleep(2)
                if self._state_ok:
                    break
            else:
                self._die('keepalive timeout')

    def _die(self, reason):
        if self._alive:
            self._alive = False
            self.on_disconnect(reason)


class DevMgmtClient(TunnelClient):
    """KNXnet/IP local device management: configure the gateway itself via
    M_PropRead/Write (interface object type + instance, e.g. type 11 =
    KNXnet/IP parameters). Secure variant: knxsec.SecureDevMgmtClient."""

    CRI = bytes([2, 0x03])               # DEVICE_MGMT_CONNECTION
    REQ_SVC = DEVCFG_REQ

    def mprop_read(self, obj_type, pid, count=1, start=1, instance=1):
        return self._mprop(MC_PROPREAD_REQ, MC_PROPREAD_CON,
                           obj_type, pid, b'', count, start, instance)

    def mprop_write(self, obj_type, pid, data, count=1, start=1, instance=1):
        self._mprop(MC_PROPWRITE_REQ, MC_PROPWRITE_CON,
                    obj_type, pid, data, count, start, instance)

    def _mprop(self, mc, con, obj_type, pid, data, count, start, instance):
        while not self._mprops.empty():
            self._mprops.get_nowait()
        self.send_cemi(cemi_mprop(mc, obj_type, pid, data, count, start,
                                  instance))
        end = time.time() + 3.0
        while True:
            try:
                r = parse_mprop(self._mprops.get(
                    timeout=max(0.1, end - time.time())))
            except queue.Empty:
                raise TimeoutError(
                    f'no M_Prop confirmation (pid {pid})') from None
            if not r or (r[0], r[1], r[3]) != (con, obj_type, pid):
                continue
            if r[4] == 0:                # error .con: count=0, 1-byte code
                code = r[6][0] if r[6] else 0
                raise ValueError(f'property {pid}: error {code:#x} '
                                 f'{PROP_ERRS.get(code, "")}'.strip())
            return r[6]

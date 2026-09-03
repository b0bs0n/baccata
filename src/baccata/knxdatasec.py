"""KNX Data Secure — application-layer security (AN158).

Secures management APDUs in an S-A_Data APDU (APCI 0x3F1) with AES-128 CCM under
the device *tool key*. This is what ETS uses to manage a security-ON device: the
plaintext property services return empty/UNSPECIFIED, the same services wrapped in
Data Secure work.

CCM scheme is the KNX custom 16-byte-B0 variant (as in knxsec.py for IP Secure),
but with the Data-Secure block layout. It is pinned byte-for-byte against real ETS
SyncRequest frames to the Weinzierl 732 with its known tool key
(tests/test_datasec.py) and calimero SecureApplicationLayer.
"""
import base64, os, re, struct, time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

S_A_DATA = 0x3F1

# SCF service codes (low 3 bits)
SVC_DATA = 0
SVC_SYNC_REQ = 2
SVC_SYNC_RES = 3


def decode_fdsk(cert):
    """Decode a device's FDSK from the base32 'Cert' string on its label
    (e.g. 'ADCQCB-ZBDN2Z-...'). Returns (serial: 6 bytes, fdsk: 16 bytes).
    In factory state the tool key equals the FDSK."""
    b32 = cert.replace('-', '').replace(' ', '').upper()
    raw = base64.b32decode(b32 + '=' * (-len(b32) % 8))[:22]
    return raw[:6], raw[6:22]


CERT_RE = re.compile(
    r'(?<![A-Z2-7])((?:[A-Z2-7]{6}[- ]?){5}[A-Z2-7]{6})(?![A-Z2-7])')


def cert_from_text(text):
    """Find a device cert (36 base32 chars, bare or 6x6 dash/space groups) in
    scanned QR text; return it normalized to dashed uppercase. ValueError if
    the text contains none."""
    m = CERT_RE.search(text.upper())
    if not m:
        raise ValueError('no FDSK certificate in scanned code')
    b32 = re.sub(r'[- ]', '', m.group(1))
    return '-'.join(b32[i:i + 6] for i in range(0, 36, 6))


def scf(service, tool=True):
    """Security Control Field byte. b7 tool access, b4 Auth+Conf (always: we
    never send Auth-only), b3 system broadcast (never), b2-0 service."""
    return (0x80 if tool else 0) | 0x10 | (service & 0x07)


def cbc_mac(key, b0, aad, payload):
    """KNX CCM CBC-MAC: one contiguous run b0 | len(aad) | aad | payload,
    zero-padded once to 16. Shared with the IP Secure layer (knxsec) — the
    two differ in the B0 layout, not in the MAC itself."""
    data = b0 + struct.pack('!H', len(aad)) + aad + payload
    data += b'\0' * (-len(data) % 16)
    enc = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16)).encryptor()
    return (enc.update(data) + enc.finalize())[-16:]


def _blocks(seq, src, dst, group, tpci, plen):
    """CCM B0 (MAC) and counter-0 (CTR IV) for a secured APDU. `tpci` is the
    secured APDU's first octet (transport bits | the 0x3F1 high bits); B0 also
    carries the 0x3F1 low octet as the APCI byte."""
    at = 0x80 if group else 0                      # | extended-frame-format (0)
    head = seq + struct.pack('!HH', src, dst)
    b0 = head + bytes([0, at, tpci, S_A_DATA & 0xFF, 0, plen])
    ctr0 = head + b'\0\0\0\0\x01\x00'
    return b0, ctr0


def _ctr(key, ctr0, data):
    c = Cipher(algorithms.AES(key), modes.CTR(ctr0)).encryptor()
    return c.update(data)


def _tpci_octet(base_tpci):
    return (base_tpci & 0xFC) | (S_A_DATA >> 8)    # low 2 bits carry APCI high


def secure(key, plain, src, dst, seq, *, service=SVC_DATA, serial=b'',
           tool=True, group=False, base_tpci=0x00):
    """Build a secured (S-A_Data) TPDU. `plain` is the plaintext protected:
    the full inner APDU (its APCI octets + data) for SVC_DATA, or the 6-byte
    challenge for SVC_SYNC_REQ. Returns the TPDU starting with the 0x3F1 octets."""
    tpci = _tpci_octet(base_tpci)
    s = scf(service, tool=tool)
    ser = serial if service != SVC_DATA else b''
    b0, ctr0 = _blocks(seq, src, dst, group, tpci, len(plain))
    mac = cbc_mac(key, b0, bytes([s]) + ser, plain)[:4]
    stream = _ctr(key, ctr0, mac + plain)
    enc_mac, enc = stream[:4], stream[4:]
    return (bytes([tpci, S_A_DATA & 0xFF, s]) + seq + ser + enc + enc_mac)


def unsecure(key, tpdu, src, dst, *, group=False):
    """Verify + decrypt a secured TPDU (starting with the 0x3F1 octets).
    Returns (service, seq:6, plain, serial). Raises ValueError on MAC mismatch."""
    tpci = tpdu[0]
    body = tpdu[2:]                                # after the 2 APCI octets
    s = body[0]
    service = s & 0x07
    # SCF | seq:6 | [serial:6] | ciphertext | mac:4 — SyncReq carries dst serial
    head = 13 if service == SVC_SYNC_REQ else 7
    if len(body) < head + 4:
        raise ValueError(f'truncated Data Secure TPDU ({len(body)} bytes)')
    seq, serial, rest = body[1:7], body[7:head], body[head:]
    enc, enc_mac = rest[:-4], rest[-4:]
    b0, ctr0 = _blocks(seq, src, dst, group, tpci, len(enc))
    stream = _ctr(key, ctr0, enc_mac + enc)
    mac_plain, plain = stream[:4], stream[4:]
    if cbc_mac(key, b0, bytes([s]) + serial, plain)[:4] != mac_plain:
        raise ValueError('Data Secure MAC mismatch (wrong tool key?)')
    return service, seq, plain, serial


def unsecure_group(key, t):
    """Decrypt a secured group telegram `t` (knxip.Telegram with apci10 0x3F1)
    under its group key; returns the plaintext Telegram. Passive — no seq or
    replay tracking. Raises ValueError on MAC mismatch."""
    from .knxip import parse_tpdu
    _, _, plain, _ = unsecure(key, t.tpdu, t.src, t.dst, group=True)
    p = parse_tpdu(t.src, t.dst, plain, t.group, t.confirm)   # plain = inner TPDU
    if p is None:
        raise ValueError('empty Data Secure payload')
    return p


def parse_sync_response(key, tpdu, src, dst, challenge, *, group=False):
    """Parse a SyncResponse (service 3) sent by `src` to us (`dst`) in reply to
    our SyncRequest whose 6-byte `challenge` we still hold. The wire's seq field
    is (random XOR challenge); recover random, rebuild the blocks with it, verify
    + decrypt. Returns (device_next_seq, our_next_seq) as 48-bit ints."""
    tpci = tpdu[0]
    body = tpdu[2:]
    s = body[0]
    if s & 0x07 != SVC_SYNC_RES:
        raise ValueError(f'not a SyncResponse (SCF {s:#04x})')
    if len(body) < 11:
        raise ValueError(f'truncated SyncResponse ({len(body)} bytes)')
    rand = bytes(a ^ b for a, b in zip(body[1:7], challenge))
    enc, enc_mac = body[7:-4], body[-4:]
    b0, ctr0 = _blocks(rand, src, dst, group, tpci, len(enc))
    stream = _ctr(key, ctr0, enc_mac + enc)
    mac_plain, plain = stream[:4], stream[4:]
    if cbc_mac(key, b0, bytes([s]), plain)[:4] != mac_plain:
        raise ValueError('SyncResponse MAC mismatch (wrong tool key?)')
    dev_next = int.from_bytes(plain[0:6], 'big')     # sender's (device) next seq
    our_next = int.from_bytes(plain[6:12], 'big')    # our next seq, as device sees
    return dev_next, our_next


def build_sync_response(key, src, dst, challenge, our_next, their_next, *,
                        rand=None, group=False, base_tpci=0x00):
    """Build a SyncResponse (for answering a peer's SyncRequest). Plaintext =
    [our_next:6][their_next:6]; the wire seq field carries (rand XOR challenge)."""
    rand = rand or os.urandom(6)
    tpci = _tpci_octet(base_tpci)
    s = scf(SVC_SYNC_RES)
    plain = our_next.to_bytes(6, 'big') + their_next.to_bytes(6, 'big')
    b0, ctr0 = _blocks(rand, src, dst, group, tpci, len(plain))
    mac = cbc_mac(key, b0, bytes([s]), plain)[:4]
    stream = _ctr(key, ctr0, mac + plain)
    enc_mac, enc = stream[:4], stream[4:]
    xored = bytes(a ^ b for a, b in zip(rand, challenge))
    return bytes([tpci, S_A_DATA & 0xFF]) + bytes([s]) + xored + enc + enc_mac


_last_seq = 0


def next_seq():
    """A monotonic 6-byte sequence number. Epoch-ms never regresses across
    sessions, satisfying the device's replay check; two calls in the same ms
    still count up."""
    global _last_seq
    _last_seq = max(int(time.time() * 1000), _last_seq + 1)
    return struct.pack('!Q', _last_seq)[2:]


class DataSecure:
    """Per-link Data Secure state: the tool key, our source IA, and a monotonic
    send sequence. Wraps outgoing plain APDUs and unwraps responses so callers
    keep matching on the inner APCI."""

    def __init__(self, key, src):
        self.key = key
        self.src = src
        self._seq = int.from_bytes(next_seq(), 'big')
        self._rx = -1            # last accepted device seq (replay guard)

    def _seq_bytes(self):
        s = self._seq
        self._seq += 1
        return s.to_bytes(6, 'big')

    def wrap(self, plain, dst, *, group=False, base_tpci=0x00, tool=True):
        return secure(self.key, plain, self.src, dst, self._seq_bytes(),
                      service=SVC_DATA, tool=tool, group=group,
                      base_tpci=base_tpci)

    def unwrap(self, tpdu, src, dst, *, group=False, check_replay=True):
        service, seq, plain, _serial = unsecure(self.key, tpdu, src, dst,
                                                group=group)
        if service != SVC_DATA:
            # a Sync request/response carries a challenge or seq pair, not an
            # APDU — returning it would be parsed as one by every caller
            raise ValueError(f'not a Data Secure data frame (service {service})')
        n = int.from_bytes(seq, 'big')
        if check_replay and n <= self._rx:
            raise ValueError('replayed Data Secure frame')
        self._rx = max(self._rx, n)
        return plain

    def sync_request(self, dst, serial=b'\0' * 6, *, group=False,
                     base_tpci=0x00):
        challenge = os.urandom(6)
        return challenge, secure(
            self.key, challenge, self.src, dst, self._seq_bytes(),
            service=SVC_SYNC_REQ, serial=serial, group=group,
            base_tpci=base_tpci)

    def adopt_sync(self, device_next, our_next):
        """Apply a parsed SyncResponse: never let our send seq or the device
        replay baseline regress."""
        if our_next > self._seq:
            self._seq = our_next
        self._rx = max(self._rx, device_next - 1)

    def fresh(self):
        """A new session with the same key and source: fresh monotonic sequence,
        cleared replay baseline. A connect retry must not reuse a session whose
        sequence the device has already rejected — knxsecure.warm_conn does the
        same by rebuilding the session on every attempt."""
        return DataSecure(self.key, self.src)

    def rekey(self, new_key):
        """Switch the tool key mid-session (e.g. right after writing a new tool
        key: the device now expects the new key for every following frame). The
        monotonic send sequence is kept, and the receive baseline is reset since
        it belonged to the old key."""
        self.key = new_key
        self._rx = -1

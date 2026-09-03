"""KNXnet/IP Secure session layer wrapping TunnelClient.

The CCM block layout follows the KNX AN159 scheme (custom 16-byte B0, not
RFC 3610 nonce sizes), so it is built from raw AES-CBC/CTR. Validated against
the KNX spec test vectors (tests/test_knxip.py) and a real 732 interface.
"""
import hmac, os, socket, struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .knxdatasec import cbc_mac        # same KNX CCM MAC, different B0 layout
from .knxip import (DevMgmtClient, TunnelClient, frame, parse_frame,
                   parse_cemi, STATE_RES, DEVCFG_REQ, DISC_REQ, DISC_RES,
                   TUNNEL_REQ)

SESSION_REQ = 0x0951
SESSION_RES = 0x0952
SESSION_AUTH = 0x0953
SESSION_STATUS = 0x0954
TIMER_NOTIFY = 0x0955
WRAPPER = 0x0950


def _pbkdf2(password, salt):
    return PBKDF2HMAC(SHA256(), 16, salt, 65536).derive(password.encode())


def user_key(password):
    return _pbkdf2(password, b'user-password.1.secure.ip.knx.org')


def device_key(auth_code):
    return _pbkdf2(auth_code, b'device-authentication-code.1.secure.ip.knx.org')


def ccm(key, b0, aad, payload, encrypt, mac_in=b''):
    """KNX-style CCM: CBC-MAC over b0|len(aad)|aad|payload; CTR encrypts the
    MAC with counter block 0 (= b0[0:14]|ff00) and the payload with blocks 1+.
    Returns (out_payload, mac) for encrypt; (payload, mac) verified for decrypt."""
    ctr = Cipher(algorithms.AES(key),
                 modes.CTR(b0[:14] + b'\xff\x00')).encryptor()
    if encrypt:
        mac = ctr.update(cbc_mac(key, b0, aad, payload))
        return ctr.update(payload), mac
    mac_tr = ctr.update(mac_in)              # decrypt MAC (counter 0)
    plain = ctr.update(payload)
    if not hmac.compare_digest(cbc_mac(key, b0, aad, plain), mac_tr):
        raise ValueError('CCM MAC mismatch')
    return plain, mac_tr


HPAI_TCP = struct.pack('!BB4sH', 8, 0x02, b'\0\0\0\0', 0)   # route-back


class SecureTunnelClient(TunnelClient):
    """IP Secure tunneling: X25519 session + AES-128 CCM secure wrapper.
    Secure sessions run over TCP (stream framing, no TUNNELING_ACKs)."""

    CTRL_HPAI = HPAI_TCP
    def __init__(self, host, port=3671, user_id=2, password='',
                 auth_code='', **kw):
        super().__init__(host, port, **kw)
        self.user_id = user_id
        self.password = password
        # Carried but NOT used yet: the device authentication code keys the
        # SESSION_RESPONSE MAC, i.e. it authenticates the *gateway* to us. We
        # do not verify that MAC, so a secure session is confidential but the
        # peer is unauthenticated. Wiring it up needs a capture to pin the
        # construction against (see the module docstring's grounding rule) —
        # every other block here is byte-pinned, this one would be a guess.
        self.auth_code = auth_code
        self.session = None
        self.key = None
        self.serial = b'\0\0\0\0\0\0'
        self._seq = 0            # secure-wrapper sequence, session-scoped counter
        self._seq_rx = -1        # last received wrapper sequence (replay check)
        self._buf = b''

    CONNECT_ERRS = {0x22: 'connection option not supported',
                    0x23: 'no free tunnel connection',
                    0x24: 'no more connections (stale tunnels? wait ~1 min)',
                    0x29: 'authorisation error'}

    def connect(self, timeout=3.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(self.addr)
        self._handshake()
        self._connect_loop(self.CTRL_HPAI * 2, timeout)

    def _read_frame(self):
        while True:
            if len(self._buf) >= 6:
                total = struct.unpack('!H', self._buf[4:6])[0]
                if total < 6:
                    raise ConnectionError('bad frame header')
                if total <= len(self._buf):
                    pkt, self._buf = self._buf[:total], self._buf[total:]
                    return pkt
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError('TCP connection closed')
            self._buf += chunk

    def _rx(self, timeout):
        self.sock.settimeout(timeout)
        try:
            return parse_frame(self._unwrap(self._read_frame()))
        except socket.timeout:
            return None, b''

    def send_cemi(self, cemi):
        if not self._alive:
            raise ConnectionError('not connected')
        with self._txlock:
            head = struct.pack('!BBBB', 4, self.channel, self.seq_send, 0)
            self._tx(frame(self.REQ_SVC, head + cemi))   # TCP: no ack
            self.seq_send = (self.seq_send + 1) & 0xFF

    def _reader(self):
        while self._alive:
            try:
                service, body = self._rx(1.0)
            except (ConnectionError, OSError, ValueError) as e:
                self._die(str(e))
                return
            if service == TUNNEL_REQ and len(body) >= 4:
                t = parse_cemi(body[4:])
                if t and not (self.raw_hook and self.raw_hook(t)):
                    self.on_telegram(t)
            elif service == DEVCFG_REQ and len(body) >= 4:
                self._mprops.put(body[4:])   # TCP: no DEVCFG_ACK
            elif service == STATE_RES:
                self._state_ok = True
            elif service == DISC_REQ:
                self._tx(frame(DISC_RES, struct.pack('!BB', body[0], 0)))
                self._die('gateway closed the connection')

    # -- handshake (TCP socket exists, timeout set)
    def _handshake(self):
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        self.sock.sendall(frame(SESSION_REQ, HPAI_TCP + pub))
        try:
            service, body = parse_frame(self._read_frame())
        except socket.timeout:
            raise ConnectionError(
                'no reply to SESSION_REQUEST (secure not enabled?)') from None
        if service != SESSION_RES or len(body) < 50:
            raise ConnectionError('no SESSION_RESPONSE (secure not enabled?)')
        self.session = struct.unpack('!H', body[:2])[0]
        server_pub = body[2:34]
        shared = priv.exchange(X25519PublicKey.from_public_bytes(server_pub))
        h = Hash(SHA256())
        h.update(shared)
        self.key = h.finalize()[:16]
        xor_pub = bytes(a ^ b for a, b in zip(pub, server_pub))

        # authenticate: MAC over header|0|user|xor(pubkeys) with password key,
        # sent INSIDE the secure wrapper (everything after SESSION_RESPONSE is)
        auth_body = struct.pack('!BB', 0, self.user_id)
        aad = (frame(SESSION_AUTH, auth_body + b'\0' * 16)[:6]
               + auth_body + xor_pub)
        _, mac = ccm(user_key(self.password), b'\0' * 16, aad, b'', True)
        self._tx(frame(SESSION_AUTH, auth_body + mac))
        try:
            for _ in range(4):               # skip timer notifies etc.
                service, body = parse_frame(self._unwrap(self._read_frame()))
                if service == SESSION_STATUS:
                    break
            else:
                raise ConnectionError('no SESSION_STATUS after authenticate')
        except socket.timeout:
            raise ConnectionError(
                'no SESSION_STATUS after authenticate') from None
        if body[0] != 0:
            why = {1: 'authentication failed (wrong user id or password?)',
                   2: 'unauthenticated', 3: 'timeout', 4: 'closed'}.get(
                body[0], '')
            raise ConnectionError(f'secure auth: status {body[0]} {why}'.strip())

    # -- wrapper
    def _tx(self, data):
        # lock: send_cemi/_keepalive/_reader all send; seq reuse would repeat
        # a CTR counter under the session key
        with self._txlock:
            if self.key is None:
                self.sock.sendall(data)
                return
            seq = struct.pack('!Q', self._seq)[2:]   # 48-bit session counter
            self._seq += 1
            tag = os.urandom(2)
            # body = session | seq | serial | tag | ciphertext | mac:16
            sess = struct.pack('!H', self.session)
            prefix = sess + seq + self.serial + tag
            header = struct.pack('!BBHH', 0x06, 0x10, WRAPPER,
                                 6 + len(prefix) + len(data) + 16)
            b0 = seq + self.serial + tag + struct.pack('!H', len(data))
            enc, mac = ccm(self.key, b0, header + sess, data, True)
            self.sock.sendall(header + prefix + enc + mac)

    def _unwrap(self, data):
        service, body = parse_frame(data)
        if service != WRAPPER or self.key is None:
            return data
        session = body[:2]
        seq, serial, tag = body[2:8], body[8:14], body[14:16]
        enc, mac = body[16:-16], body[-16:]
        b0 = seq + serial + tag + struct.pack('!H', len(enc))
        aad = data[:6] + session
        plain, _ = ccm(self.key, b0, aad, enc, False, mac)
        seqn = int.from_bytes(seq, 'big')
        if seqn <= self._seq_rx:
            raise ValueError('replayed secure wrapper')
        self._seq_rx = seqn
        return plain


class SecureDevMgmtClient(DevMgmtClient, SecureTunnelClient):
    """Device management inside an IP Secure session. Defaults to the
    management user (user 1) — commissioning writes require it."""

    def __init__(self, host, port=3671, **kw):
        kw.setdefault('user_id', 1)
        super().__init__(host, port, **kw)


def make_bus(c, **kw):
    """Tunnel client for a project connection dict (type/host/port/user/…)."""
    if c.get('type') == 'ip-secure':
        return SecureTunnelClient(
            c['host'], c.get('port', 3671), user_id=c.get('user', 2),
            password=c.get('password', ''),
            auth_code=c.get('auth_code', ''), **kw)
    return TunnelClient(c['host'], c.get('port', 3671), **kw)

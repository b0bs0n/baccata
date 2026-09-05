"""KNX Secure commissioning — provision a factory device with security (no ETS).

Builds on knxdatasec (S-A_Data tool-key transport) and the connected Conn service
set. The commissioning model (KNX support articles, references-first):

  read cert -> serial + FDSK (factory tool key)
  -> talk to the device with tool key = FDSK
  -> generate a project tool key, WRITE it (replaces the FDSK at runtime)
  -> set device auth code, tunnelling users + passwords, secured service families
  -> activate secure mode.

Security state lives in the Security Interface Object (OT 17) and the KNXnet/IP
Parameter Object (OT 11). Access is via the extended, object-by-TYPE services
(FunctionProperty-Ext for security mode, PropertyExt for the key tables) so no
object-index scan is needed. Every op can be Data-Secure-wrapped by giving the
Conn a DataSecure session; before that, security mode is readable plaintext.

Grounding: the FunctionProperty-Ext addressing is pinned byte-for-byte against a
real ETS commissioning capture (tests/test_secure.py, frame OT-17/PID-51). The
tool-key write encoding is the one op with no capture to copy — flagged in
commission() for live pinning.
"""
import hashlib, json, os, struct

from .knxsec import device_key, user_key           # PBKDF2 with the KNX salts
from .knxip import (A_PROPEXT_READ, A_PROPEXT_RESP, A_PROPEXT_WRITE,
                   A_PROPEXT_WRITE_RESP, OT_KNXIP, OT_SECURITY,
                   PID_ADDITIONAL_IAS, ga_str)
from .knxdatasec import DataSecure
from .knxmgmt import Conn, project_links

# --- APCI (extended, object-by-type) --------------------------------------
# Values pinned to a real ETS6 secure commission (captures/knx-commission-secure
# .pcap, device = 732). The earlier guesses were one slot off in each block.
# The A_PropertyExt* block is shared with knxmgmt, so it lives in knxip.
A_FUNC_PROP_EXT_CMD = 0x1D4      # A_FunctionPropertyExtCommand (set, with value)
A_FUNC_PROP_EXT_READ = 0x1D5     # A_FunctionPropertyExtStateRead (get)
A_FUNC_PROP_EXT_RESP = 0x1D6     # A_FunctionPropertyExtStateResponse

# Security Interface Object (OT 17) PIDs. Layout/format pinned from the device
# stack thelsing/knx (security_interface_object.cpp) + KNX master, and — for the
# group-comms tables — from captures/knx-cheops-secure.pcap, an ETS6 commission +
# download + decommission of the Theben Cheops S.
PID_LOAD_STATE_CTRL = 5          # generic PID_LOAD_STATE_CONTROL (load state m/c)
LOAD_LOAD, LOAD_COMPLETED, LOAD_UNLOAD = 1, 2, 4   # PID 5 record events
PID_SEC_MODE = 51                # security mode (FunctionProperty; 0=off 1=on)
PID_P2P_KEY_TABLE = 52           # PDT_GENERIC_20: 2B index + 16B key + 2B roles
PID_GRP_KEY_TABLE = 53           # PDT_GENERIC_18: 2B index + 16B key. CONFIRMED
                                 # in the Cheops capture: one element per SECURED
                                 # group address, written singly at start=N, e.g.
                                 # n=1 start=1 data=0001<16B key>. The 2B index is
                                 # the GA's ADDRESS-TABLE index, not the GA itself.
PID_SEC_IA_TABLE = 54            # PDT_GENERIC_08: 2B address + 6B seqno (x32).
                                 # Element 0 is the entry COUNT — the Cheops got
                                 # `n=1 start=0 data=0000`, i.e. an empty table.
PID_SEC_FAILURES_LOG = 55
PID_TOOL_KEY = 56                # PID_SKI_TOOL, PDT_GENERIC_16: the 16B tool key
                                 # (default FDSK; ETS overwrites at commission,
                                 # factory reset restores FDSK). Confirmed = 56
                                 # in the ETS6 capture (was wrongly 60 = zone key)
PID_SEQ_SENDING = 63             # 6-byte sending sequence
PID_TOOL_SEQ_SENDING = 59        # 6-byte tool sending sequence. ETS SEEDS this
                                 # right after writing the tool key (Cheops
                                 # capture: `SEC/TOOL_SEQ n=1 start=1
                                 # data=003f9abbd6ba`). We do not, and the 732
                                 # commission worked without it — the device's own
                                 # counter is authoritative and Conn.sync() reads
                                 # it back. Noted, not copied.
PID_GO_SECURITY_FLAGS = 61       # per-GROUP-OBJECT security flags: one byte per
                                 # com-object NUMBER, 1-based, written in chunks.
                                 # DECODED from the Cheops capture: 117 elements,
                                 # non-zero only at 4 and 35 (=0x03) — exactly the
                                 # two com objects the project links (O-4 -> 8/0/0,
                                 # O-35 -> 2/0/0), the two GAs ETS then named as
                                 # "will communicate plain" when security was
                                 # switched off. So 0x03 marks an object as
                                 # secured; 0x00 leaves it plaintext.

# FunctionProperty on PID 51: data = [reserved 0][serviceId 0][mode]. Get omits
# the mode byte; response = [returncode][serviceId][isEnabled]. (thelsing/knx)
SEC_MODE_SERVICE = 0x00

# KNXnet/IP Parameter Object (OT 11) security PIDs. PID_ADDITIONAL_IAS (53) is
# the tunnel users — one 2-byte element per tunnel slot — and comes from knxip,
# since knxiface reads the same property as interface config.
PID_BACKBONE_KEY = 91            # IP-secure routing (backbone) key; NOT written
                                 # yet — SecureConfig mints and stores one, but
                                 # nothing provisions it (routing is unsupported)
PID_DEVICE_AUTH_CODE = 92        # device authentication code
PID_PASSWORD_HASHES = 93         # tunnel-user password hashes (per additional IA)
PID_SECURED_SVC_FAMILIES = 94
PID_TUNNELLING_USERS = 97


# --- key material ---------------------------------------------------------
def gen_key():
    """A fresh random 16-byte AES-128 key (tool key, backbone key, group key)."""
    return os.urandom(16)


# --- extended-service APDU builders (payload after the 2 APCI octets) ------
def _addr(obj_type, pid, inst=1):
    """obj_type(2) | 12-bit instance | 12-bit PID = 5 bytes. Object addressed by
    TYPE, no index scan (pinned vs the ETS pcap: OT 17 PID 51 -> 00110010 33)."""
    return obj_type.to_bytes(2, 'big') + (((inst & 0xFFF) << 12)
                                          | (pid & 0xFFF)).to_bytes(3, 'big')


def funcprop_ext(obj_type, pid, data=b'', inst=1):
    """A_FunctionPropertyExtCommand payload."""
    return _addr(obj_type, pid, inst) + data


def propext_read(obj_type, pid, inst=1, count=1, start=1):
    """A_PropertyExtValueRead payload: addressing + count(1B) + start(2B).
    The EXTENDED service uses an 8-bit element count + 16-bit start index (the
    non-extended service's 4b|12b packing is wrong here — pinned vs the ETS6
    capture: OT 17 PID 56 write = 0011 001038 01 0001 <key>)."""
    return (_addr(obj_type, pid, inst) + bytes([count & 0xFF])
            + (start & 0xFFFF).to_bytes(2, 'big'))


def propext_write(obj_type, pid, data, inst=1, count=1, start=1):
    """A_PropertyExtValueWrite payload: addressing + count|start + data."""
    return propext_read(obj_type, pid, inst, count, start) + data


# --- high-level ops (over a connected Conn; secured if conn.sec is set) ----
def read_security_mode(conn):
    """Read the device's security mode (OT 17 PID 51 FunctionProperty). Get data
    = [reserved 0][serviceId 0]; response after the echoed addressing =
    [returncode][serviceId][isEnabled]. Returns True/False, or None if unclear."""
    d = conn.request(A_FUNC_PROP_EXT_READ,
                     funcprop_ext(OT_SECURITY, PID_SEC_MODE,
                                  bytes([0x00, SEC_MODE_SERVICE])),
                     A_FUNC_PROP_EXT_RESP)
    tail = d[5:]                                   # strip the 5-byte addressing
    return bool(tail[2]) if len(tail) >= 3 else None


def set_security_mode(conn, on, log=print):
    """Enable/disable security mode (OT 17 PID 51 FunctionProperty). Set data =
    [reserved 0][serviceId 0][mode]."""
    conn.request(A_FUNC_PROP_EXT_CMD,
                 funcprop_ext(OT_SECURITY, PID_SEC_MODE,
                              bytes([0x00, SEC_MODE_SERVICE, 1 if on else 0])),
                 A_FUNC_PROP_EXT_RESP)
    log(f'security mode -> {"ON" if on else "OFF"}')


def read_tool_key(conn):
    """Read back the active tool key (OT 17 PID 56, 16 bytes). PID 56 is the
    pcap-pinned value — 60 is the zone key and was the earlier wrong guess."""
    d = conn.request(A_PROPEXT_READ, propext_read(OT_SECURITY, PID_TOOL_KEY),
                     A_PROPEXT_RESP)
    # addr(5)+count(1)+start(2)+data; count=0 = read refused (write-only once
    # secured), the single data byte then is a return code — not a key.
    if len(d) < 9 or d[5] == 0:
        return b''
    return d[8:]


def write_tool_key(conn, key, log=print, rekey=False):
    """Write the tool key (OT 17 PID 56, 16 bytes). After this write the device's
    tool key is `key`, so later Data-Secure management must use the new key; a
    factory reset restores the FDSK.

    Over Data Secure the device sends its WriteResponse wrapped with the NEW key
    (verified live on the 732 + in the ETS pcap). Pass rekey=True to switch the
    session key between our request and its response, so the response unwraps and
    is consumed cleanly and every following op uses the new key."""
    assert len(key) == 16
    conn.request(A_PROPEXT_WRITE, propext_write(OT_SECURITY, PID_TOOL_KEY, key),
                 A_PROPEXT_WRITE_RESP, rekey=key if rekey else None)
    log('wrote tool key (OT 17 PID 56)')


# --- secured group communication -------------------------------------------
# Decoded from captures/knx-cheops-secure.pcap (ETS6 commissioning + downloading
# the Theben Cheops S). ETS writes three tables in ONE OT 17 load transaction,
# after the last memory write and before the objects are marked LoadCompleted.
#
# The per-GA setting ETS shows (Auto / force On / force Off) is PLANNING state
# and never reaches a device: the whole security footprint on the wire is
# concrete, an object is secured or it is not. Auto means "secured iff every
# device on this group address is a secure product and is being commissioned",
# which only the project can evaluate. So the tri-state lives in project.json
# and resolve_ga() turns it into the per-device tables here.

GO_SECURED = 0x03                # GO_SEC_FLAGS byte for a secured group object
GO_PLAIN = 0x00

# Elements per GO_SEC_FLAGS write. ETS uses 33 (observed: start 1, 34, 67, then
# the 18 that remain of 117), which is exactly what fits the 56-octet budget it
# holds every secured frame to: 56 - 13 Data Secure - 2 APCI - 5 addressing
# - 1 count - 2 start = 33.
GO_FLAGS_CHUNK = 33


def device_secured(project, dev):
    """Is `dev` a device this project secures? True when the product supports
    KNX Secure AND the project either has commissioned it (a tool key) or is
    about to (the Security page switch). Intent counts, not just the accomplished
    fact — otherwise a group address shared by two devices could never resolve to
    secured, since whichever you commission first would still see the other as
    plain."""
    sec = dev.sec or {}
    if not dev.product:                  # imported without its program
        return False
    return bool(project.program(dev).secure
                and (sec.get('tool_key') or sec.get('commissioning')))


def ga_users(project, ga):
    """Every device that links `ga`."""
    return [d for d in project.devices
            if any(ga in gs for gs in (d.links or {}).values())]


def resolve_ga(project, ga):
    """A group address's EFFECTIVE security: True (secured) or False (plain).

    'on'/'off' are the user's override; 'auto' (the default) is secured iff the
    GA has users and every one of them is secured. A single non-secure product
    on the GA keeps it plain — that is the whole point of auto, and why forcing
    'on' needs the check in force_on_conflicts()."""
    mode = (project.gas.get(ga) or {}).get('security', 'auto')
    if mode == 'on':
        return True
    if mode == 'off':
        return False
    users = ga_users(project, ga)
    return bool(users) and all(device_secured(project, d) for d in users)


def resolve_all(project):
    """{ga: bool} for every group address, in one pass. resolve_ga() rescans
    every device per GA, which is fine for a call or two and not for painting a
    list of hundreds."""
    users = project.ga_users_map()
    ok = {id(d): device_secured(project, d) for d in project.devices}
    out = {}
    for ga, g in project.gas.items():
        mode = g.get('security', 'auto')
        if mode in ('on', 'off'):
            out[ga] = mode == 'on'
        else:
            us = users.get(ga, [])
            out[ga] = bool(us) and all(ok[id(d)] for d in us)
    return out


def download_impact(project, before, after):
    """{device: [ga]} for every device whose group communication changed between
    two resolve_all() snapshots.

    Commissioning a device changes NOTHING about how it talks — it secures
    management only. The group keys and per-object flags reach a device in its
    next download, so a security change leaves the project and the bus
    disagreeing until then. This is what lets the UI say which downloads are now
    owed: for the device that changed, and for every other device sharing an
    affected address."""
    changed = {ga for ga in set(before) | set(after)
               if before.get(ga) != after.get(ga)}
    out = {}
    for d in project.devices:
        gas = {g for gs in (d.links or {}).values() for g in gs} & changed
        if gas:
            out[d] = sorted(gas)
    return out


def force_on_conflicts(project, ga):
    """The devices on `ga` that cannot do secure group communication. Forcing a
    GA on while one of these is linked to it silently stops that device working,
    so the UI refuses it — the one case auto handles for you and a manual
    override does not."""
    return [d for d in ga_users(project, ga) if not device_secured(project, d)]


def group_key(project, ga, mint=True):
    """The 16-byte key for `ga`, minted and stored on first use. Returns None
    when there is none and `mint` is False. Keys live in project.json beside the
    tool keys — losing them means every device on the GA must be re-downloaded."""
    g = project.gas.get(ga)
    if g is None:
        return None
    if not g.get('key'):
        if not mint:
            return None
        g['key'] = gen_key().hex()
    return bytes.fromhex(g['key'])


def ensure_group_keys(project):
    """Mint a key for every GA that currently resolves to secured. Returns the
    GAs that got a NEW one. The caller must save the project before the
    download (run_mgmt does, for writes) — a key that was written to a device
    but not saved is unrecoverable."""
    minted = []
    secured = resolve_all(project)
    for ga in sorted(project.gas):
        if secured.get(ga) and not project.gas[ga].get('key'):
            group_key(project, ga)
            minted.append(ga)
    return minted


def device_group_security(project, dev):
    """The OT 17 group-comms tables for `dev`, or None when it is not secured.

    Returns {'keys': [(address-table index, 16-byte key)], 'flags': bytes,
    'gas': [secured ga]}. `flags` has one byte per group-object table entry,
    1-based by com-object number — the same numbering the com-object table uses,
    so element N describes object N."""
    if not device_secured(project, dev):
        return None
    prog = project.program(dev)
    corefs = project.visible_corefs(dev)
    # the address table the download builds: sorted, 1-based (device_images_b)
    gas = sorted({g for cid in corefs for g in dev.links.get(cid, [])})
    secured = [g for g in gas if resolve_ga(project, g)]
    if 0 < prog.max_sec_grp_keys < len(secured):
        raise RuntimeError(f'{len(secured)} secured group addresses, but the '
                           f'product holds {prog.max_sec_grp_keys} keys')

    keys = []
    for g in secured:
        k = group_key(project, g, mint=False)
        if k is None:
            raise RuntimeError(f'no group key for {ga_str(g)} — save the '
                               'project first')
        keys.append((gas.index(g) + 1, k))

    n = max((co.number for co in prog.comobjs.values()), default=0)
    flags = bytearray(n)                      # element i-1 describes object i
    for num, glist in project_links(project, dev).items():
        on = [g for g in glist if g in secured]
        # A group object is secured or it is not — there is one flag byte for
        # it, not one per link. So an object carrying both a secured and a plain
        # group address has no correct encoding: mark it secured and the plain
        # partners stop understanding it, mark it plain and the secured ones do.
        # Auto never produces this (it resolves per GA over all participants);
        # only a forced override can. Refuse rather than pick.
        if on and len(on) != len(glist):
            plain = [g for g in glist if g not in secured]
            raise RuntimeError(
                f'group object {num} links both secured '
                f'({", ".join(ga_str(g) for g in on)}) and plain '
                f'({", ".join(ga_str(g) for g in plain)}) group addresses — '
                'clear the forced security setting on those addresses')
        if on and 1 <= num <= n:
            flags[num - 1] = GO_SECURED
    return {'keys': keys, 'flags': bytes(flags), 'gas': secured}


def device_fingerprint(project, dev):
    """Hash of everything a Program writes into `dev`: settings, links, IP
    settings and the group-security tables. Stored in info.programmed_fp on
    a successful download; a later mismatch means project and device
    disagree. The IA is not part of it — it is written by IA assignment
    and tracked as info.ia_written. A group-security error (no key minted
    yet, mixed object) hashes as its message: a download is owed either way."""
    try:
        g = device_group_security(project, dev)
        gsec = g and {'gas': g['gas'], 'flags': g['flags'].hex(),
                      'keys': [[i, k.hex()] for i, k in g['keys']]}
    except RuntimeError as e:
        gsec = f'error: {e}'
    d = dev.to_dict()
    src = {k: d.get(k) for k in ('product', 'variant', 'values', 'links',
                                 'iface')}
    src['gsec'] = gsec
    return hashlib.sha1(json.dumps(src, sort_keys=True).encode()).hexdigest()


def unload_group_security(conn, log=print):
    """Unload the security object (OT 17 load state control, LoadEvent 4) so the
    key and flag tables start empty.

    Necessary, not cosmetic: the tables are written entry by entry, so dropping
    from two secured group addresses to one would otherwise leave entry 2 behind
    — a live key bound to an address-table index that now means a different
    address. ETS does exactly this, in the unload phase alongside the other
    objects (captures/knx-cheops-secure.pcap, `SEC/LOAD_CTRL 04` right after the
    five `objN/5 04` writes), and the rest of that capture still decodes under
    the new tool key — so the unload does NOT discard the tool key or the
    security mode, which is the one thing worth being sure of before copying it.
    """
    conn.request(A_FUNC_PROP_EXT_CMD,
                 funcprop_ext(OT_SECURITY, PID_LOAD_STATE_CTRL,
                              bytes([LOAD_UNLOAD] + [0] * 9)),
                 A_FUNC_PROP_EXT_RESP)
    log('security object unloaded (group keys + flags cleared)')


def write_group_security(conn, tables, log=print):
    """Write the secured-group-communication tables in one OT 17 load
    transaction, the way ETS does (captures/knx-cheops-secure.pcap).

    The security IA table gets element 0 = 0: it tracks the sending sequence of
    SECURED SENDERS for replay protection, and ETS left it empty on a freshly
    commissioned device — the device fills it as it meets peers. We replicate
    that rather than invent entries.

    The key table is written sequentially from element 1, each entry carrying its
    own 2-byte address-table index. The capture cannot distinguish that from a
    table indexed BY address-table position, because there every secured GA was
    also contiguous — but an array property's elements are 1..N with no holes,
    and an entry would not carry an index if its position already were one."""
    keys, flags = tables['keys'], tables['flags']
    conn.request(A_FUNC_PROP_EXT_CMD,
                 funcprop_ext(OT_SECURITY, PID_LOAD_STATE_CTRL,
                              bytes([LOAD_LOAD] + [0] * 9)),
                 A_FUNC_PROP_EXT_RESP)
    conn.request(A_PROPEXT_WRITE,
                 propext_write(OT_SECURITY, PID_SEC_IA_TABLE, b'\0\0', start=0),
                 A_PROPEXT_WRITE_RESP)
    for i, (idx, key) in enumerate(keys, start=1):
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_SECURITY, PID_GRP_KEY_TABLE,
                                   idx.to_bytes(2, 'big') + key, start=i),
                     A_PROPEXT_WRITE_RESP)
    for off in range(0, len(flags), GO_FLAGS_CHUNK):
        chunk = flags[off:off + GO_FLAGS_CHUNK]
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_SECURITY, PID_GO_SECURITY_FLAGS, chunk,
                                   count=len(chunk), start=off + 1),
                     A_PROPEXT_WRITE_RESP)
    conn.request(A_FUNC_PROP_EXT_CMD,
                 funcprop_ext(OT_SECURITY, PID_LOAD_STATE_CTRL,
                              bytes([LOAD_COMPLETED] + [0] * 9)),
                 A_FUNC_PROP_EXT_RESP)
    log(f'group security: {len(keys)} key(s), '
        f'{sum(1 for b in flags if b)} of {len(flags)} objects secured')


class SecureConfig:
    """The security material to provision onto a device. Generated locally;
    exported to a keyring later so the config is reusable."""

    def __init__(self, *, tool_key=None, backbone_key=None, auth_code='',
                 mgmt_password='', tunnel_passwords=None, tunnel_ias=None,
                 secured_families=None):
        self.tool_key = tool_key or gen_key()
        self.backbone_key = backbone_key or gen_key()
        self.auth_code = auth_code
        self.mgmt_password = mgmt_password               # IP-secure user 1
        self.tunnel_passwords = tunnel_passwords or []   # per tunnel slot
        self.tunnel_ias = tunnel_ias or []               # int IA per tunnel slot
        # service-family IDs to secure (3=core, 4=tunnelling, 5=routing)
        self.secured_families = secured_families or []

    def to_dict(self):
        return {'tool_key': self.tool_key.hex(),
                'backbone_key': self.backbone_key.hex(),
                'auth_code': self.auth_code,
                'mgmt_password': self.mgmt_password,
                'tunnel_passwords': list(self.tunnel_passwords),
                'tunnel_ias': list(self.tunnel_ias),
                'secured_families': list(self.secured_families)}

    @classmethod
    def from_dict(cls, d):
        return cls(
            tool_key=bytes.fromhex(d['tool_key']) if d.get('tool_key') else None,
            backbone_key=(bytes.fromhex(d['backbone_key'])
                          if d.get('backbone_key') else None),
            auth_code=d.get('auth_code', ''),
            mgmt_password=d.get('mgmt_password', ''),
            tunnel_passwords=d.get('tunnel_passwords', []),
            tunnel_ias=d.get('tunnel_ias', []),
            secured_families=d.get('secured_families', []))


def commission(conn, cfg, log=print, enable=True, commit=True):
    """Provision `cfg` onto the device over `conn` (a connected Conn). DESTRUCTIVE
    — back up / be ready to factory-reset (which restores the FDSK tool key and
    turns security off).

    Order (KNX model): write all key material while it is still writable, then
    turn security mode ON last. On a not-yet-secured device (mode OFF) `conn` is
    plaintext (conn.sec=None) — a mode-OFF device is managed plaintext and ignores
    Data Secure; to reconfigure an already-secured device pass a Data-Secure conn
    under its current tool key. `commit=False` skips the NVM commit — the caller
    does it, e.g. plaintext commission commits over Data Secure once mode is ON.

    WORKS FOR ANY SECURE DEVICE, not just interfaces. Everything between the tool
    key and the mode switch is OT 11 (KNXnet/IP Parameter Object) material, and
    write_credentials() skips each block whose SecureConfig field is empty. So a
    SecureConfig carrying only a tool_key — the plain sensor/actuator case —
    reduces this to the three generic writes: tool key (OT 17 PID 56), security
    mode ON (OT 17 PID 51), commit OT 17 (PID 5, LoadEvent 1 then 2).

    Wire encoding pinned to a real ETS6 secure commission
    (captures/knx-commission-secure.pcap) and validated live on the 732."""
    mode = read_security_mode(conn)
    log(f'current security mode: {"ON" if mode else "OFF" if mode is not None else "?"}')

    # 1) tool key (OT 17 PID 56) — new project key replacing the FDSK. ETS runs
    #    the whole commission over Data Secure under the FDSK, so once the new key
    #    lands the device expects it: switch the session key mid-flow (rekey). On
    #    a plaintext conn (mode OFF / offline test) there is nothing to switch.
    secured = conn.sec is not None
    write_tool_key(conn, cfg.tool_key, log, rekey=secured)
    if secured:
        log('switched Data-Secure session to the new tool key')

    # 2) device auth code + tunnel-user passwords + secured families
    write_credentials(conn, cfg, log)

    # 3) security mode ON — LAST. After this the device requires the new tool key
    #    for management and secures group comms.
    if enable:
        set_security_mode(conn, True, log)

    # 4) COMMIT the security object to NVM (tool key + mode + IA table live on
    #    OT 17). Without this the writes are runtime-only and a power cycle
    #    reverts them — proven live on the 732. On a plaintext commission the
    #    caller does this over Data Secure once mode is ON (mode-OFF plaintext is
    #    gone), so it can be skipped here.
    if commit:
        commit_object(conn, OT_SECURITY, log)
    log('commissioning done — verify with a Data-Secure read under the new key')


def write_credentials(conn, cfg, log=print):
    """Write the tunnel users (additional IAs), device auth code, tunnel-user
    passwords and secured families (all OT 11). Shared by commission() and
    run_update(); it never touches the tool key or security mode, so it is safe
    to re-run over a Data-Secure conn under the current tool key."""
    # additional individual addresses (OT 11 PID 53) = the tunnel users. A tunnel
    # user must exist before its password can be set, so write these FIRST — one
    # 2-byte IA per slot, all in one write (start=1), as ETS does (KNXIP/53 n=N).
    ias = [ia for ia in cfg.tunnel_ias if ia]
    if ias:
        payload = b''.join(struct.pack('!H', ia) for ia in ias)
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_KNXIP, PID_ADDITIONAL_IAS, payload,
                                   count=len(ias), start=1),
                     A_PROPEXT_WRITE_RESP)
        log(f'wrote {len(ias)} tunnel address(es) (OT 11 PID 53)')

    # device authentication code (OT 11 PID 92) — the session auth key
    if cfg.auth_code:
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_KNXIP, PID_DEVICE_AUTH_CODE,
                                   device_key(cfg.auth_code)),
                     A_PROPEXT_WRITE_RESP)
        log('wrote device authentication code')

    # IP-secure user passwords (OT 11 PID 93, hash per user id). User 1 is the
    # MANAGEMENT user (ETS's commissioning password) — it may always tunnel and
    # is never listed in PID 97. Tunnel slot i (1-based) belongs to user i+1;
    # without a PID 97 (user -> slot) entry a secured connect for user >= 2 is
    # refused with 0x24 NO_MORE_CONNECTIONS (pinned from calimero-server, the
    # reference KNXnet/IP Secure server; verified live on the 732).
    users = [(1, cfg.mgmt_password)] + [
        (slot + 1, pw) for slot, pw in enumerate(cfg.tunnel_passwords, start=1)]
    users = [(uid, pw) for uid, pw in users if pw]
    if users:
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_KNXIP, PID_PASSWORD_HASHES,
                                   max(uid for uid, _ in users)
                                   .to_bytes(2, 'big'), start=0),
                     A_PROPEXT_WRITE_RESP)
    for uid, pw in users:
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_KNXIP, PID_PASSWORD_HASHES,
                                   user_key(pw), start=uid),
                     A_PROPEXT_WRITE_RESP)
        log(f'wrote user {uid} password hash'
            + (' (management)' if uid == 1 else f' (tunnel {uid - 1})'))

    # user -> tunnel-slot mapping (OT 11 PID 97): element 0 = entry count, then
    # one 2-byte [user id, slot index] entry per tunnel user, sorted by user
    # (both 1-based; format pinned from calimero-server).
    entries = [(uid, uid - 1) for uid, _ in users if uid > 1]
    if entries:
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_KNXIP, PID_TUNNELLING_USERS,
                                   len(entries).to_bytes(2, 'big'), start=0),
                     A_PROPEXT_WRITE_RESP)
        conn.request(A_PROPEXT_WRITE,
                     propext_write(OT_KNXIP, PID_TUNNELLING_USERS,
                                   bytes(b for e in entries for b in e),
                                   count=len(entries), start=1),
                     A_PROPEXT_WRITE_RESP)
        log(f'wrote {len(entries)} tunnel-user mapping(s) (OT 11 PID 97)')

    # secure tunnelling: the secured KNXnet/IP service families (OT 11 PID 94)
    if cfg.secured_families:
        set_secure_tunnelling(conn, True, cfg.secured_families, log)


# ETS exposes two independent switches; they map to different objects, so Baccata
# keeps them separate too:
#   secure commissioning = KNX Data Secure for management + group comms
#       -> security mode (OT 17 PID 51) + tool key.  set_security_mode / commission
#   secure tunnelling    = KNXnet/IP tunnels must use IP Secure
#       -> secured service families (OT 11 PID 94).   set_secure_tunnelling
def set_secure_tunnelling(conn, on, families=(3, 4, 5), log=print):
    """Toggle secure tunnelling — the secured KNXnet/IP service families (OT 11
    PID 94), ETS's 'secure tunnelling' switch. One FunctionProperty per family;
    data = [reserved 0][serviceId 0][familyId][enable 0/1] (pinned vs the ETS6
    capture). OFF lets plain (non-IP-secure) tunnels connect again. Independent of
    the Data-Secure security mode (secure commissioning)."""
    for fam in families:
        conn.request(A_FUNC_PROP_EXT_CMD,
                     funcprop_ext(OT_KNXIP, PID_SECURED_SVC_FAMILIES,
                                  bytes([0x00, 0x00, fam, 1 if on else 0])),
                     A_FUNC_PROP_EXT_RESP)
        log(f'secure tunnelling family {fam} -> {"ON" if on else "OFF"}')


def commit_object(conn, obj_type, log=print):
    """Commit an interface object's current RAM state to non-volatile memory via
    its load-state machine (PID 5): LoadEvent 1 (Load/StartLoading) then 2
    (LoadCompleted). WITHOUT this the property writes are runtime-only and revert
    on the next power cycle — proven live on the 732, and ETS wraps its security
    writes in exactly this transaction (OT 17 PID 5, via FunctionPropertyExt).
    Returns the load state read back after (3 = Loaded on success)."""
    for event in (LOAD_LOAD, LOAD_COMPLETED):
        conn.request(A_FUNC_PROP_EXT_CMD,
                     funcprop_ext(obj_type, PID_LOAD_STATE_CTRL,
                                  bytes([event] + [0] * 9)),
                     A_FUNC_PROP_EXT_RESP)
    state = read_load_state(conn, obj_type)
    log(f'committed OT {obj_type} (load state {state})')
    return state


def read_load_state(conn, obj_type):
    """Read an object's load state (OT PID 5 via PropertyExt). Returns the state
    byte (0 Unloaded, 1 Loaded, 2 Loading, 3 Loaded, …), or None when the device
    does not answer — it is advisory, logged after a commit, never a gate."""
    try:
        d = conn.request(A_PROPEXT_READ,
                         propext_read(obj_type, PID_LOAD_STATE_CTRL),
                         A_PROPEXT_RESP)
    except (TimeoutError, ValueError, OSError):
        return None
    return d[8] if len(d) > 8 else None


def decommission(conn, fdsk=None, families=(), log=print):
    """Turn secure commissioning OFF and, if `fdsk` is given, restore the FDSK
    tool key (back to factory security material). Like ETS, this also turns secure
    tunnelling OFF (you can't have secured tunnels without commissioning). `conn`
    must currently manage the device (Data-Secure under the current tool key).
    Order matters — restore the FDSK LAST, since changing the tool key invalidates
    the session key.

    `families` defaults to NONE. Secured service families live on OT 11, which
    only a KNXnet/IP interface has — blind-writing them to a plain secure device
    is three FunctionProperty commands to an object that isn't there. The
    interface caller passes (3, 4, 5) explicitly.

    The group keys + GO flags go FIRST, while the tool key still opens OT 17.
    Mode OFF does not switch them off — verified live on the Cheops: mode OFF,
    FDSK restored, and it kept sending 2/0/0 as S-A_Data. And OT 17 refuses
    plaintext (0xFC AccessDenied, mode OFF or not), so the later plain download
    cannot clean up either. ETS wipes the whole device instead (RestartMaster
    erase 7, knx-cheops-secure2.pcap); this is the surgical version."""
    # secure tunnelling OFF first (OT 11; the tool key is unchanged so the
    # Data-Secure session keeps working)
    if families:
        set_secure_tunnelling(conn, False, families, log)
    unload_group_security(conn, log)
    write_group_security(conn, {'keys': [], 'flags': b''}, log)
    # then drop the security mode (still authenticated with the current key)
    set_security_mode(conn, False, log)
    if fdsk is not None:
        write_tool_key(conn, fdsk, log, rekey=conn.sec is not None)
        log('restored FDSK tool key')
    # Commit OT 17 so mode-OFF + FDSK survive a power cycle (else runtime-only).
    commit_object(conn, OT_SECURITY, log)
    log('security mode OFF' + ('' if fdsk is not None
                               else ' (tool key unchanged — factory-reset to '
                               'restore the FDSK)'))


# --- orchestration over a live Mgmt (used by the editor + bench) ----------
def _conn(m, ia, tool_key=None, timeout=10.0, co=False):
    """A Conn to `ia`: Data-Secure under `tool_key` if given, else plaintext.
    CONNECTIONLESS by default, like ETS: the 732 ignores connection-oriented
    management to its own IA over its own tunnel (no T_ACK, wedges the tunnel),
    while the same ops answer connectionless within ms (verified live + in the ETS
    pcap), and the pcap shows ETS commissioning connectionless throughout.

    `co=True` is the escape hatch for a device on the far side of the bus, where
    connection-oriented management is the norm — untested, since the only
    hardware-verified secure device so far is the interface itself."""
    sec = DataSecure(tool_key, src=m.bus.ia) if tool_key else None
    return Conn(m, ia, timeout=timeout, sec=sec, co=co)


def warm_conn(m, ia, tool_key=None, *, timeout=10.0, tries=4, co=False,
              log=None):
    """Build a Conn and prove it works with a cheap secured read before the caller
    does real work. The device can ignore the first SyncRequests after a fresh
    tunnel (ETS hits the same and retries) — so retry sync + first read with a
    FRESH Data-Secure session each time (fresh monotonic seq, reset replay
    baseline), at a short probe timeout. Returns (conn, mode). Reads/writes are
    idempotent so the retry is safe; do NOT use this to retry a mid-flow rekey."""
    last = None
    probe = min(timeout, 2.0)     # fail fast — the outer loop retries with a fresh session
    for _ in range(tries):
        c = _conn(m, ia, tool_key, probe, co=co)
        try:
            c.sync()                          # Data Secure seq handshake (no-op if plaintext)
            mode = read_security_mode(c)
            c.timeout = timeout               # warmed up — full patience for real work
            return c, mode
        except (TimeoutError, ValueError, OSError) as e:
            last = e
            if log:
                log(f'  (warm-up retry: {type(e).__name__})')
            c.disconnect()
    raise last or TimeoutError(f'no response from {ia:#06x}')


def read_state(m, ia, *, fdsk=None, tool_key=None, timeout=10.0, co=False,
               log=print):
    """Read security mode + tool key. A READ must not trust the project: it
    is the tool for finding out whether the device and the project agree. So
    it tries every way in — plaintext (a factory device, or one that never
    took the commission), the stored tool key, then the FDSK — and reports
    which one answered. Returns {'mode', 'tool_key', 'is_fdsk', 'via'}."""
    ways = [('plaintext', None), ('tool key', tool_key), ('FDSK', fdsk)]
    seen, last = set(), None
    for via, key in ways:
        if key in seen or (key is None and via != 'plaintext'):
            continue
        seen.add(key)
        try:
            c, mode = warm_conn(m, ia, key, timeout=timeout, tries=2, co=co,
                                log=log)
            break
        except (TimeoutError, ValueError, OSError) as e:
            last = e
            log(f'no answer via {via}')
    else:
        raise last or TimeoutError(f'no response from {ia:#06x}')
    log(f'answers via {via}')
    try:
        log(f'security mode: {"ON" if mode else "OFF" if mode is not None else "?"}')
        tk = b''
        try:
            tk = read_tool_key(c)
        except Exception as e:                 # often write-only once secured
            log(f'tool key not readable ({type(e).__name__})')
        is_fdsk = (tk == fdsk) if (fdsk and tk) else None
        if tk:
            log(f'tool key: {tk.hex()}'
                + ('  (= FDSK / factory)' if is_fdsk
                   else '  (custom)' if is_fdsk is False else ''))
        return {'mode': mode, 'tool_key': tk, 'is_fdsk': is_fdsk,
                'via': via}
    finally:
        c.disconnect()


def run_commission(m, ia, cfg, fdsk, *, timeout=10.0, co=False, log=print,
                   verify=True, resume=False):
    """Commission a not-yet-secured device (security mode OFF), installing
    cfg.tool_key + the credentials and turning security ON.

    A mode-OFF device is managed in PLAINTEXT and does NOT answer Data-Secure
    funcprop reads (verified live on the 732). The caller picks the path by what
    it passes as `fdsk`: None commissions plaintext (mode OFF), a key opens a
    Data-Secure session under it (already-secured device, or a factory device ETS
    has touched), and commission() then switches to cfg.tool_key mid-flow.

    `resume=True` retries a commission that died PART-WAY. The tool-key write is
    the point of no return: if it landed, the device now answers only under
    cfg.tool_key and reaching it with the FDSK is hopeless; if it did not, only
    the FDSK works. Which of the two happened is not knowable from the failure,
    so try cfg.tool_key first and fall back to the FDSK — commission() is a
    re-runnable sequence of idempotent writes either way."""
    keys = [cfg.tool_key, fdsk] if resume else [fdsk]
    c = None
    for i, k in enumerate(keys):
        try:
            c, _ = warm_conn(m, ia, k, timeout=timeout, co=co, log=log)
            if resume:
                log(f'resuming under the {"new tool key" if i == 0 else "FDSK"}')
            break
        except (TimeoutError, ValueError, OSError):
            if i == len(keys) - 1:
                raise
            log('  (no answer under the new tool key — trying the FDSK)')
    try:
        commission(c, cfg, log=log, enable=True)
    finally:
        c.disconnect()
    if verify:
        log('verifying a Data-Secure read under the new tool key…')
        c2, mode = warm_conn(m, ia, cfg.tool_key, timeout=timeout, co=co,
                             log=log)
        c2.disconnect()
        log(f'verify: secured security mode = '
            f'{"ON" if mode else "OFF" if mode is not None else "?"}')


def run_update(m, ia, tool_key, cfg, *, set_tunnelling=None, families=(3, 4, 5),
               timeout=10.0, co=False, log=print):
    """Adjust an already-secured device in ONE management session (Data-Secure
    under its current tool_key): optionally toggle secure tunnelling
    (`set_tunnelling` True/False; None leaves the families untouched), then
    rotate the auth code / tunnel passwords. The tool key and security mode are
    left untouched; OT 11 persists without a load-state commit (no OT 11 load
    control appears in the ETS capture).

    Both run on a SINGLE Conn. The 732 will not reliably carry a second
    management Conn on the same IP-secure tunnel — opening one per op (the old
    set-tunnelling + change-credentials pair) reproducibly timed out on the
    second, which is why Apply failed when changing a password on a
    fully-secured device. Verified live: the two ops on one Conn succeed where
    two Conns fail. That is why there is no separate run_set_secure_tunnelling:
    pass set_tunnelling here instead of opening a second session."""
    c, _ = warm_conn(m, ia, tool_key, timeout=timeout, co=co, log=log)
    try:
        if set_tunnelling is not None:
            set_secure_tunnelling(c, set_tunnelling, families, log=log)
        write_credentials(c, cfg, log=log)
        log('credentials updated — reconnect the tunnel with the new password(s)')
    finally:
        c.disconnect()


def run_decommission(m, ia, tool_key, *, fdsk=None, families=(), timeout=10.0,
                     co=False, log=print):
    """Disable secure commissioning (Data-Secure security mode) on a device;
    restore the FDSK if given. `families` (interfaces only) are switched off
    first; with none given, secure tunnelling is left untouched.

    A device that already answers in PLAINTEXT with mode OFF is not secured,
    whatever the project remembers (a commission that never took, a factory
    reset) — then there is nothing to write and the tool key would only fail:
    report it and let the caller drop the stale key."""
    try:
        c, mode = warm_conn(m, ia, None, timeout=timeout, tries=1, co=co)
    except (TimeoutError, ValueError, OSError):
        mode = None                          # no plaintext answer: secured
    else:
        c.disconnect()
        if mode is False:
            log('security mode already OFF — the project tool key never '
                'reached this device, nothing to write')
            return
    c, _ = warm_conn(m, ia, tool_key, timeout=timeout, co=co, log=log)
    try:
        decommission(c, fdsk=fdsk, families=families, log=log)
    finally:
        c.disconnect()

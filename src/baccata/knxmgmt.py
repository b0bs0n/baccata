"""KNX device management: connection-oriented transport + memory-image builders.

The pure builders turn a parsed Program plus a device's parameter values / GA
links into the byte images ETS would write to the address, association and
parameter segments (big-endian MSB-first packing, pinned by tests against the
shipped segment data). The Mgmt/Conn classes run point-to-point device
management (T_Connect, memory/property/descriptor services) over any TunnelClient.
"""
import queue, struct, time
from dataclasses import dataclass, field

from .knxip import (cemi_ldata, dpt9_value, dpt9_word, ga_str, ia_int, ia_str,
                   A_PROP_READ, A_PROP_RESP, A_PROP_WRITE, A_RESTART)
from .knxdatasec import DataSecure, S_A_DATA, parse_sync_response
from .knxprod import Block, Choose, CRef, test_matches

# TPCI octets
T_CONNECT, T_DISCONNECT = 0x80, 0x81
T_ACK, T_DATA = 0xC2, 0x40          # | (seq << 2)

# APCI (10-bit). The property and restart services are shared with knxiface /
# knxsecure and come from knxip; these are management-only. The extended
# PROPERTY services live in knxip too — only knxsecure speaks them.
A_IND_ADDR_READ, A_IND_ADDR_RESP, A_IND_ADDR_WRITE = 0x100, 0x140, 0x0C0
# by KNX serial number (03/03/07 §3.5.7): broadcast, no programming mode
A_IND_ADDR_SN_READ, A_IND_ADDR_SN_RESP, A_IND_ADDR_SN_WRITE = 0x3DC, 0x3DD, 0x3DE
A_DESC_READ, A_DESC_RESP = 0x300, 0x340
A_MEM_READ, A_MEM_RESP, A_MEM_WRITE = 0x200, 0x240, 0x280
A_AUTH_REQ, A_AUTH_RESP = 0x3D1, 0x3D2
A_RESTART_MASTER, A_RESTART_RESP = 0x381, 0x3A1
# extended memory services (System B): 24-bit address, up to 250 B
A_MEMX_WRITE, A_MEMX_WRITE_RESP = 0x1FB, 0x1FC
A_MEMX_READ, A_MEMX_READ_RESP = 0x1FD, 0x1FE


# ---- bit packing (MSB-first, multi-byte) ---------------------------------

def get_bits(buf, byte_off, bit_off, width):
    """Read a big-endian bit field: `width` bits starting `bit_off` from the
    MSB of buf[byte_off]."""
    pos = byte_off * 8 + bit_off
    v = 0
    for i in range(width):
        p = pos + i
        v = (v << 1) | ((buf[p >> 3] >> (7 - (p & 7))) & 1)
    return v


def put_bits(buf, byte_off, bit_off, width, value):
    """Write `value` into a big-endian bit field (see get_bits)."""
    pos = byte_off * 8 + bit_off
    value &= (1 << width) - 1
    for i in range(width):
        bit = (value >> (width - 1 - i)) & 1
        p = pos + i
        bi, mask = p >> 3, 1 << (7 - (p & 7))
        buf[bi] = (buf[bi] | mask) if bit else (buf[bi] & ~mask)


# ---- parameter images ----------------------------------------------------

def param_images(prog, param_values=None, active=None, base=None, log=None):
    """Build {segment_id: bytearray}, overlaying memory-mapped int/enum params
    with their effective value.

    active: iterable of parameter ids to write. REQUIRED for a correct image —
      parameters share memory through Unions, so writing inactive members
      clobbers the active one. When None, every mapped param is written (only
      safe when no unions overlap; kept for tests).
    base: {segment_id: bytes} initial images (e.g. the device's current memory);
      defaults to the knxprod segment seed.
    log: called for each ACTIVE parameter that maps to memory but could not be
      encoded. Those keep the seed byte, so the device silently gets a value
      nobody chose — on a download that must be visible, not swallowed.
    """
    param_values = param_values or {}
    active = None if active is None else set(active)
    if base is None:
        imgs = {sid: bytearray(seg.data)
                for sid, seg in prog.segments.items() if seg.data is not None}
    else:
        imgs = {sid: bytearray(b) for sid, b in base.items()}
    for pid, p in prog.params.items():
        if not p.mem or (active is not None and pid not in active):
            continue
        seg, off, bit = p.mem
        buf = imgs.get(seg)
        t = prog.types.get(p.type_id)
        if buf is None or t is None:
            continue                 # RAM/unseeded segment, or an unknown type
        raw = param_values.get(pid, p.value)
        try:
            if t.kind == 'float' and t.enc == 'DPT 9':
                val = dpt9_word(float(raw))
            elif t.kind in ('enum', 'int') and t.bits > 0:
                val = int(raw)
            else:
                continue             # text/colour/picture: not memory-encoded
        except (TypeError, ValueError) as e:
            if log:
                log(f'  parameter {p.text or pid!r} ({t.kind}): value {raw!r} '
                    f'not encodable ({e}) — segment byte left at its default')
            continue
        put_bits(buf, off, bit, t.bits, val)
    return imgs


# ---- address / association tables ----------------------------------------

def addr_table(ia, gas, size=None):
    """Address table image: count byte (1 + #GAs), own IA, then sorted GAs,
    all big-endian 16-bit. Padded with zeros to `size`."""
    gas = sorted(set(gas))
    out = bytearray([1 + len(gas)]) + struct.pack('!H', ia)
    for g in gas:
        out += struct.pack('!H', g)
    if size is not None:
        if len(out) > size:
            raise ValueError('address table exceeds segment size')
        out += b'\0' * (size - len(out))
    return bytes(out)


def assoc_table(pairs, size=None):
    """Association table image (mask 0705): count byte, then one-byte pairs
    (1-based address-table index, com-object number). `pairs` in final order."""
    out = bytearray([len(pairs)])
    for idx, num in pairs:
        out += bytes([idx & 0xFF, num & 0xFF])
    if size is not None:
        if len(out) > size:
            raise ValueError('association table exceeds segment size')
        out += b'\0' * (size - len(out))
    return bytes(out)


# ---- project -> download images ------------------------------------------

def _image_base(project, dev, base=None, log=None):
    """The model-independent start of every download image build:
    (prog, visible ComObjectRef ids, sorted linked GAs, parameter images).
    Only the ACTIVE (visible) params are written — union members share
    memory, so writing inactive ones corrupts the image."""
    prog = project.program(dev)
    corefs = project.visible_corefs(dev)
    gas = sorted({g for cid in corefs for g in dev.links.get(cid, [])})
    active = {prog.prefs[r].param_id for r in project.visible_prefs(dev)
              if r in prog.prefs}
    imgs = param_images(prog, effective_param_values(prog, dev.values),
                        active=active, base=base, log=log)
    return prog, corefs, gas, imgs


def _visible_objs(prog, corefs):
    """(coref id, ComObjectRef, ComObject) for each visible ref that resolves."""
    for cid in corefs:
        cr = prog.corefs.get(cid)
        co = prog.comobjs.get(cr.obj_id) if cr else None
        if co:
            yield cid, cr, co


def effective_param_values(prog, dev_values):
    """param_id -> value string: each parameter's ParameterRef default, with the
    device's deviations (keyed by pref id) applied on top."""
    pv = {pr.param_id: (pr.value if pr.value is not None
                        else prog.params[pr.param_id].value)
          for pr in prog.prefs.values() if pr.param_id in prog.params}
    for pref_id, val in dev_values.items():
        pr = prog.prefs.get(pref_id)
        if pr:
            pv[pr.param_id] = val
    return pv


def device_images(project, dev, base=None, log=None):
    """Build {segment_id: bytes} for a download from the project.

    Parameters: only the ACTIVE (visible) params are written — union members
    share memory, so writing inactive ones corrupts the image. `base` is the
    initial memory ({segment_id: bytes}); pass the device's current memory to
    preserve every byte the project does not explicitly set (safest), else the
    knxprod seed is used. The com-object table keeps the seed's data pointers
    and types; each config byte is rebuilt from the effective flags."""
    prog, corefs, gas, imgs = _image_base(project, dev, base, log)
    ia = ia_int(dev.ia)
    pairs, active = [], {}
    for cid, cr, co in _visible_objs(prog, corefs):
        links = dev.links.get(cid, [])
        active[co.number] = (_effective_flags(prog, cr), bool(links))
        for g in links:
            pairs.append((gas.index(g) + 1, co.number))
    # DynamicTableManagement: the tables are packed back to back (see
    # Mgmt._placement), so they are not padded to the segment size
    if prog.addrtab:
        seg = prog.segments[prog.addrtab[0]]
        imgs[prog.addrtab[0]] = bytearray(
            addr_table(ia, gas, None if prog.dyntab else seg.size))
    if prog.assoctab:
        seg = prog.segments[prog.assoctab[0]]
        # ETS orders the pairs by object number (pinned from its own write
        # to the ESYLUX PD-C180i: (5,0)(1,1)(2,4)(3,9)(4,15)(5,19))
        pairs.sort(key=lambda p: (p[1], p[0]))
        imgs[prog.assoctab[0]] = bytearray(
            assoc_table(pairs, None if prog.dyntab else seg.size))
    if prog.comobjtab:
        seg = prog.segments[prog.comobjtab[0]]
        base_ct = imgs.get(prog.comobjtab[0], seg.data)
        if base_ct is not None:
            imgs[prog.comobjtab[0]] = bytearray(
                comobj_table(base_ct, active))
    return {sid: bytes(buf) for sid, buf in imgs.items()}, prog


def _effective_flags(prog, coref):
    """Com-object flags with the ComObjectRef's overrides applied."""
    co = prog.comobjs.get(coref.obj_id)
    s = set(co.flags.replace(' ', '')) if co else set()
    for ch, on in coref.flag_overrides.items():
        (s.add if on else s.discard)(ch)
    return ''.join(sorted(s))


def comobj_table(factory, active):
    """Build the com-object table from the factory image. Layout:
    [count:1][ram_flags_ptr:2] then N x [dataptr:2][config:1][type:1]. Data
    pointers and type bytes are kept from the factory image. A visible
    object's config byte comes from its effective flags (_co_config_b: C only
    when it has a group link); an invisible object keeps the factory config
    with C cleared. Pinned on the MDT BE-02 (factory 0xdf -> 0xdb, CT linked
    -> 0x47, CTUW linked -> 0xd7, CRT unlinked -> 0x4b) and the ESYLUX
    PD-C180i (factory 0x17/0x47 -> 0x13/0x43 invisible, CW linked -> 0x17,
    CRT linked -> 0x4f, CRT unlinked -> 0x4b).

    active maps object number -> (flags, linked). Object numbers are 0-based
    here — the System B table (comobj_table_b) is 1-based; both are keyed by
    ComObject.number for their own family."""
    buf = bytearray(factory)
    count = buf[0]
    if len(buf) < 3 + 4 * count:
        raise ValueError(f'com-object table declares {count} objects but the '
                         f'segment holds {len(buf)} bytes')
    for num in range(count):
        i = 3 + 4 * num + 2
        if num in active:
            buf[i] = _co_config_b(*active[num], prio=buf[i] & 0x03)
        else:
            buf[i] &= ~0x04
    return bytes(buf)


def crc16(data, crc=0x1D0F):
    """CRC-16/AUG-CCITT (poly 0x1021, init 0x1D0F): the System B memory
    control block (PID 27) checksum."""
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else crc << 1
    return crc


def addr_table_b(gas, max_entries=None):
    """System B address table: 16-bit count, then the sorted GAs (the own IA
    is NOT part of the table, unlike mask 0705)."""
    gas = sorted(set(gas))
    if max_entries and len(gas) > max_entries:
        raise ValueError('address table exceeds MaxEntries')
    return struct.pack('!H', len(gas)) + b''.join(
        struct.pack('!H', g) for g in gas)


def assoc_table_b(pairs):
    """System B association table: 16-bit count, then 16-bit pairs (1-based
    address-table index, com-object number) in ETS order: each object's
    first (= sending) association sorted by object number, then the
    remaining associations, also by object number. Pinned against real ETS
    downloads (single-link Cheops, multi-link Gira actuator)."""
    first, rest, seen = [], [], set()
    for idx, num in pairs:
        (rest if num in seen else first).append((idx, num))
        seen.add(num)
    out = sorted(first, key=lambda p: p[1]) + sorted(rest, key=lambda p: p[1])
    return struct.pack('!H', len(out)) + b''.join(
        struct.pack('!HH', idx, num) for idx, num in out)


# ObjectSize -> group-object descriptor type code: "N Bit" -> N-1, then bytes
_BYTE_CODES = {1: 7, 2: 8, 3: 9, 4: 10, 5: 15, 6: 11, 7: 16, 8: 12, 9: 17,
               10: 13, 11: 18, 12: 19, 13: 20, 14: 14}

def _size_code(size, num=None):
    try:
        n, unit = size.split()
        n = int(n)
    except (AttributeError, ValueError):
        raise ValueError(f'com-object {num}: no usable ObjectSize '
                         f'({size!r}) — cannot build its descriptor') from None
    if unit.startswith('Bit'):
        return n - 1
    return _BYTE_CODES.get(n, n + 6)


def _co_config_b(flags, linked, prio=3):
    """System B group-object descriptor config byte: b7=U b6=T b5=I(read on
    init) b4=W b3=R b2=C b1-0=priority. ETS sets C only on objects that have
    a group association."""
    c = prio & 0x03
    for ch, bit in (('U', 0x80), ('T', 0x40), ('I', 0x20),
                    ('W', 0x10), ('R', 0x08)):
        if ch in flags:
            c |= bit
    if linked and 'C' in flags:
        c |= 0x04
    return c


def comobj_table_b(count, descs):
    """System B group-object table: 16-bit count, then one descriptor
    [config:1][size code:1] per object number 1..count. descs maps
    number -> (flags, size string, linked); numbers not present (objects
    invisible in the current parameter config) get 0x0000."""
    out = bytearray(struct.pack('!H', count))
    for num in range(1, count + 1):
        d = descs.get(num)
        if d:
            flags, size, linked = d
            out += bytes([_co_config_b(flags, linked), _size_code(size, num)])
        else:
            out += b'\0\0'
    return bytes(out)


def device_images_b(project, dev, log=None):
    """Build the System B download images, one per load state machine:
    {1: address table, 2: association table, 3: group-object table,
    4+: app image}. App LSM images concatenate that LSM's relative segments
    at their offsets over the knxprod seed, with the active parameters
    overlaid (same rules as device_images)."""
    prog, corefs, gas, segimgs = _image_base(project, dev, log=log)
    imgs = {}
    for sid, seg in prog.segments.items():
        if not seg.lsm:
            continue
        buf = imgs.setdefault(seg.lsm, bytearray())
        if len(buf) < seg.offset + seg.size:
            buf += b'\0' * (seg.offset + seg.size - len(buf))
        data = segimgs.get(sid, seg.data)
        if data:
            buf[seg.offset:seg.offset + len(data)] = data

    pairs, descs = [], {}
    for cid, cr, co in _visible_objs(prog, corefs):
        linked = bool(dev.links.get(cid))
        if co.number not in descs or linked:   # a linked ref wins the slot
            descs[co.number] = (_effective_flags(prog, cr),
                                cr.size or co.size, linked)
        for g in dev.links.get(cid, []):
            pairs.append((gas.index(g) + 1, co.number))
    imgs[1] = bytearray(addr_table_b(gas, prog.addrtab and prog.addrtab[2]))
    imgs[2] = bytearray(assoc_table_b(pairs))
    count = max((co.number for co in prog.comobjs.values()), default=0)
    imgs[3] = bytearray(comobj_table_b(count, descs))
    return {oi: bytes(buf) for oi, buf in imgs.items()}, prog


# ---- BCU1 (mask 0012 family) ---------------------------------------------
# The oldest programming model, and the simplest: no interface objects, no load
# state machines, no property services. One EEPROM page at 0x100 holds the BCU1
# system bytes, ALL THREE TABLES (at the offsets the knxprod declares inside
# that segment, not in segments of their own) and the parameter memory. The
# download is a plain sequence of A_MemoryWrite runs.
#
# Layout, from the mask's Resources in knx_master.xml and KNX spec 3/5/1
# realisation type 1: 0x100 option register, 0x101-0x103 manufacturer data,
# 0x104 application id, 0x10D RunError, 0x10E-0x115 route count / config /
# table pointers, 0x116 address table (count, own IA, then the GAs), and the
# com-object table, association table and parameter memory wherever the
# knxprod places them in the rest of the page.

def comobj_table_1(factory, descs):
    """BCU1 group-object table, patched into the factory image: [count:1]
    [RAM flags pointer:1] then N x [data pointer:1][config:1][type:1]. Only
    the config byte is ours — the data pointer (an offset into the app's user
    RAM) and the size/type code belong to the application, so they are kept
    exactly as shipped. `descs` maps a 0-based object number to
    (flags, linked); objects not in it are invisible under the current
    parameter config and get config 0 (communication off), as ETS does on the
    later models.

    One-byte pointers are what separates this from the BIM M112 table
    (comobj_table): BCU1 addresses everything within the 0x100 page.

    UNPINNED: the descriptor layout and the config byte come from the spec
    (the standard group-object descriptor, same bit assignment System B uses),
    not from a captured ETS download — no BCU1 device with com objects has
    been seen yet. The rest of the BCU1 path is pinned by the mask's own
    default load procedure; this is the one part that is not."""
    buf = bytearray(factory)
    count = buf[0]
    if len(buf) < 2 + 3 * count:
        raise ValueError(f'com-object table declares {count} objects but only '
                         f'{len(buf)} bytes are available')
    for num in range(count):
        d = descs.get(num)
        buf[2 + 3 * num + 1] = _co_config_b(*d) if d else 0
    return bytes(buf)


def _patch_table(imgs, tab, data, what):
    """Write a table into its segment image at the offset the knxprod declares
    (BCU1 keeps all three inside the one code segment)."""
    if not tab:
        return
    sid, off, _ = tab
    buf = imgs.get(sid)
    if buf is None:
        raise ValueError(f'{what} table segment {sid} has no image')
    if off + len(data) > len(buf):
        raise ValueError(
            f'{what} table ({len(data)} B at offset {off}) does not fit the '
            f'{len(buf)}-byte segment — too many group addresses for this device')
    buf[off:off + len(data)] = data


def device_images_1(project, dev, base=None, log=None):
    """Build the BCU1 download image: {segment_id: bytes}, normally a single
    256-byte EEPROM page. Same parameter rules as device_images; the address,
    association and com-object tables are then patched into that page at their
    declared offsets.

    The address and association tables have the same byte layout as mask 0705
    (1-byte count, 1-byte association pairs) — the address table's placement is
    itself the cross-check: at offset 22 its count lands on 0x116 and its own-IA
    entry on 0x117-0x118, exactly the bytes the default load procedure writes
    separately and skips."""
    prog, corefs, gas, imgs = _image_base(project, dev, base, log)
    pairs, descs = [], {}
    for cid, cr, co in _visible_objs(prog, corefs):
        linked = bool(dev.links.get(cid))
        if co.number not in descs or linked:   # a linked ref wins the slot
            descs[co.number] = (_effective_flags(prog, cr), linked)
        for g in dev.links.get(cid, []):
            pairs.append((gas.index(g) + 1, co.number))
    if prog.comobjtab:
        sid, off, _ = prog.comobjtab
        buf = imgs.get(sid)
        if buf is None or off >= len(buf):
            raise ValueError(f'com-object table offset {off} falls outside '
                             f'segment {sid}')
        _patch_table(imgs, prog.comobjtab,
                     comobj_table_1(buf[off:off + 2 + 3 * buf[off]], descs),
                     'com-object')
    _patch_table(imgs, prog.addrtab, addr_table(ia_int(dev.ia), gas), 'address')
    _patch_table(imgs, prog.assoctab, assoc_table(sorted(pairs)), 'association')
    return {sid: bytes(buf) for sid, buf in imgs.items()}, prog


def app_owned(seg, i):
    """Does byte `i` of a segment belong to the application program? The
    knxprod <Mask> marks the device's own bytes (its individual address, the
    manufacturer data, a factory identity/MAC area) with 0x00; writing the
    knxprod seed over those would clobber per-device data, and comparing them
    on a read-back would report differences nobody can fix.

    The BCU1 path writes and compares only these runs; BIM M112 uses
    written_runs (mask 0xff OR parameter-covered) for its parameter segments;
    System B is pinned byte-for-byte against real ETS downloads writing whole
    segments."""
    return seg.mask is None or i >= len(seg.mask) or seg.mask[i] == 0xFF


def mask_runs(seg, off, size):
    """[(offset, length)] — `size` bytes from `off` split into the runs the
    application program owns (see app_owned)."""
    runs, i, end = [], off, off + size
    while i < end:
        if not app_owned(seg, i):
            i += 1
            continue
        j = i
        while j < end and app_owned(seg, j):
            j += 1
        runs.append((i, j - i))
        i = j
    return runs


def written_runs(prog, sid, img):
    """[(offset, length)] of a BIM M112 config segment ETS actually writes:
    the bytes a memory-mapped parameter covers plus those the knxprod <Mask>
    marks 0xff (fixed data). Segments without a <Mask> and the three tables
    are written whole (the MDT BE-02 pin). Pinned on the ESYLUX PD-C180i:
    after an ETS download every byte outside this set reads erased (0xff),
    so writing the seed there is both unverified and unverifiable."""
    seg = prog.segments[sid]
    tables = {t[0] for t in (prog.addrtab, prog.assoctab, prog.comobjtab) if t}
    if seg.mask is None or sid in tables:
        return [(0, len(img))]
    own = bytearray(len(img))
    for i in range(min(len(img), len(seg.mask))):
        own[i] = seg.mask[i] == 0xFF
    for p in prog.params.values():
        t = prog.types.get(p.type_id) if p.mem and p.mem[0] == sid else None
        if not t or t.bits <= 0:
            continue
        start = p.mem[1] * 8 + p.mem[2]
        for b in range(start // 8, (start + t.bits - 1) // 8 + 1):
            if b < len(own):
                own[b] = 1
    runs, i = [], 0
    while i < len(own):
        if not own[i]:
            i += 1
            continue
        j = i
        while j < len(own) and own[j]:
            j += 1
        runs.append((i, j - i))
        i = j
    return runs


# ---- device -> project (read-back decode) --------------------------------
# Inverses of the builders above: parse the tables and bit-unpack the params
# from memory read back off a device, so its state can be diffed against (or
# imported into) the project.

def parse_addr_table(data):
    """Inverse of addr_table (mask 0705): (own IA, sorted GA list)."""
    n = data[0]                       # count includes the own IA
    ia = struct.unpack('!H', data[1:3])[0]
    return ia, [struct.unpack('!H', data[1 + 2 * i:3 + 2 * i])[0]
                for i in range(1, n)]


def parse_assoc_table(data):
    """Inverse of assoc_table (mask 0705): [(addr index, comobj number)]."""
    return [(data[1 + 2 * i], data[2 + 2 * i]) for i in range(data[0])]


def parse_addr_table_b(data):
    """Inverse of addr_table_b: the sorted GA list."""
    n = struct.unpack('!H', data[:2])[0]
    return [struct.unpack('!H', data[2 + 2 * i:4 + 2 * i])[0]
            for i in range(n)]


def parse_assoc_table_b(data):
    """Inverse of assoc_table_b: [(addr index, comobj number)]."""
    n = struct.unpack('!H', data[:2])[0]
    return [struct.unpack('!HH', data[2 + 4 * i:6 + 4 * i])
            for i in range(n)]


def links_from_tables(gas, pairs):
    """{comobj number: [ga]} from a parsed address + association table, in
    table order — the object's FIRST association is its sending one. The
    address index is 1-based; on 0705 entry 0 is the own IA, so the
    numbering over the GA list is the same for both families."""
    m = {}
    for idx, num in pairs:
        if 1 <= idx <= len(gas):
            g = gas[idx - 1]
            l = m.setdefault(num, [])
            if g not in l:
                l.append(g)
    return m


def project_links(project, dev):
    """{comobj number: [ga]} the project would program (the same walk the
    image builders do over the visible ComObjectRefs; link-list order kept,
    first = sending)."""
    prog = project.program(dev)
    m = {}
    for cid, _, co in _visible_objs(prog, project.visible_corefs(dev)):
        for g in dev.links.get(cid, []):
            l = m.setdefault(co.number, [])
            if g not in l:
                l.append(g)
    return m


def _mem_pref(prog, pref_id):
    """(Param, ParamType) when the pref maps to a decodable memory-mapped
    parameter (same filter param_images writes), else None."""
    pr = prog.prefs.get(pref_id)
    p = prog.params.get(pr.param_id) if pr else None
    if not p or not p.mem:
        return None
    t = prog.types.get(p.type_id)
    if not t or t.bits <= 0:
        return None
    if (t.kind == 'float' and t.enc == 'DPT 9') or t.kind in ('enum', 'int'):
        return p, t
    return None


def _val_eq(a, b):
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        return a == b


def decode_params(project, dev, imgs):
    """Decode the visible memory-mapped parameter values from device images
    ({lsm: bytes} for System B, {segment_id: bytes} for 0705). Visibility
    depends on the values (union members share memory), so decode iterates
    to a fixpoint. Mem-less params (module args, text) gate visibility but
    leave no trace in memory — reconstruction is ambiguous without them, so
    the device's current project deviations for those are kept as seeds and
    carried into the result. Returns {pref_id: value string}."""
    prog = project.program(dev)
    saved = dev.values
    keep = {r: v for r, v in saved.items() if not _mem_pref(prog, r)}
    try:
        dev.values = dict(keep)
        for _ in range(10):
            new = dict(keep)
            for r in project.visible_prefs(dev):
                pt = _mem_pref(prog, r)
                if not pt:
                    continue
                p, t = pt
                sid, boff, bit = p.mem
                s = prog.segments[sid]
                if not s.is_config:      # RAM / identity: not readable config
                    continue
                buf = imgs.get(s.lsm or sid)
                off = boff + (s.offset if s.lsm else 0)
                if buf is None or off * 8 + bit + t.bits > len(buf) * 8:
                    continue
                raw = get_bits(buf, off, bit, t.bits)
                new[r] = (str(dpt9_value(raw)) if t.kind == 'float'
                          else str(raw))
            if new == dev.values:
                return new
            dev.values = new
        raise RuntimeError('parameter decode did not reach a fixpoint')
    finally:
        dev.values = saved


def parse_comobj_table_b(data):
    """Active com-object numbers from a System B group-object table: the
    descriptor slots ETS leaves 0x0000 are invisible objects (inverse of
    comobj_table_b)."""
    n = struct.unpack('!H', data[:2])[0]
    return {num for num in range(1, n + 1)
            if data[2 * num] or data[2 * num + 1]}


def _gate_prefs(prog):
    """Pref ids used in Choose tests whose param has no memory location —
    values that gate visibility but leave no trace in parameter memory."""
    out = {}

    def walk(nodes):
        for n in nodes:
            if isinstance(n, Choose):
                if n.param_ref in prog.prefs and not _mem_pref(prog, n.param_ref):
                    out[n.param_ref] = None
                for _, kids in n.whens:
                    walk(kids)
            elif isinstance(n, Block):
                walk(n.children)
    walk(prog.dynamic)
    return list(out)


def _visible_nums(project, dev, prog):
    return {co.number
            for _, _, co in _visible_objs(prog, project.visible_corefs(dev))}


def _cover_missing(project, dev, prog, missing):
    """Assign mem-less gate prefs so each missing object's Choose-condition
    path passes (memory-decoded conditions are facts and never touched).
    Returns True when something was assigned."""
    values = prog.values(dev)
    paths = {}                        # number -> [ [(pref_id, test)], ... ]

    def walk(nodes, conds):
        for n in nodes:
            if isinstance(n, CRef):
                cr = prog.corefs.get(n.ref_id)
                co = cr and prog.comobjs.get(cr.obj_id)
                if co and co.number in missing:
                    paths.setdefault(co.number, []).append(conds)
            elif isinstance(n, Block):
                walk(n.children, conds)
            elif isinstance(n, Choose):
                for test, kids in n.whens:
                    walk(kids, conds + [(n.param_ref, test)])
    walk(prog.dynamic, [])
    changed = False
    for num in sorted(missing):
        for conds in paths.get(num, []):
            fix, ok = {}, True
            for pref_id, test in conds:
                v = fix.get(pref_id, values.get(pref_id, ''))
                if test is None or test_matches(test, v):
                    continue
                if pref_id not in prog.prefs or _mem_pref(prog, pref_id):
                    ok = False
                    break
                t = prog.types.get(
                    prog.params[prog.prefs[pref_id].param_id].type_id)
                cands = ([str(e[0]) for e in t.enums] if t and t.enums
                         else [str(i) for i in range(16)])
                sat = next((c for c in cands if test_matches(test, c)), None)
                if sat is None:
                    ok = False
                    break
                fix[pref_id] = sat
            if ok:
                if fix:
                    dev.values.update(fix)
                    values.update(fix)
                    changed = True
                break                 # this number's path is satisfied
    return changed


def _active_0705(prog, dev_imgs, linked):
    """Objects certainly visible on a 0705 device: linked, or a config byte
    that differs from the invisible value (factory config with C cleared).
    A visible unlinked object whose flags give that same byte is ambiguous
    and left out."""
    seed = prog.segments[prog.comobjtab[0]].data
    got = dev_imgs[prog.comobjtab[0]]
    return set(linked) | {i for i in range(seed[0])
                          if got[3 + 4 * i + 2] != seed[3 + 4 * i + 2] & ~0x04}


def infer_gate_params(project, dev, dev_imgs, links=None, log=print):
    """Recover mem-less gate params (channel modes, module args) from the
    group-object table: the correct gate values are the ones that make the
    project's visible-object set match the device's. System B: ETS gives
    every VISIBLE object a nonzero descriptor, so the sets are compared
    directly. BIM M112: the table is rebuilt from the project (comobj_table,
    with `links` = the device's decoded {number: [ga]}) and the config bytes
    compared to the device's — ambiguous objects then cost nothing. Two
    phases: constraint pass — satisfy the condition path of every
    active-but-hidden object directly (handles coarse gates like 'extensions
    fitted' whose flip alone would look worse); then a greedy hill-climb over
    gate enum values to clear leftover differences. Memory params are
    re-decoded after each round (visibility shifts what is mapped). Mutates
    dev.values; returns the final {pref_id: value}."""
    prog = project.program(dev)
    if prog.mask in Mgmt._SYSTEMB_MASKS:
        active = parse_comobj_table_b(dev_imgs[3])

        def score():
            return len(active ^ _visible_nums(project, dev, prog))
    else:
        linked = set(links or ())
        active = _active_0705(prog, dev_imgs, linked)
        seed = prog.segments[prog.comobjtab[0]].data
        got = dev_imgs[prog.comobjtab[0]]

        def score():
            vis = {co.number: (_effective_flags(prog, cr), co.number in linked)
                   for _, cr, co in _visible_objs(
                       prog, project.visible_corefs(dev))}
            want = comobj_table(seed, vis)
            return sum(want[3 + 4 * i + 2] != got[3 + 4 * i + 2]
                       for i in range(seed[0]))
    dev.values = decode_params(project, dev, dev_imgs)

    for _ in range(10):
        missing = active - _visible_nums(project, dev, prog)
        if not missing or not _cover_missing(project, dev, prog, missing):
            break
        dev.values = decode_params(project, dev, dev_imgs)
    gates = _gate_prefs(prog)
    s = score()
    for _ in range(10):
        if not s:
            break
        improved = False
        for r in gates:
            p = prog.params[prog.prefs[r].param_id]
            t = prog.types.get(p.type_id)
            if not t or not t.enums:
                continue
            cur = str(dev.values.get(r, prog.default(r)))
            for v, _txt in t.enums:
                if str(v) == cur:
                    continue
                dev.values[r] = str(v)
                s1 = score()
                if s1 < s:
                    s, cur, improved = s1, str(v), True
                else:
                    dev.values[r] = cur
        if not improved:
            break
        dev.values = decode_params(project, dev, dev_imgs)
        s = score()
    if s:
        log(f'group-object table: {s} object(s) unresolved after gate '
            'inference (mem-less params are ambiguous)')
    return dev.values


def recover_device(project, dev, dev_imgs, log=print):
    """decode_device plus inference of mem-less gate params (System B and
    BIM M112, needs the group-object table image). The device's current
    project deviations still seed the decode; a fresh device starts from
    defaults."""
    prog = project.program(dev)
    if prog.mask in Mgmt._SYSTEMB_MASKS:
        has_table = 3 in dev_imgs
    elif prog.mask in Mgmt._BIMM112_MASKS:
        has_table = bool(prog.comobjtab) and prog.comobjtab[0] in dev_imgs
    else:
        has_table = False
    state = decode_device(project, dev, dev_imgs)
    if not has_table:
        return state
    saved = dev.values
    try:
        dev.values = dict(saved)
        state['params'] = infer_gate_params(project, dev, dev_imgs,
                                            state['links'], log)
    finally:
        dev.values = saved
    return state


def _assoc_pairs_0705(prog, dev_imgs, gas):
    """0705 association pairs, from whichever layout the device actually uses:
    ETS may place the association table in its own segment (MDT: a separate
    AssociationTable segment) OR pack it contiguously right after the address
    table in the address segment (ESYLUX: the AssociationTable segment address
    in the knxprod is unused; ETS allocates assoc at addr_table_end). Read both
    candidates and take the one that parses to in-range (index, object) pairs."""
    def ok(pairs):
        return bool(pairs) and all(1 <= idx <= len(gas) for idx, _ in pairs)
    at = dev_imgs.get(prog.addrtab[0], b'')
    at_len = 3 + 2 * len(gas)                 # count + own IA + GAs
    contiguous = parse_assoc_table(at[at_len:]) if len(at) > at_len else []
    separate = (parse_assoc_table(dev_imgs[prog.assoctab[0]])
                if prog.assoctab and prog.assoctab[0] in dev_imgs else [])
    if ok(contiguous):
        return contiguous
    if ok(separate):
        return separate
    return contiguous or separate


def _tables_1(prog, dev_imgs):
    """BCU1 (gas, association pairs): both tables live inside the one code
    segment, so they are parsed from their declared offsets into its image."""
    img = dev_imgs[prog.addrtab[0]]
    _, gas = parse_addr_table(img[prog.addrtab[1]:])
    pairs = (parse_assoc_table(dev_imgs[prog.assoctab[0]][prog.assoctab[1]:])
             if prog.assoctab else [])
    return gas, pairs


def decode_device(project, dev, dev_imgs):
    """Semantic state from read-back images:
    {'params': {pref_id: value}, 'links': {comobj number: [ga]}}."""
    prog = project.program(dev)
    if prog.mask in Mgmt._SYSTEMB_MASKS:
        gas = parse_addr_table_b(dev_imgs.get(1, b'\0\0'))
        pairs = parse_assoc_table_b(dev_imgs.get(2, b'\0\0'))
    elif prog.mask in Mgmt._BCU1_MASKS:
        gas, pairs = _tables_1(prog, dev_imgs)
    else:
        _, gas = parse_addr_table(dev_imgs[prog.addrtab[0]])
        pairs = _assoc_pairs_0705(prog, dev_imgs, gas)
    return {'params': decode_params(project, dev, dev_imgs),
            'links': links_from_tables(gas, pairs)}


def semantic_diff(project, dev, state):
    """Decoded device `state` against the project: ({comobj number:
    (device gas, project gas)}, {pref id: (device value, project value)}).
    Params only visible on one side are gated by a differing value that is
    itself reported, so only prefs visible on both sides are compared."""
    prog = project.program(dev)
    mine = project_links(project, dev)
    links = {}
    for num in sorted(set(state['links']) | set(mine)):
        d, p = state['links'].get(num, []), mine.get(num, [])
        if d != p:
            links[num] = (d, p)
    proj_par = {r: dev.values.get(r, prog.default(r))
                for r in project.visible_prefs(dev) if _mem_pref(prog, r)}
    params = {r: (state['params'][r], proj_par[r])
              for r in sorted(set(state['params']) & set(proj_par))
              if not _val_eq(state['params'][r], proj_par[r])}
    return links, params


def diff_report(project, dev, state, log):
    """Log the semantic differences (semantic_diff): group links per
    com-object, then parameter values. Returns their count."""
    prog = project.program(dev)
    names = {co.number: co.text for co in prog.comobjs.values()}
    links, params = semantic_diff(project, dev, state)
    for num, (d, p) in links.items():
        log(f'  obj {num} "{names.get(num, "?")}": device '
            f'{" ".join(map(ga_str, d)) or "-"}, project '
            f'{" ".join(map(ga_str, p)) or "-"}')
    for r, (d, p) in params.items():
        pr = prog.prefs[r]
        log(f'  param {pr.text or prog.params[pr.param_id].text}: '
            f'device {d}, project {p}')
    n = len(links) + len(params)
    log(f'{n} difference(s)')
    return n


def apply_device_state(project, dev, state):
    """Import decoded device state into the project device. Kept deviations:
    value != ref default OR != the last-wins effective value (dropping either
    kind would change what a download writes). Links are rebuilt from
    {comobj number: [ga]}; unknown GAs are created named after the device.
    Returns the comobj numbers whose links could not be mapped (not visible
    under the imported values)."""
    prog = project.program(dev)
    base = effective_param_values(prog, {})
    dev.values = {r: v for r, v in state['params'].items() if r in prog.prefs
                  and (not _val_eq(v, prog.default(r))
                       or not _val_eq(v, base.get(prog.prefs[r].param_id)))}
    num2cid = {}
    for cid, _, co in _visible_objs(prog, project.visible_corefs(dev)):
        num2cid.setdefault(co.number, cid)
    dev.links = {}
    skipped = []
    for num, gas in sorted(state['links'].items()):
        cid = num2cid.get(num)
        if not cid:
            skipped.append(num)
            continue
        cr = prog.corefs[cid]
        co = prog.comobjs[cr.obj_id]
        for g in gas:
            new = g not in project.gas
            project.link(dev, cid, g)
            if new:
                project.gas[g].update(name=f'from {dev.ia}',
                                      dpt=cr.dpt or co.dpt or '')
    return skipped


# ---- point-to-point management ------------------------------------------

def _apdu(apci10, payload=b'', tpci=0x00):
    """TPCI/APCI octets + payload. Low 6 bits of the APCI share octet1 with a
    count/type (already folded into apci10 by the caller)."""
    return bytes([tpci | (apci10 >> 8 & 0x03), apci10 & 0xFF]) + payload


class Cancelled(RuntimeError):
    """The user cancelled the task; raised from Mgmt.wait between telegrams."""


class NoResponse(TimeoutError):
    """The peer ACKed our request at the transport layer but never sent the
    application response — i.e. something IS at that address. Distinct from a
    plain TimeoutError (no T_ACK: nothing answered at all), which is how scan
    tells a mute device from an empty address."""


def _apci_match(got, want):
    """Match a received APCI to an expected one. Escape-coded APCIs (>= 0x3C0,
    e.g. PropertyValue) and the extended services block (0x1C0-0x1FF: ext
    memory/property) match exactly; others (Memory, DeviceDescriptor) carry a
    count/type in the low 6 bits, so match on the 4-bit kind only."""
    if want >= 0x3C0 or want >> 6 == 7:
        return got == want
    return (got & 0x3C0) == (want & 0x3C0)


def _segment_report(imgs, dev_imgs, bad, mcbs=None):
    """Per-segment numbers for a VerifyResult: lengths, CRC16s (System B
    without a read-back: the device's MCB CRCs), the first byte diffs."""
    out = []
    for k in sorted(imgs):
        a, b = imgs[k], dev_imgs.get(k)
        seg = {'id': f'LSM {k}' if isinstance(k, int) else
               f'segment {k.split("_")[-1]}',
               'proj_len': len(a), 'proj_crc16': crc16(a),
               'dev_len': None, 'dev_crc16': None,
               'match': k not in bad, 'diff_count': 0, 'first_diffs': []}
        if b is not None:
            seg['dev_len'], seg['dev_crc16'] = len(b), crc16(b)
            offs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
            seg['diff_count'] = len(offs) + abs(len(a) - len(b))
            seg['first_diffs'] = [(o, a[o], b[o]) for o in offs[:8]]
        elif mcbs and k in mcbs:
            seg['dev_len'] = sum(l for l, _, _ in mcbs[k])
            seg['dev_crc16'] = [cc for _, _, cc in mcbs[k]]
        out.append(seg)
    return out


@dataclass
class VerifyResult:
    """What Mgmt.verify found, in numbers and ids only — the part of a verify
    that may leave the machine as a report (no names, addresses, values)."""
    outcome: str = 'error'          # match | mismatch | error
    error: str = ''                 # the exception's message on error
    descriptor: str = ''            # mask read from the device (hex)
    app_id_ok: bool | None = None   # System B PID 13 == knxprod (None: n/a)
    # per LSM / segment: {id, proj_len, dev_len, proj_crc16, dev_crc16,
    # match, diff_count, first_diffs: [(offset, proj, dev)] (<= 8)}
    segments: list = field(default_factory=list)
    params_differ: list = field(default_factory=list)   # pref ids
    links_differ: list = field(default_factory=list)    # com-object numbers


class Mgmt:
    """Device management over a connected TunnelClient. Installs a raw_hook to
    capture broadcast + individually-addressed telegrams into a queue; call
    close() to restore normal monitor delivery."""

    def __init__(self, bus):
        self.bus = bus
        self.q = queue.Queue()
        self.cancelled = lambda: False   # polled in wait(); raises Cancelled
        self.last_verify = None          # VerifyResult of the last verify()
        self._descriptor = ''            # last _open's device descriptor
        self._mcbs = {}                  # last _check_sysb's MCBs per LSM
        self._prev_hook = bus.raw_hook
        bus.raw_hook = self._hook

    def _hook(self, t):
        if (t.group and t.dst == 0) or not t.group:   # broadcast or p2p
            self.q.put(t)
            return True
        return self._prev_hook(t) if self._prev_hook else False

    def close(self):
        self.bus.raw_hook = self._prev_hook

    def _drain(self):
        try:
            while True:
                self.q.get_nowait()
        except queue.Empty:
            pass

    def wait(self, pred, timeout):
        end = time.monotonic() + timeout
        while True:
            if self.cancelled():
                # once: the cleanup that follows (disconnects, restores) must
                # still get its answers
                self.cancelled = lambda: False
                raise Cancelled('cancelled by user')
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                t = self.q.get(timeout=min(left, 0.25))   # stay cancellable
            except queue.Empty:
                continue
            if pred(t):
                return t

    # -- broadcast (programming mode) --
    def _bcast(self, apci10, payload=b''):
        self.bus.send_cemi(cemi_ldata(0, _apdu(apci10, payload), self.bus.ia, True))

    def ia_read(self, timeout=3.0):
        """Individual addresses of all devices currently in programming mode."""
        self._drain()
        self._bcast(A_IND_ADDR_READ)
        found = []
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            t = self.wait(lambda t: t.group and t.apci10 == A_IND_ADDR_RESP,
                          end - time.monotonic())
            if not t:
                break
            if t.src not in found:
                found.append(t.src)
        return found

    def ia_write(self, ia):
        self._bcast(A_IND_ADDR_WRITE, struct.pack('!H', ia))

    def assign(self, ia, log=print, cancelled=lambda: False):
        """ETS-style address assignment: poll for a device in programming mode
        (the user presses its button), then write `ia` and verify. Returns the
        device descriptor. `cancelled` is checked between polls."""
        log('press the programming button on the device…')
        while True:
            devs = self.ia_read(1.5)
            if devs:
                break
            if cancelled():
                raise Cancelled('cancelled by user')
        if len(devs) > 1:
            raise RuntimeError(f'{len(devs)} devices in programming mode; '
                               'only one allowed')
        log(f'device found (current address {ia_str(devs[0])}), '
            f'writing {ia_str(ia)}')
        self.ia_write(ia)
        time.sleep(1.0)
        if ia not in self.ia_read():
            raise RuntimeError('address not accepted by device')
        log('address verified, reading descriptor')
        c = self.connect(ia)
        try:
            return c.descriptor()
        finally:
            c.disconnect()

    # -- broadcast (by serial number) --
    def ia_sn_read(self, serial, timeout=3.0):
        """Current individual address of the device with this 6-byte KNX
        serial number, or None when nothing answers. Plain broadcast, as ETS
        sends it even to a secured device (captures/knx-cheops-secure.pcap
        @35s: `03dc <serial>` -> `03dd <serial> <domain 2B> 0000` from the
        device's own address)."""
        self._drain()
        self._bcast(A_IND_ADDR_SN_READ, serial)
        t = self.wait(lambda t: t.group and t.apci10 == A_IND_ADDR_SN_RESP
                      and t.data[:6] == serial, timeout)
        return t.src if t else None

    def ia_sn_write(self, serial, ia, sec=None):
        """`sec`: a DataSecure session under the device's tool key, already
        synced on broadcast (see _sync_bcast). A secured device (security mode
        ON) silently drops the plain write — verified live on the Cheops."""
        apdu = serial + struct.pack('!H', ia) + b'\0' * 4  # serial | IA | reserved
        if sec is None:
            self._bcast(A_IND_ADDR_SN_WRITE, apdu)
        else:
            tpdu = sec.wrap(_apdu(A_IND_ADDR_SN_WRITE, apdu), 0, group=True)
            self.bus.send_cemi(cemi_ldata(0, tpdu, self.bus.ia, True))

    def _sync_bcast(self, sec, serial, timeout=3.0):
        """Data Secure sequence handshake on BROADCAST, the device picked by
        its serial number (its IA may be unknown / about to change) — what ETS
        does right after the serial read (captures/knx-cheops-secure.pcap
        @35.3s: `03f1 92 <seq> <serial> …` to 0/0/0, answered `03f1 93 …`
        from the device to 0/0/0)."""
        challenge, req = sec.sync_request(0, serial=serial, group=True)
        self._drain()
        self.bus.send_cemi(cemi_ldata(0, req, self.bus.ia, True))
        end = time.monotonic() + timeout
        while True:
            r = self.wait(lambda t: t.group and t.dst == 0
                          and t.apci10 == S_A_DATA, end - time.monotonic())
            if not r:
                raise TimeoutError('no SyncResponse on broadcast')
            try:
                dev_next, our_next = parse_sync_response(
                    sec.key, _apdu(r.apci10, r.data, r.tpci), r.src, 0,
                    challenge, group=True)
            except ValueError:
                continue
            sec.adopt_sync(dev_next, our_next)
            return r.src

    def assign_by_serial(self, serial, ia, tool_key=None, log=print):
        """Address assignment without the programming button: the device is
        picked by its KNX serial number (from the factory cert). `tool_key`
        for a secure-commissioned device — the write then goes Data Secure on
        broadcast. Returns the device descriptor."""
        log(f'looking for serial {serial.hex()}…')
        cur = self.ia_sn_read(serial)
        if cur is None:
            raise RuntimeError(f'no device with serial {serial.hex()} answered')
        if cur == ia:
            log(f'device already has {ia_str(ia)}')
        else:
            log(f'device found (current address {ia_str(cur)}), '
                f'writing {ia_str(ia)}' + (' (secured)' if tool_key else ''))
            sec = None
            if tool_key:
                sec = DataSecure(tool_key, self.bus.ia)
                self._sync_bcast(sec, serial)
            self.ia_sn_write(serial, ia, sec)
            time.sleep(1.0)
            if self.ia_sn_read(serial) != ia:
                raise RuntimeError('address not accepted by device'
                                   + ('' if tool_key else
                                      ' (secured device? needs its tool key)'))
            log('address verified, reading descriptor')
        c = self.connect(ia, sec=DataSecure(tool_key, self.bus.ia)
                         if tool_key else None)
        try:
            return c.descriptor()
        finally:
            c.disconnect()

    def connect(self, ia, tries=3, sec=None, co=True):
        """Open a CO connection, confirming it with a descriptor read; retries
        the T_Connect (some devices ignore one sent right after a disconnect).
        `co=False` is for a KNXnet/IP interface: ETS downloads to those
        connectionless (captures/knx-commission-secure.pcap), and the 732
        answers T_Connect + descriptor but never a CO A_Authorize.

        `sec` is a knxdatasec.DataSecure session (the device's tool key) for a
        secure-commissioned device, whose security mode makes it drop plaintext
        management. Each try gets a FRESH session — a device that has been used
        before holds a persisted sequence baseline and rejects Data-Secure frames
        until a SyncRequest re-establishes it, so sync() runs before the
        confirming descriptor read and a retry must not reuse a dead sequence.

        Still CONNECTION-ORIENTED, unlike knxsecure's commissioning path. That
        one is connectionless because its target is the interface's own IA over
        its own tunnel, which is the case the 732 refuses to ACK; a device out on
        the bus has no such quirk, and its plaintext download — CO, and
        hardware-proven — differs here only by the envelope."""
        last = None
        for _ in range(tries):
            c = Conn(self, ia, sec=sec.fresh() if sec else None, co=co)
            try:
                c.sync()                     # no-op on a plaintext Conn
                c.descriptor()
                return c
            except TimeoutError as e:
                last = e
                c.disconnect()
                time.sleep(1.0)
            except BaseException:
                c.disconnect()
                raise
        raise last or TimeoutError(f'no connection to {ia:#06x}')

    @staticmethod
    def _sec_session(dev, bus, log):
        """The Data Secure session for `dev`, or None when the project holds no
        tool key for it. The project is the only record of the key: a device we
        commissioned answers nothing but Data Secure, and there is no way to read
        the key back out of it."""
        key = (dev.sec or {}).get('tool_key')
        if not key:
            return None
        log('device is secure-commissioned — managing it over KNX Data Secure')
        return DataSecure(bytes.fromhex(key), src=bus.ia)

    def scan(self, first, last, log=print, cancelled=lambda: False,
             names=None):
        """Probe each IA in [first, last] with a short T_Connect + descriptor
        read; report responders. Skips the bus's own address."""
        hits = 0
        for a in range(first, last + 1):
            if cancelled():
                log('cancelled')
                return
            if a == self.bus.ia:
                log(f'{ia_str(a)}  (own address, skipped)')
                continue
            if a % 16 == 0:
                log(f'  … {ia_str(a)}')
            c = Conn(self, a, timeout=0.5, tries=1)
            try:
                mask = c.descriptor().hex()
                name = (names or {}).get(ia_str(a), 'unknown')
                log(f'{ia_str(a)}  mask {mask}  {name}')
                hits += 1
            except NoResponse:           # ACKed, but the descriptor was mute
                log(f'{ia_str(a)}  responds (no descriptor)')
                hits += 1
            except TimeoutError:
                pass                     # no T_ACK: nothing at this address
            finally:
                c.disconnect()
        log(f'{hits} device(s) found')

    LOAD_STATE = {0: 'Unloaded', 1: 'Loaded', 2: 'Loading', 3: 'Error'}

    def _build_images(self, project, dev, log=None):
        """(images, prog) for the device's programming model, dispatched on
        the knxprod mask — models can reuse LdCtrl step names with different
        semantics, so guard by mask, never by step."""
        prog = project.program(dev)
        if prog.mask in self._BIMM112_MASKS:
            return device_images(project, dev, log=log)  # full image from seed
        if prog.mask in self._SYSTEMB_MASKS:
            return device_images_b(project, dev, log=log)
        if prog.mask in self._BCU1_MASKS:
            return device_images_1(project, dev, log=log)
        raise NotImplementedError(
            f'{prog.mask}: implemented only for BimM112 (0705 family), '
            'System B (07B0 family) and BCU1 (0012 family) so far')

    def _open(self, dev, prog, log):
        """Connect to the device, check its descriptor against the knxprod
        mask, authorize. Caller must disconnect. This is the single choke point
        for program/verify/read_device, so it is also where a secure-commissioned
        device's tool key enters: every APDU on the returned Conn is then wrapped
        in S-A_Data."""
        sec = self._sec_session(dev, self.bus, log)
        c = self.connect(ia_int(dev.ia), sec=sec, co=not prog.tunnels)
        try:
            d = c.descriptor()
            self._descriptor = d.hex()
            if d.hex() != prog.mask[3:].lower():
                raise RuntimeError(f'device mask {d.hex()} does not match '
                                   f'the knxprod ({prog.mask})')
            try:
                log(f'descriptor {d.hex()}, authorize -> level {c.authorize()}')
            except NoResponse:
                # BCU1 predates mandatory access protection and plenty of those
                # devices simply do not answer A_Authorize; the later models do,
                # so a silent one there is a real fault. A secured device is a
                # second such case: tool access replaces the authorize key, and
                # whether it still answers A_Authorize is unpinned (no capture of
                # ETS downloading to a secured device yet) — so tolerate silence
                # rather than fail a download that would otherwise work. A
                # KNXnet/IP interface (the plain 732, over its own tunnel) is a
                # third: it answers everything but A_Authorize.
                if (prog.mask not in self._BCU1_MASKS and sec is None
                        and not prog.tunnels):
                    raise
                why = ('secured — tool access replaces it' if sec is not None
                       else 'interface' if prog.tunnels
                       else 'BCU1 without access protection')
                log(f'descriptor {d.hex()}, no A_Authorize — continuing '
                    f'unauthorized ({why})')
            return c
        except BaseException:
            c.disconnect()
            raise

    def program(self, project, dev, log=print):
        """Download the project config into `dev`. Segment geometry is
        assumed unchanged (same application flashed)."""
        imgs, prog = self._build_images(project, dev, log)
        run = (self._run_loadproc if prog.mask in self._BIMM112_MASKS else
               self._run_bcu1 if prog.mask in self._BCU1_MASKS else
               self._run_sysb)
        gsec = self._group_security(project, dev, prog, log)
        # only _run_sysb takes gsec, and _group_security has already refused
        # any other model that needs it
        extra = {'gsec': gsec} if gsec else {}
        c = self._open(dev, prog, log)
        try:
            run(c, prog, imgs, log, **extra)
        finally:
            c.disconnect()

    @staticmethod
    def _group_security(project, dev, prog, log):
        """The OT 17 group-comms tables to write during this download, or None
        when the device secures no group address. Raises rather than silently
        skipping on a model with no pinned choreography for it."""
        from . import knxsecure as ks
        g = ks.device_group_security(project, dev)
        if not g:
            return None                       # not a device this project secures
        if prog.mask not in Mgmt._SYSTEMB_MASKS:
            if g['keys']:
                raise NotImplementedError(
                    f'{prog.mask}: secured group communication is supported '
                    'only on System B devices — set those group addresses '
                    'to Off')
            return None                       # nothing to secure, nothing to clear
        # Run the transaction even with NO secured addresses: that is how a
        # device that used to have group keys gets them cleared. Skipping it
        # would leave the device expecting secured telegrams nobody sends.
        log(f'{len(g["keys"])} secured group address(es)'
            + (': ' + ', '.join(ga_str(x) for x in g['gas']) if g['gas']
               else ' — clearing the security object'))
        return g

    def verify(self, project, dev, log=print):
        """Compare the device's programmed state against the project without
        writing anything (no restart, tunnel stays up). Fast path: System B
        compares the PID 27 MCB length+CRC per LSM, 0705 reads the segments
        back; on any difference the memory is read and a semantic diff
        (links + params) is logged. Returns True when the device matches;
        self.last_verify holds the VerifyResult either way (also on error)."""
        self.last_verify = res = VerifyResult()
        self._descriptor = ''
        try:
            return self._verify(project, dev, res, log)
        except BaseException as e:
            res.outcome, res.error = 'error', str(e) or type(e).__name__
            res.descriptor = self._descriptor
            raise

    def _verify(self, project, dev, res, log):
        imgs, prog = self._build_images(project, dev, log)
        self._mcbs = {}
        c = self._open(dev, prog, log)
        res.descriptor = self._descriptor
        dev_imgs, bad = {}, []
        try:
            if prog.mask in self._SYSTEMB_MASKS:
                self._check_app_b(c, prog, sorted(imgs))
                res.app_id_ok = True
                bad = self._check_sysb(c, imgs, log)
                if bad:
                    dev_imgs = self._read_sysb(c, sorted(imgs), log)
            else:
                dev_imgs = self._read_mem(c, prog, imgs, log)
                if not dev_imgs:     # nothing comparable: never call that a match
                    raise RuntimeError(
                        'no programmed-config segments to compare (the knxprod '
                        'declares only RAM / non-config memory)')
                bad = [sid for sid in dev_imgs if dev_imgs[sid] != imgs[sid]]
                for sid in sorted(dev_imgs):
                    log(f'segment {sid.split("_")[-1]}: '
                        f'{"MISMATCH" if sid in bad else "ok"}')
        finally:
            c.disconnect()
        res.segments = _segment_report(imgs, dev_imgs, bad, self._mcbs)
        if not bad:
            res.outcome = 'match'
            log('device matches the project')
            return True
        res.outcome = 'mismatch'
        links, params = semantic_diff(project, dev,
                                      decode_device(project, dev, dev_imgs))
        res.links_differ, res.params_differ = sorted(links), sorted(params)
        if not diff_report(project, dev, decode_device(project, dev, dev_imgs),
                           log):
            # nothing attributable: show the raw byte diffs (typically param
            # bytes under branches gated by mem-less params — invisible to
            # the semantic decode on both sides)
            for seg in res.segments:
                if seg['match'] or not seg['first_diffs']:
                    continue
                name = seg['id']
                if seg['dev_len'] != seg['proj_len']:
                    name += f' (size dev {seg["dev_len"]}/proj {seg["proj_len"]})'
                log(f'  {name}: {seg["diff_count"]} byte(s) differ: ' + ' '.join(
                    f'@{o:#06x} dev {b:02x} proj {a:02x}'
                    for o, a, b in seg['first_diffs'])
                    + (' …' if seg['diff_count'] > 8 else ''))
        return False

    def read_device(self, project, dev, log=print):
        """Read the device's programmed state (read-only) and decode it:
        {'params': {pref_id: value}, 'links': {comobj number: [ga]}}."""
        imgs, prog = self._build_images(project, dev, log)
        c = self._open(dev, prog, log)
        try:
            if prog.mask in self._SYSTEMB_MASKS:
                self._check_app_b(c, prog, sorted(imgs))
                dev_imgs = self._read_sysb(c, sorted(imgs), log)
            else:
                dev_imgs = self._read_mem(c, prog, imgs, log)
        finally:
            c.disconnect()
        return recover_device(project, dev, dev_imgs, log)

    def _read_mem(self, c, prog, imgs, log):
        """Read the memory-mapped models' segments back (BimM112 / BCU1)."""
        return (self._read_bcu1 if prog.mask in self._BCU1_MASKS
                else self._read_0705)(c, prog, imgs, log)

    def _read_bcu1(self, c, prog, imgs, log):
        """Read the BCU1 EEPROM page(s) back -> {segment_id: bytes}. Bytes the
        knxprod mask reserves for the device are taken from the project image
        instead: the download never wrote them, so a difference there is the
        device's own identity, not a configuration fault."""
        out = {}
        for sid in sorted(imgs):
            s = prog.segments[sid]
            if not s.addr or not s.is_config:
                continue
            log(f'read {sid.split("_")[-1]} @{s.addr:#06x} ({len(imgs[sid])} B)')
            got = bytearray(c.mem_read_block(s.addr, len(imgs[sid])))
            for i in range(len(got)):
                if not app_owned(s, i):
                    got[i] = imgs[sid][i]
            out[sid] = bytes(got)
        return out

    def _check_app_b(self, c, prog, lsms):
        """System B: the application id (PID 13) must match the knxprod —
        decoding another application's memory would be garbage."""
        for oi in (o for o in lsms if o > 3):
            try:
                d = c.prop_read(oi, 13)
            except (TimeoutError, IOError):
                continue
            if len(d) < 5:
                continue
            man, app, ver = struct.unpack('!HHB', d[:5])
            if (man, app, ver) != (prog.manufacturer, prog.app_number,
                                   prog.app_version):
                raise RuntimeError(
                    f'device runs application {man:04x}:{app:04x} v{ver:02x},'
                    f' project expects {prog.manufacturer:04x}:'
                    f'{prog.app_number:04x} v{prog.app_version:02x}')

    def _sysb_mcbs(self, c, oi):
        """The LSM's memory control blocks: [(length, flags, crc)]."""
        mcbs = []
        for start in range(1, 5):
            try:
                d = c.prop_read(oi, 27, start=start)
            except (TimeoutError, IOError):
                break
            if len(d) < 8:
                break
            mcbs.append(struct.unpack('!IHH', d[:8]))
        return mcbs

    def _check_sysb(self, c, imgs, log):
        """Fast System B compare: load state + MCB length/CRC per LSM against
        the built images, no memory read. Returns the mismatched LSMs."""
        bad = []
        self._mcbs = {}                  # oi -> [(len, flags, crc)] for verify
        for oi in sorted(imgs):
            st = c.load_state(oi)
            if st != 1:
                log(f'LSM {oi}: {self.LOAD_STATE.get(st, st)} — MISMATCH')
                bad.append(oi)
                continue
            mcbs = self._sysb_mcbs(c, oi)
            self._mcbs[oi] = mcbs
            img, off, diff = imgs[oi], 0, False
            if sum(l for l, _, _ in mcbs) != len(img):
                diff = True
            else:
                for l, _, cc in mcbs:
                    if crc16(img[off:off + l]) != cc:
                        diff = True
                    off += l
            log(f'LSM {oi}: {"MISMATCH" if diff else "ok"} '
                f'({sum(l for l, _, _ in mcbs)} B, {len(mcbs)} MCB)')
            if diff:
                bad.append(oi)
        return bad

    def _read_sysb(self, c, lsms, log):
        """Read each LSM's memory (device-sized via its MCBs) -> {oi: bytes}."""
        out = {}
        for oi in lsms:
            base = struct.unpack('!I', c.prop_read(oi, 7))[0]
            size = sum(l for l, _, _ in self._sysb_mcbs(c, oi))
            log(f'read LSM {oi} @{base:#06x} ({size} B)')
            out[oi] = c.mem_ext_read_block(base, size)
        return out

    # interface object index of each table's load state machine (0705)
    _TABLE_OI = {'addrtab': 1, 'assoctab': 2, 'comobjtab': 3}

    def _read_0705(self, c, prog, imgs, log):
        """Read back the programmed-config segments -> {sid: bytes}. RAM
        (runtime state) and non-config scratch (device serial/identity) are
        skipped — they never match the project and aren't decodable.

        The address and association tables are read at the base the DEVICE
        reports (PID 7 table reference), not the knxprod segment address: some
        apps (ESYLUX) pack the association table right after the address table
        instead of at its own segment, and — critically — this device returns
        empty reads that start mid-table, so a chunked read spanning the
        addr/assoc boundary corrupts everything after it. Reading each table
        from its own base sidesteps both."""
        out = {}
        table_base = {}
        for attr, oi in self._TABLE_OI.items():
            seg = getattr(prog, attr)
            if not seg:
                continue
            try:
                d = c.prop_read(oi, 7)
                if len(d) >= 2:
                    table_base[seg[0]] = int.from_bytes(d[-2:], 'big')
            except (TimeoutError, IOError):
                pass
        for sid in sorted(imgs):
            s = prog.segments[sid]
            if not s.addr or not s.is_config:
                continue
            base = table_base.get(sid, s.addr)
            if prog.dyntab and sid in (prog.addrtab[0], prog.assoctab[0]):
                # packed tables: the device's count decides the length, not
                # the project's (an empty project would read 3 bytes)
                size = 1 + 2 * c.mem_read_block(base, 1)[0]
                log(f'read {sid.split("_")[-1]} @{base:#06x} ({size} B)')
                out[sid] = c.mem_read_block(base, size)
                continue
            log(f'read {sid.split("_")[-1]} @{base:#06x} ({len(imgs[sid])} B)')
            got = bytearray(imgs[sid])          # unwritten bytes: don't care
            for i, n in written_runs(prog, sid, imgs[sid]):
                got[i:i + n] = c.mem_read_block(base + i, n)
            out[sid] = bytes(got)
        return out

    # -- load-procedure interpreter (knxprod <LoadProcedures> LdCtrl* steps) --
    LOAD_EVENT = {'unload': 4, 'load': 1, 'completed': 2}   # PID 5 record events

    # masks per management model (KNX master); only BimM112 is verified
    _BIMM112_MASKS = {'MV-0700', 'MV-0701', 'MV-0705', 'MV-1900', 'MV-2705',
                      'MV-5705'}
    _SYSTEMB_MASKS = {'MV-07B0', 'MV-17B0', 'MV-27B0', 'MV-2920', 'MV-57B0'}
    # BCU1 DEVICE masks, TP (0010-0013) and PL (1011-1013); all seven share one
    # identical default load procedure. The 0900/091A line couplers are Bcu1
    # too but theirs writes filter tables in separate address spaces, so they
    # are deliberately left out — _run_bcu1 would reject them anyway.
    _BCU1_MASKS = {'MV-0010', 'MV-0011', 'MV-0012', 'MV-0013',
                   'MV-1011', 'MV-1012', 'MV-1013'}

    def _load_ctrl(self, c, oi, key, want, log):
        """BimM112 load control: PID 5, 10-byte [event]+9 zeros; verify state."""
        c.prop_write(oi, 5, bytes([self.LOAD_EVENT[key]] + [0] * 9))
        st = c.load_state(oi)
        log(f'LSM {oi}: {key} -> {self.LOAD_STATE.get(st, st)}')
        if st != want:
            raise RuntimeError(f'LSM {oi} {key} failed '
                               f'({self.LOAD_STATE.get(st, st)})')

    def _alloc(self, c, oi, rec, what, log):
        """BimM112 additional load control: a 10-byte event-3 record on PID 5
        (segment allocation, task segment, task pointers). The LSM must stay
        in Loading. Layouts per bcusdk common/loadimage.cpp — the BCU2 SDK
        that really programs these; there is no ETS capture of a 0705 download."""
        c.prop_write(oi, 5, rec)
        st = c.load_state(oi)
        log(f'LSM {oi}: {what} {rec.hex()} -> {self.LOAD_STATE.get(st, st)}')
        if st != 2:
            raise RuntimeError(f'LSM {oi} {what} refused '
                               f'({self.LOAD_STATE.get(st, st)})')

    def _placement(self, prog, imgs):
        """{segment_id: (addr, size)} the download uses. Knxprod values, except
        DynamicTableManagement: ETS then packs the association table right
        behind the used address table (the device reports that base in PID 7),
        both sized to the actual table."""
        place = {sid: (s.addr, s.size) for sid, s in prog.segments.items() if s.addr}
        if prog.dyntab and prog.addrtab and prog.assoctab:
            at, st = prog.addrtab[0], prog.assoctab[0]
            if at in imgs and st in imgs:
                base = prog.segments[at].addr
                place[at] = (base, len(imgs[at]))
                place[st] = (base + len(imgs[at]), len(imgs[st]))
        return place

    def _run_loadproc(self, c, prog, imgs, log):
        # BimM112 is LoadProcedureStyle="ProductProcedure": the knxprod carries
        # the whole sequence, so procedure() hands back its steps unspliced.
        steps = prog.procedure('Load', 'ap1')
        if not steps:                    # would silently "succeed" writing nothing
            raise RuntimeError('knxprod has no load procedure')
        addr2seg = {s.addr: sid for sid, s in prog.segments.items() if s.addr}
        place = self._placement(prog, imgs)
        u16 = lambda k: struct.pack('!H', int(a.get(k, 0)))
        for n, (tag, a) in enumerate(steps):
            oi = int(a.get('LsmIdx', 0))
            if tag in ('LdCtrlConnect', 'LdCtrlDisconnect', 'LdCtrlCompareProp'):
                continue                  # connect/authorize handled in program()
            elif tag == 'LdCtrlUnload':
                self._load_ctrl(c, oi, 'unload', 0, log)
            elif tag == 'LdCtrlLoad':
                self._load_ctrl(c, oi, 'load', 2, log)
            elif tag == 'LdCtrlLoadCompleted':
                self._load_ctrl(c, oi, 'completed', 1, log)
            elif tag == 'LdCtrlAbsSegment':
                sid = addr2seg.get(int(a['Address']))
                addr, size = place.get(sid, (int(a['Address']), int(a['Size'])))
                rec = (bytes([3, int(a.get('SegType', 0))]) + struct.pack('!HH', addr, size)
                       + bytes([int(a.get('Access', 0)), int(a.get('MemType', 0)),
                                int(a.get('SegFlags', 0)), 0]))
                self._alloc(c, oi, rec, 'alloc', log)
                if sid and sid in imgs:            # RAM / unchanged segs: skip
                    for i, n in written_runs(prog, sid, imgs[sid]):
                        log(f'  write {sid.split("_")[-1]} @{addr + i:#06x} ({n} B)')
                        c.mem_write_block(addr + i, imgs[sid][i:i + n])
            elif tag == 'LdCtrlTaskSegment':
                addr = int(a['Address'])
                sid = addr2seg.get(addr)             # a placed table moved with it
                addr = place.get(sid, (addr,))[0]
                rec = (bytes([3, 2]) + struct.pack('!H', addr) + bytes([prog.pei_type])
                       + struct.pack('!HH', prog.manufacturer, prog.app_number)
                       + bytes([prog.app_version]))
                self._alloc(c, oi, rec, 'task segment', log)
            elif tag == 'LdCtrlTaskPtr':
                rec = bytes([3, 3]) + u16('InitPtr') + u16('SavePtr') + u16('SerialPtr') + b'\0\0'
                self._alloc(c, oi, rec, 'task ptr', log)
            elif tag == 'LdCtrlTaskCtrl1':
                rec = bytes([3, 4]) + u16('Address') + bytes([int(a.get('Count', 0))]) + bytes(5)
                self._alloc(c, oi, rec, 'task ctrl1', log)
            elif tag == 'LdCtrlTaskCtrl2':
                rec = bytes([3, 5]) + u16('Callback') + u16('Address') + u16('Seg0') + u16('Seg1')
                self._alloc(c, oi, rec, 'task ctrl2', log)
            elif tag == 'LdCtrlRestart':
                log('restart')
                c.restart()
                # A_Restart drops the transport connection; whatever follows
                # (the ESYLUX has a TaskSegment+Load on a manufacturer object 5
                # that has no load state at all) cannot be delivered.
                rest = [t for t, _ in steps[n + 1:] if t != 'LdCtrlDisconnect']
                if rest:
                    log(f'  {len(rest)} step(s) after restart skipped: {", ".join(rest)}')
                break
            else:
                raise NotImplementedError(f'unsupported load step {tag}')

    # -- BCU1 download (mask 0012 family) --
    # Driven by the mask's default load procedure out of knx_master.xml: BCU1
    # knxprods declare LoadProcedureStyle="DefaultProcedure" and ship no
    # <LoadProcedures> of their own. Every step is a plain A_MemoryWrite; the
    # procedure brackets the writes by stopping the application (RunError = 0)
    # and shrinking the address table to its own IA, so a half-written device
    # cannot act on group telegrams, then restores both and restarts.

    def _seg_at(self, prog, imgs, addr, size):
        """(segment_id, Segment) whose image covers [addr, addr+size), or None."""
        for sid, s in prog.segments.items():
            if (sid in imgs and s.addr
                    and s.addr <= addr and addr + size <= s.addr + len(imgs[sid])):
                return sid, s
        return None

    def _run_bcu1(self, c, prog, imgs, log):
        steps = prog.procedure('Load', 'all')   # nothing to splice: no fragments
        if not steps:
            raise RuntimeError(
                f'{prog.mask}: the product database ships no knx_master.xml '
                'default load procedure, so the download sequence is unknown')
        for tag, a in steps:
            if tag in ('LdCtrlConnect', 'LdCtrlDisconnect'):
                continue          # connect + authorize are done by program()
            elif tag == 'LdCtrlSetControlVariable':
                continue          # EnableVerifyOnWriteDirect: mem_write verifies
            elif tag == 'LdCtrlLoadImageMem':
                continue          # declares an address as image-backed; the
                                  # procedure writes it explicitly further down
            elif tag == 'LdCtrlWriteMem':
                self._bcu1_write(c, prog, imgs, a, log)
            elif tag == 'LdCtrlRestart':
                log('restart')
                c.restart()
            else:
                raise NotImplementedError(f'unsupported BCU1 load step {tag}')

    def _bcu1_write(self, c, prog, imgs, a, log):
        """One LdCtrlWriteMem step: either literal InlineData (the procedure's
        own bracketing writes and RAM clears) or a run of the segment image."""
        space = a.get('AddressSpace', 'StandardMemory')
        if space != 'StandardMemory':
            raise NotImplementedError(
                f'BCU1 load step writes {space} memory (line-coupler filter '
                'table) — not implemented')
        addr, size = int(a['Address']), int(a['Size'])
        if a.get('InlineData'):
            data = bytes.fromhex(a['InlineData'])
            if len(data) != size:
                raise RuntimeError(
                    f'load step at {addr:#06x} declares {size} B but carries '
                    f'{len(data)} B of InlineData')
            log(f'  write {addr:#06x} ({len(data)} B) {data.hex()}')
            c.mem_write_block(addr, data)
            return
        found = self._seg_at(prog, imgs, addr, size)
        if not found:
            raise RuntimeError(f'load step writes {size} B at {addr:#06x}, '
                               'which no segment image covers')
        sid, s = found
        img, off = imgs[sid], addr - s.addr
        for i, n in mask_runs(s, off, size):
            log(f'  write {s.addr + i:#06x} ({n} B)')
            c.mem_write_block(s.addr + i, img[i:i + n])

    # -- System B download (mask 07B0 family) --
    # A System B knxprod carries only the product-specific FRAGMENTS of its
    # load procedure (<LoadProcedure MergeId="2"/"4"/"7">); the surrounding
    # unload/load/allocate/write/complete scaffolding is the KNX-standard
    # "System B default load procedure", which lives in the knx_master.xml
    # every knxprod ships. Program.procedure() splices the two, and the walk
    # below maps each step to the service it means on this model — a mapping
    # that is in no file and came from an ETS capture of a real 07B0 download
    # (captures/knx-systemb.pcap, replayed in tests/test_sysb.py).
    #
    # LSMs: 1=addr table 2=assoc 3=group objects 4=application 5=PEI.

    def _sysb_alloc(self, c, oi, size, mode, log):
        """PID 5 event-3 record: allocate `size` bytes on that LSM."""
        c.prop_write(oi, 5, bytes([3, 0x0b]) + struct.pack('!I', size)
                     + bytes([mode, 0, 0, 0]))
        st = c.load_state(oi)
        if st != 2:
            raise RuntimeError(f'LSM {oi} allocate failed '
                               f'({self.LOAD_STATE.get(st, st)})')
        log(f'LSM {oi}: allocated {size} B')

    def _sysb_steps(self, prog, imgs):
        """(subtype, merged steps) for a full download of these images. 'ap1'
        is the single-application-program procedure — what every product here
        uses; 'all' additionally loads LSM 5, for two-application hardware."""
        sub = 'all' if any(oi > 4 for oi in imgs) else 'ap1'
        steps = prog.procedure('Load', sub)
        if not steps:
            raise RuntimeError(
                f'{prog.mask}: the product database ships no knx_master.xml '
                f'Load/{sub} procedure, so the download sequence is unknown')
        # every step that reaches into `imgs` must have one, or the walk dies
        # with an opaque KeyError halfway through a half-unloaded device
        missing = {int(a.get('LsmIdx', a.get('ObjIdx', 0))) for t, a in steps
                   if t in ('LdCtrlLoad', 'LdCtrlRelSegment',
                            'LdCtrlWriteRelMem', 'LdCtrlLoadImageProp')}
        missing -= set(imgs)
        if missing:
            raise RuntimeError(f'the Load/{sub} procedure needs LSM(s) '
                               f'{sorted(missing)} but no image was built '
                               'for them')
        return sub, steps

    def _run_sysb(self, c, prog, imgs, log, gsec=None):
        sub, steps = self._sysb_steps(prog, imgs)
        log(f'System B Load/{sub}: {len(steps)} steps')
        tolerate = False       # inside an LdCtrlMapError -> success bracket
        mcbs = {}              # oi -> PID 27 records written, for the verify
        gsec_unloaded = False
        for tag, a in steps:
            oi = int(a.get('LsmIdx', a.get('ObjIdx', 0)))
            if tag in ('LdCtrlConnect', 'LdCtrlDisconnect'):
                continue       # connect + authorize are done by program()
            elif tag == 'LdCtrlMapError':
                # the masks use this only to turn "LSM does not exist"
                # (0xC0000E08) into success, bracketing the PEI unload
                tolerate = a.get('MappedError') == '0'
            elif tag == 'LdCtrlUnload':
                try:
                    self._load_ctrl(c, oi, 'unload', 0, log)
                except (TimeoutError, RuntimeError):
                    if not tolerate:
                        raise
                    log(f'LSM {oi}: no answer, skipped')
            elif tag == 'LdCtrlLoad':
                # ETS unloads the security object with the others, before the
                # first load — see knxsecure.unload_group_security for why the
                # tables must start empty rather than be overwritten in place
                if gsec is not None and not gsec_unloaded:
                    from . import knxsecure as ks
                    ks.unload_group_security(c, log)
                    gsec_unloaded = True
                self._load_ctrl(c, oi, 'load', 2, log)
            elif tag == 'LdCtrlRelSegment':
                # Size in the procedure is a placeholder (the master says 2 for
                # every table); the real allocation is the built image.
                self._sysb_alloc(c, oi, len(imgs[oi]), int(a.get('Mode', 0)),
                                 log)
            elif tag == 'LdCtrlWriteProp':
                pid = int(a['PropId'])
                if pid == 13:            # InlineData is 5 placeholder zeros
                    data = struct.pack('!HHB', prog.manufacturer,
                                       prog.app_number, prog.app_version)
                else:                    # PID 27 memory control blocks
                    data = bytes.fromhex(a['InlineData'])[:8]
                    mcbs.setdefault(oi, []).append((tag, a))
                c.prop_write(oi, pid, data,
                             start=int(a.get('StartElement', 1)))
            elif tag == 'LdCtrlWriteRelMem':
                if int(a.get('Offset', 0)):
                    raise NotImplementedError(
                        f'LSM {oi}: load procedure writes at offset '
                        f'{a["Offset"]}, only whole-image writes are supported')
                # Size is a 1 MB maximum, and the address is not in the data at
                # all — the device reports it as its PID 7 table reference.
                base = struct.unpack('!I', c.prop_read(oi, 7))[0]
                log(f'  write LSM {oi} @{base:#06x} ({len(imgs[oi])} B)')
                c.mem_ext_write_block(base, imgs[oi])
            elif tag == 'LdCtrlLoadCompleted':
                # The secured group-comms tables go in here: ETS writes them
                # after the last memory write and before anything is marked
                # LoadCompleted, in their own OT 17 load transaction
                # (captures/knx-cheops-secure.pcap).
                if gsec is not None:
                    from . import knxsecure as ks
                    ks.write_group_security(c, gsec, log)
                    gsec = None
                self._load_ctrl(c, oi, 'completed', 1, log)
            elif tag == 'LdCtrlLoadImageProp':
                self._sysb_verify(c, oi, imgs[oi], mcbs.get(oi, []), log)
            elif tag == 'LdCtrlRestart':
                log('restart')
                c.restart_master()      # System B: master reset, not A_Restart
            else:
                raise NotImplementedError(f'unsupported System B load step {tag}')

    def _sysb_verify(self, c, oi, img, steps, log):
        """Read the memory control blocks (PID 27) back and compare length +
        CRC-16 against the image, split per the knxprod's MCB records."""
        sizes = [struct.unpack('!I', bytes.fromhex(a['InlineData'])[:4])[0]
                 for t, a in steps
                 if t == 'LdCtrlWriteProp' and int(a['PropId']) == 27]
        sizes = sizes or [len(img)]
        off = 0
        for i, size in enumerate(sizes):
            d = c.prop_read(oi, 27, start=i + 1)
            if len(d) < 8:
                raise RuntimeError(f'LSM {oi} verify failed: MCB {i + 1} '
                                   f'read returned {len(d)} bytes')
            rlen, _, rcrc = struct.unpack('!IHH', d[:8])
            want = crc16(img[off:off + size])
            if (rlen, rcrc) != (size, want):
                raise RuntimeError(
                    f'LSM {oi} verify failed: MCB {i + 1} len {rlen}/{size} '
                    f'crc {rcrc:04x}/{want:04x}')
            off += size
        log(f'LSM {oi}: verified ({len(sizes)} MCB)')


class Conn:
    """A connection-oriented (T_Connect) session to one device. Sequenced,
    with T_ACK handling and retransmit. Runs on the caller's thread."""

    def __init__(self, mgmt, ia, timeout=3.0, tries=3, sec=None, co=True):
        self.m = mgmt
        self.ia = ia
        self.timeout = timeout
        self.tries = tries
        self.sec = sec               # DataSecure session, or None for plaintext
        self.co = co                 # connection-oriented; False = connectionless
        self.seq_out = 0
        self.m._drain()
        if co:
            self._send(bytes([T_CONNECT]))

    def _send(self, tpdu):
        self.m.bus.send_cemi(cemi_ldata(self.ia, tpdu, self.m.bus.ia, group=False))

    def disconnect(self):
        if not self.co:
            return
        try:
            self._send(bytes([T_DISCONNECT]))
        except OSError:
            pass

    def _from_peer(self, t):
        return not t.group and t.src == self.ia and not t.confirm

    def sync(self, serial=b'\0' * 6):
        """KNX Data Secure sequence handshake: send a SyncRequest and adopt the
        device's SyncResponse sequence numbers. A device that has been used before
        (a persisted sequence baseline) rejects Data-Secure frames until synced —
        so do this once after connecting, before any secured read/write. No-op on
        a plaintext conn."""
        if self.sec is None:
            return
        tp = T_DATA | (self.seq_out << 2) if self.co else 0x00
        challenge, req = self.sec.sync_request(self.ia, serial=serial,
                                               base_tpci=tp)
        if self.co:
            ack = None
            for _ in range(self.tries):
                self._send(req)
                ack = self.m.wait(
                    lambda t: self._from_peer(t)
                    and t.tpci == (T_ACK | (self.seq_out << 2)), self.timeout)
                if ack:
                    break
            if not ack:
                raise TimeoutError(f'no T_ACK for SyncRequest from {self.ia:#06x}')
            self.seq_out = (self.seq_out + 1) & 0x0F
        else:
            self._send(req)
        deadline = time.monotonic() + self.timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f'no SyncResponse from {self.ia:#06x}')
            r = self.m.wait(
                lambda t: self._from_peer(t) and t.apci10 is not None
                and _apci_match(t.apci10, S_A_DATA), left)
            if not r:
                raise TimeoutError(f'no SyncResponse from {self.ia:#06x}')
            if self.co:
                self._send(bytes([T_ACK | (((r.tpci >> 2) & 0x0F) << 2)]))
            try:
                dev_next, our_next = parse_sync_response(
                    self.sec.key, _apdu(r.apci10, r.data, r.tpci), r.src,
                    self.m.bus.ia, challenge)
            except ValueError:
                continue      # stale SyncResponse to an earlier challenge — skip
            self.sec.adopt_sync(dev_next, our_next)
            return

    def request(self, apci10, payload=b'', resp=None, rekey=None, match=None):
        """Send a numbered APDU, await its T_ACK (retransmitting), then—if
        `resp` is given—await the peer's response APDU and ACK it. Returns the
        response payload (bytes after the 2 APCI octets), or None. `match`
        filters response payloads (a stale answer to an earlier request is
        skipped, not returned).

        Connectionless (co=False) has no T_ACK, so a lost frame can only be
        recovered by sending again: the request is resent up to `tries` times
        while no response arrives — re-wrapped each time under Data Secure,
        since a resent secured APDU is a replay the device drops.

        `rekey` (Data-Secure only): a new tool key to switch to AFTER our request
        is sent but BEFORE the response is unwrapped. Writing the tool key makes
        the device answer under the new key, so the request is wrapped with the
        old key and its response is unwrapped (and consumed) with the new one."""
        tp = T_DATA | (self.seq_out << 2) if self.co else 0x00
        for attempt in range(1 if self.co or rekey else self.tries):
            if self.sec is None:
                tpdu = _apdu(apci10, payload, tp)
                want = resp
            else:                    # wrap the plain APDU in S-A_Data (tool key)
                tpdu = self.sec.wrap(_apdu(apci10, payload), self.ia, base_tpci=tp)
                want = S_A_DATA if resp is not None else None
            if self.co:
                ack = None
                for _ in range(self.tries):
                    self._send(tpdu)
                    ack = self.m.wait(
                        lambda t: self._from_peer(t)
                        and t.tpci == (T_ACK | (self.seq_out << 2)), self.timeout)
                    if ack:
                        break
                if not ack:
                    raise TimeoutError(f'no T_ACK from {self.ia:#06x}')
                self.seq_out = (self.seq_out + 1) & 0x0F
            else:
                self._send(tpdu)
            if rekey is not None and self.sec is not None:
                self.sec.rekey(rekey)
            if resp is None:
                return None
            try:
                return self._response(want, resp, match)
            except NoResponse:
                if self.co or attempt == self.tries - 1:
                    raise

    def _response(self, want, resp, match):
        # A secured response only matches S_A_DATA at the frame level, so a stale
        # earlier response (e.g. a mode-read echo) can arrive first. Loop until the
        # UNWRAPPED inner APCI is the one we want, skipping and ACKing the rest,
        # until the deadline. Replay-checking is off: a response to our own
        # just-sent request is not a replay threat (the device enforces replay on
        # what WE send), and the 732 re-sends stale frames that would trip it.
        deadline = time.monotonic() + self.timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise NoResponse(f'no response {resp:#x} from {self.ia:#06x}')
            r = self.m.wait(
                lambda t: self._from_peer(t) and t.apci10 is not None
                and _apci_match(t.apci10, want), left)
            if not r:
                raise NoResponse(f'no response {resp:#x} from {self.ia:#06x}')
            if self.co:
                self._send(bytes([T_ACK | (((r.tpci >> 2) & 0x0F) << 2)]))
            if self.sec is None:
                data = r.data
            else:
                try:
                    inner = self.sec.unwrap(_apdu(r.apci10, r.data, r.tpci),
                                            r.src, self.m.bus.ia, check_replay=False)
                except ValueError:
                    # e.g. a retransmitted SyncResponse (the 732 re-sends it even
                    # after our T_ACK) — not our response; ACKed above, skip it.
                    continue
                if not _apci_match(((inner[0] & 0x03) << 8) | inner[1], resp):
                    continue
                data = inner[2:]
            if match is None or match(data):
                return data

    # -- services --
    def descriptor(self, kind=0):
        """e.g. b'\\x07\\x05' for mask 0705."""
        return self.request(A_DESC_READ | kind, resp=A_DESC_RESP)

    def mem_read(self, addr, n):
        d = self.request(A_MEM_READ | n, struct.pack('!H', addr), A_MEM_RESP)
        return d[2:2 + n]             # strip echoed address

    def mem_write(self, addr, data, verify=True):
        self.request(A_MEM_WRITE | len(data), struct.pack('!H', addr) + data)
        if verify and self.mem_read(addr, len(data)) != data:
            raise IOError(f'memory verify failed at {addr:#06x}')

    def _prop(self, apci, obj, pid, count, start, data=b''):
        # the response echoes obj/pid/start (count is 0 on an error response),
        # which tells it apart from a late answer to an earlier request —
        # read_array walks one pid in chunks, so obj+pid alone would not
        head = struct.pack('!BBH', obj, pid, (count << 12) | start)
        d = self.request(apci, head + data, A_PROP_RESP, match=lambda d: (
            len(d) >= 4 and d[:2] == head[:2]
            and int.from_bytes(d[2:4], 'big') & 0xFFF == start))
        return d[4:]                  # b'' on an error response

    def prop_read(self, obj, pid, count=1, start=1):
        return self._prop(A_PROP_READ, obj, pid, count, start)

    def prop_write(self, obj, pid, data, count=1, start=1):
        return self._prop(A_PROP_WRITE, obj, pid, count, start, data)

    def load_state(self, oi):
        d = self.prop_read(oi, 5)     # PID_LOAD_STATE_CONTROL
        return d[0] if d else None

    def authorize(self, key=0xFFFFFFFF):
        """A_Authorize with a 4-byte key; returns the granted access level
        (0 = highest). ETS authorizes before writing to a device."""
        d = self.request(A_AUTH_REQ, b'\x00' + struct.pack('!I', key), A_AUTH_RESP)
        return d[0] if d else None

    # KNX Data Secure grows every APDU by a fixed 13 octets: the S-A_Data APCI
    # pair (2) + SCF (1) + sequence (6) + MAC (4). ETS keeps its plaintext
    # download TPDUs at 56 octets — 50 payload bytes plus the 6-byte
    # A_MemoryExtWrite header (all 468 writes in captures/knx-gira.pcap). It
    # holds the OUTER TPDU to that same budget when the download is secured,
    # shrinking the payload instead of sending a bigger frame.
    #
    # PINNED: captures/knx-cheops-secure.pcap (ETS securing + downloading the
    # Cheops S) writes 42 of its 57 memory chunks at exactly n=37 = 50 - 13, and
    # never more. So this is ETS's own number, not a safety margin.
    SEC_OVERHEAD = 13

    def _chunk(self, chunk):
        """`chunk` as-is on a plaintext Conn; shrunk by the Data Secure overhead
        on a secured one, so the wrapped TPDU stays within the same budget the
        plaintext download is pinned to — 50 -> 37, which is what ETS does.
        Never returns less than 1."""
        if self.sec is None:
            return chunk
        return max(1, chunk - self.SEC_OVERHEAD)

    def mem_write_block(self, addr, data, chunk=12, verify=True):
        """Chunked write. `verify` reads every chunk back, which doubles the
        traffic — the download keeps it on, callers that know better can not."""
        chunk = self._chunk(chunk)
        for i in range(0, len(data), chunk):
            self.mem_write(addr + i, data[i:i + chunk], verify)

    def restart(self):
        try:
            self.request(A_RESTART)   # device ACKs, then reboots
        except (TimeoutError, ConnectionError, OSError):
            pass                      # some devices reboot without ACK, and a
                                      # restart can drop the tunnel we rode in on

    def mem_read_block(self, addr, size, chunk=12):
        chunk = self._chunk(chunk)           # the RESPONSE is secured too
        out = b''
        while size > 0:
            n = min(chunk, size)
            out += self.mem_read(addr, n)
            addr += n
            size -= n
        return out

    # -- extended memory (System B): 24-bit address, [len:1][addr:3] APDU --
    def mem_ext_read(self, addr, n):
        d = self.request(A_MEMX_READ, bytes([n]) + addr.to_bytes(3, 'big'),
                         A_MEMX_READ_RESP)
        if d[0]:
            raise IOError(f'ext memory read failed at {addr:#x} (rc {d[0]})')
        return d[4:4 + n]             # strip rc + echoed address

    def mem_ext_write(self, addr, data):
        d = self.request(A_MEMX_WRITE,
                         bytes([len(data)]) + addr.to_bytes(3, 'big') + data,
                         A_MEMX_WRITE_RESP)
        if d[0]:
            raise IOError(f'ext memory write failed at {addr:#x} (rc {d[0]})')

    def mem_ext_write_block(self, addr, data, chunk=50):
        chunk = self._chunk(chunk)
        for i in range(0, len(data), chunk):
            self.mem_ext_write(addr + i, data[i:i + chunk])

    def mem_ext_read_block(self, addr, size, chunk=50):
        chunk = self._chunk(chunk)           # the RESPONSE is secured too
        return b''.join(self.mem_ext_read(addr + i, min(chunk, size - i))
                        for i in range(0, size, chunk))

    def restart_master(self, erase=1):
        """A_Restart master mode (System B): erase code 1 = confirmed
        restart. The device answers, then reboots."""
        try:
            self.request(A_RESTART_MASTER, bytes([erase, 0]), A_RESTART_RESP)
        except (TimeoutError, ConnectionError):
            pass                      # some devices reboot without answering


# ---- device compatibility ------------------------------------------------

def unsupported_reason(prog):
    """Why Baccata cannot fully program `prog`, or None when it can. Checked
    when adding a device, so a project only holds devices we can round-trip
    (program AND read back) without ETS.

    - An ETS plugin (<Extension EtsUiPlugin/EtsDataHandler>): the product is
      configured by a manufacturer DLL shipped in the knxprod, not by the
      parameters the XML declares. Nothing to reproduce; blocked for good.
    - Unknown programming model (mask): no download procedure implemented.
    - A BCU1 mask whose product database carries no default load procedure:
      those products describe the download nowhere else, so there is nothing
      to run."""
    if prog.plugin:
        return (f'the product is configured by a manufacturer ETS plugin '
                f'({prog.plugin}); its logic is not in the product database')
    if (prog.mask not in Mgmt._BIMM112_MASKS
            and prog.mask not in Mgmt._SYSTEMB_MASKS
            and prog.mask not in Mgmt._BCU1_MASKS):
        model = f' ({prog.model})' if prog.model else ''
        return f'programming model {prog.mask}{model} is not supported yet'
    # BCU1 and System B are both driven by the mask's default procedure in
    # knx_master.xml (System B splices the knxprod's fragments into it). No
    # procedure, no download sequence — refuse now rather than mid-download.
    if ((prog.mask in Mgmt._BCU1_MASKS or prog.mask in Mgmt._SYSTEMB_MASKS)
            and not prog.procedure('Load', 'ap1')
            and not prog.procedure('Load', 'all')):
        return (f'{prog.mask}: the product database ships no knx_master.xml '
                'Load procedure, so the download sequence is unknown')
    return None

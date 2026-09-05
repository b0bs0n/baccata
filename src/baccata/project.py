"""Baccata project: a folder with project.json + catalog/ of verbatim knxprods.

Devices are a plain list with arbitrary tags. Group addresses are stored as
16-bit ints, displayed 3-level (main/middle/sub). Device parameter values
store only deviations from product defaults.
"""
import ast, fnmatch, hashlib, json, operator, re
import xml.etree.ElementTree as ET
from pathlib import Path

from .knxip import ia_parts, ga_str
from .knxprod import KnxProd, CRef, PRef, iter_visible


def ga_int(s):
    m, mid, sub = (int(x) for x in s.strip().split('/'))
    if not (0 <= m < 32 and 0 <= mid < 8 and 0 <= sub < 256):
        raise ValueError(f'group address out of range: {s}')
    return m << 11 | mid << 8 | sub


_TMPL_RE = re.compile(r'\{([^}]+)\}')

# arithmetic only — no names but the ones passed in, no calls, no attributes.
# (`eval` with an empty __builtins__ is not a sandbox: {().__class__...} walks
# straight back out to the interpreter.)
_BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub,
           ast.Mult: operator.mul, ast.Div: operator.truediv,
           ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
           ast.Pow: operator.pow}
_UNOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _arith(node, names):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
        a, b = _arith(node.left, names), _arith(node.right, names)
        if isinstance(node.op, ast.Pow) and (abs(a) > 1e6 or abs(b) > 64):
            raise ValueError('exponent too large')   # {9**9**9} would hang
        return _BINOPS[type(node.op)](a, b)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNOPS:
        return _UNOPS[type(node.op)](_arith(node.operand, names))
    raise ValueError('only + - * / // % ** and '
                     + ', '.join(sorted(names)) + ' are allowed')


def tmpl_eval(text, **names):
    """Replace every {expr} in text with the evaluated math expression;
    `names` are the variables available inside {}."""
    def ev(m):
        try:
            return str(_arith(ast.parse(m.group(1), mode='eval').body, names))
        except Exception as e:
            raise ValueError(f'bad expression {{{m.group(1)}}}: {e}')
    return _TMPL_RE.sub(ev, text)


def expand_addr_template(pattern, olds, sep):
    """Address template over old addresses, e.g. '2/{n+2}/{x+3}'. Inside {}
    any math expression; n = row number (1-based), x = the old value of the
    part at that position. Returns new address strings; raises ValueError."""
    parts = pattern.strip().split(sep)
    width = len(olds[0].split(sep)) if olds else len(parts)
    if len(parts) != width:
        raise ValueError(f'template has {len(parts)} parts, addresses have '
                         f'{width}: {pattern}')
    out = []
    for n, old in enumerate(olds, 1):
        oldp = old.split(sep)
        segs = []
        for p, o in zip(parts, oldp, strict=True):   # ValueError on a ragged row
            if '{' in p:
                try:
                    x = int(o)
                except ValueError:
                    raise ValueError(f'x has no value for row {old!r}')
                p = tmpl_eval(p, n=n, x=x)
            try:
                segs.append(str(int(p)))
            except ValueError:
                raise ValueError(f'not a number: {p!r}')
        out.append(sep.join(segs))
    return out


def match_tag_expr(tagset, expr):
    """Boolean tag filter. '|' = OR of groups, '&' = AND within a group;
    each term is a case-insensitive substring match against `tagset`
    (already lowercased). Empty groups are ignored. e.g. 'EG & light | OG'."""
    for group in expr.split('|'):
        terms = [t.strip().lower() for t in group.split('&') if t.strip()]
        if terms and all(any(term in tag for tag in tagset) for term in terms):
            return True
    return False


class Device:
    def __init__(self, d):
        self.id = d['id']
        self.name = d['name']
        self.tags = d.get('tags', [])
        self.product = d['product']      # filename in catalog/
        self.variant = d['variant']      # application program id
        self.ia = d.get('ia', '')
        self.values = d.get('values', {})    # pref_id -> value (deviations)
        # KNXnet/IP interface IP settings, deviations only (interfaces only):
        # name, assign ('dhcp'|'static'), ip/mask/gw,
        # tunnels[] (additional individual addresses)
        self.iface = d.get('iface', {})
        # KNX Secure commissioning material (secure devices only): cert/fdsk,
        # tool_key, backbone_key, auth_code, tunnel_passwords[], secured_families.
        # Secrets are stored plaintext in project.json (as connection creds are);
        # keyring (.knxkeys) persistence is a later follow-up.
        self.sec = d.get('sec', {})
        # free-form notes + management state: comment; programmed,
        # ia_assigned (local ISO timestamps of the last success);
        # programmed_fp (knxsecure.device_fingerprint at that download),
        # ia_written (the IA that assignment wrote) — the sync markers
        self.info = d.get('info', {})
        self.links = {cid: [ga_int(g) for g in gas]      # coref_id -> [ga:int]
                      for cid, gas in d.get('links', {}).items()}

    def to_dict(self):
        d = {'id': self.id, 'name': self.name, 'tags': self.tags,
             'product': self.product, 'variant': self.variant, 'ia': self.ia,
             'values': self.values,
             'links': {cid: [ga_str(g) for g in gas]
                       for cid, gas in self.links.items()}}
        # optional sections: written only when non-empty, so a plain device's
        # json stays readable
        d.update({k: v for k, v in (('iface', self.iface), ('sec', self.sec),
                                    ('info', self.info)) if v})
        return d

    def ia_synced(self):
        """The device carries this IA (assignment wrote it, unchanged since)."""
        return self.info.get('ia_written') == self.ia

    def app_synced(self, fp):
        """The device holds this configuration (`fp` = its current
        fingerprint)."""
        return self.info.get('programmed_fp') == fp


class Project:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.name = 'Untitled'
        self.devices: list[Device] = []
        self.gas: dict[int, dict] = {}       # ga -> {name, dpt}
        self.tags: list[str] = []            # project-wide tag pool
        self.connections: list[dict] = []    # bus connections (name/type/host/…)
        self.active_connection = ''
        # ETS building/trade trees, flat by path: 'Haus/EG/Flur' -> {type,
        # number, …}. Devices point in with '@loc:<path>' / '@trade:<path>'
        # tags; the dict carries what a tag cannot (node type, empty nodes).
        self.spaces: dict[str, dict] = {}
        self.trades: dict[str, dict] = {}
        self._prods = {}                     # filename -> KnxProd
        self._progs = {}                     # (filename, apid) -> Program
        self._dpts = None                    # DPT id -> name, loaded on demand
        if path and (Path(path) / 'project.json').exists():
            self._load()

    # ---- persistence -----------------------------------------------------

    def _load(self):
        self.restore(json.loads((self.path / 'project.json').read_text()))

    def restore(self, d):
        """Replace the whole project state from a dict (the file format).
        Device objects are recreated, so callers holding one must re-find
        it by id."""
        self.name = d.get('name', 'Untitled')
        self.devices = [Device(json.loads(json.dumps(x)))
                        for x in d.get('devices', [])]
        # 'security': 'auto' (default) | 'on' | 'off' — ETS's per-GA tri-state.
        # It is PLANNING state and never reaches a device: auto means "secured
        # if every device on this GA is a secure product and commissioned",
        # which only the project can evaluate. knxsecure resolves it to the
        # per-device flags at download time. 'key' is the 16-byte group key,
        # minted on first use and stored hex (plaintext, as tool keys are).
        self.gas = {ga_int(x['ga']): {'name': x.get('name', ''),
                                      'dpt': x.get('dpt', ''),
                                      'security': x.get('security', 'auto'),
                                      'key': x.get('key', '')}
                    for x in d.get('group_addresses', [])}
        self.tags = sorted({*d.get('tags', []),
                            *(t for dv in self.devices for t in dv.tags)})
        self.connections = json.loads(json.dumps(d.get('connections', [])))
        self.active_connection = d.get('active_connection', '')
        self.spaces = json.loads(json.dumps(d.get('spaces', {})))
        self.trades = json.loads(json.dumps(d.get('trades', {})))

    def state(self):
        """The project as its file dict — a deep copy, so it can be kept as
        an undo snapshot and compared (==) with a later one."""
        d = {'name': self.name,
             'tags': self.tags,
             'connections': self.connections,
             'active_connection': self.active_connection,
             'devices': [dv.to_dict() for dv in self.devices],
             'group_addresses': [
                 # security/key only when they carry information, so an
                 # all-plaintext project's file is unchanged
                 {'ga': ga_str(ga), 'name': g['name'], 'dpt': g['dpt'],
                  **({'security': g['security']}
                     if g.get('security', 'auto') != 'auto' else {}),
                  **({'key': g['key']} if g.get('key') else {})}
                 for ga, g in sorted(self.gas.items())]}
        # only when present, so a project without them keeps its file
        d.update({k: v for k, v in (('spaces', self.spaces),
                                    ('trades', self.trades)) if v})
        return json.loads(json.dumps(d))

    def save(self, path=None):
        if path:
            self.path = Path(path)
        (self.path / 'catalog').mkdir(parents=True, exist_ok=True)
        (self.path / 'project.json').write_text(
            json.dumps(self.state(), indent=1))

    # ---- products --------------------------------------------------------

    def import_product(self, src) -> str:
        """Copy a knxprod into catalog/ (dedup by content). Returns filename."""
        src = Path(src)
        return self.import_product_bytes(src.name, src.read_bytes())

    def import_product_bytes(self, name, data) -> str:
        """A knxprod given as bytes (a knxproj's manufacturer folder,
        re-packed) into catalog/, dedup by content. Returns filename."""
        cat = self.path / 'catalog'
        cat.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256(data).hexdigest()
        for f in cat.glob('*.knxprod'):
            if hashlib.sha256(f.read_bytes()).hexdigest() == h:
                return f.name
        dst = cat / name
        if dst.exists():                     # same name, different content
            dst = cat / f'{Path(name).stem}-{h[:8]}.knxprod'
        dst.write_bytes(data)
        return dst.name

    def prod(self, filename) -> KnxProd:
        if filename not in self._prods:
            self._prods[filename] = KnxProd(self.path / 'catalog' / filename)
        return self._prods[filename]

    def program(self, device):
        if not device.product:      # imported without its application program
            raise LookupError(f'{device.name}: product not in the project')
        key = (device.product, device.variant)
        if key not in self._progs:
            self._progs[key] = self.prod(device.product).load_program(device.variant)
        return self._progs[key]

    def program_or_none(self, device):
        """The device's Program, or None when the project cannot provide one
        (no product, or one the parser rejects). A failure is remembered, so
        the list can ask for every device on every rebuild."""
        key = (device.product, device.variant)
        if key not in self._progs:
            try:
                self.program(device)
            except (LookupError, ValueError, OSError, ET.ParseError):
                self._progs[key] = None
        return self._progs[key]

    # ---- devices ---------------------------------------------------------

    def add_device(self, knxprod_path, variant, name=''):
        fn = self.import_product(knxprod_path)
        did = max((d.id for d in self.devices), default=0) + 1
        dev = Device({'id': did, 'name': name or f'Device {did}',
                      'product': fn, 'variant': variant,
                      'ia': self.free_ia()})
        self.devices.append(dev)
        return dev

    def remove_device(self, dev):
        self.devices.remove(dev)

    def duplicate(self, dev, count=1):
        """`count` copies of `dev`: same product, settings, tags and links;
        fresh IAs in the device's line. Physical identity (IP settings,
        security material, timestamps) is not copied. Names continue the
        source's trailing number ("Dimmer 3" -> "Dimmer 4", "Dimmer 5"),
        else are numbered from 2."""
        m = re.fullmatch(r'(.*?)\s*(\d+)', dev.name)
        base, n = (m.group(1), int(m.group(2))) if m else (dev.name, 1)
        names = {d.name for d in self.devices}
        try:
            area, line, _ = ia_parts(dev.ia)
        except ValueError:
            area, line = 1, 1
        out = []
        for _ in range(count):
            n += 1
            while f'{base} {n}' in names:
                n += 1
            names.add(f'{base} {n}')
            did = max((d.id for d in self.devices), default=0) + 1
            src = dev.to_dict()
            for k in ('iface', 'sec', 'info'):
                src.pop(k, None)
            src.update(id=did, name=f'{base} {n}',
                       ia=self.free_ia(area, line))
            copy = Device(json.loads(json.dumps(src)))   # own values/tags
            self.devices.append(copy)
            out.append(copy)
        return out

    def used_ias(self):
        """All occupied individual addresses (device IAs + interface tunnel
        addresses), as a set of strings."""
        used = set()
        for d in self.devices:
            if d.ia:
                used.add(d.ia)
            used.update(d.iface.get('tunnels', []))
        return used

    def free_ia(self, area=1, line=1):
        used = set()
        for ia in self.used_ias():
            try:
                a, l, n = ia_parts(ia)
                if (a, l) == (area, line):
                    used.add(n)
            except ValueError:
                pass
        n = next((i for i in range(1, 256) if i not in used), None)
        if n is None:
            raise ValueError(f'line {area}.{line} has no free address')
        return f'{area}.{line}.{n}'

    def connection(self):
        """The active connection. When active_connection
        names one that no longer exists we fall back to the first — and repair
        the stale name, so the connection the UI shows is the one the bus
        actually uses instead of silently talking to a different interface."""
        for c in self.connections:
            if c['name'] == self.active_connection:
                return c
        if not self.connections:
            return None
        c = self.connections[0]
        self.active_connection = c['name']
        return c

    def visible_corefs(self, dev):
        """ComObjectRef ids visible for the device's current parameter values."""
        return self._visible(dev, CRef)

    def visible_prefs(self, dev):
        """ParameterRef ids active (visible) for the device's current values.
        These are the parameters ETS actually writes; inactive union members
        must NOT be written (they share memory with the active one)."""
        return self._visible(dev, PRef)

    def _visible(self, dev, kind):
        prog = self.program(dev)
        return [n.ref_id for n in iter_visible(prog.dynamic, prog.values(dev))
                if isinstance(n, kind)]

    # ---- group addresses -------------------------------------------------

    def ga_users(self, ga) -> list[Device]:
        return [d for d in self.devices
                if any(ga in gas for gas in d.links.values())]

    def ga_users_map(self):
        """{ga: [devices]} in one pass (ga_users per GA scans all devices)."""
        m = {}
        for d in self.devices:
            for g in {g for gas in d.links.values() for g in gas}:
                m.setdefault(g, []).append(d)
        return m

    def link(self, dev, coref_id, ga):
        self.gas.setdefault(ga, {'name': '', 'dpt': '', 'security': 'auto',
                                 'key': ''})
        gas = dev.links.setdefault(coref_id, [])
        if ga not in gas:
            gas.append(ga)

    def unlink(self, dev, coref_id, ga):
        gas = dev.links.get(coref_id, [])
        if ga in gas:
            gas.remove(ga)
        if not gas:
            dev.links.pop(coref_id, None)

    def delete_tag(self, tag):
        if tag in self.tags:
            self.tags.remove(tag)
        for d in self.devices:
            if tag in d.tags:
                d.tags.remove(tag)

    def bulk_add_gas(self, start, count, template):
        """Sequential GAs from start (int). {} in the name template = math
        expression with n = running number, e.g. 'Light {n}' or 'Dim {n*2}'.
        Returns (created, skipped_existing)."""
        if '{' not in template and count > 1:
            template += ' {n}'
        tmpl_eval(template, n=1)         # validate before creating anything
        created = skipped = 0
        for i in range(count):
            ga = start + i
            if ga > 0xFFFF:
                break
            if ga in self.gas:
                skipped += 1
            else:
                self.gas[ga] = {'name': tmpl_eval(template, n=i + 1),
                                'dpt': '', 'security': 'auto', 'key': ''}
                created += 1
        return created, skipped

    def dpt_name(self, dpt):
        """'DPST-1-1' -> '1.001 switch'. The DPT master list is the same in
        every knxprod (knx_master.xml), so one catalog file seeds it all."""
        if not dpt:
            return ''
        if self._dpts is None:
            files = self.catalog_files()
            if not files:               # retry once a product is imported
                return dpt
            self._dpts = self.prod(files[0]).dpts
        return self._dpts.get(dpt, dpt)

    def catalog_files(self):
        if not self.path:
            return []
        return sorted(f.name for f in (self.path / 'catalog').glob('*.knxprod'))

    def rename_ga(self, old, new):
        """Move a GA to a new address, updating every device link."""
        self.rename_gas({old: new})

    def rename_gas(self, mapping):
        """Move several GAs at once (old int -> new int); swaps within the
        set are fine. All-or-nothing: validates before touching anything."""
        news = list(mapping.values())
        if len(set(news)) != len(news):
            raise ValueError('duplicate target addresses')
        for old in mapping:
            if old not in self.gas:
                raise ValueError(f'{ga_str(old)} does not exist')
        for new in news:
            if new in self.gas and new not in mapping:
                raise ValueError(f'{ga_str(new)} already exists')
        moved = {old: self.gas.pop(old) for old in mapping}
        for old, new in mapping.items():
            self.gas[new] = moved[old]
        for d in self.devices:
            for gas in d.links.values():
                for i, g in enumerate(gas):
                    if g in mapping:
                        gas[i] = mapping[g]

    def delete_ga(self, ga):
        self.gas.pop(ga, None)
        for d in self.devices:
            for cid in list(d.links):
                self.unlink(d, cid, ga)

    def filter_gas(self, pattern='', used=None, tag=''):
        """pattern: fnmatch on '1/2/3' form (* and ?), or name/address substring.
        used: True/False/None. tag: boolean tag expression over linked devices'
        tags, e.g. 'EG & light' (all terms) or 'EG | OG' (any term)."""
        out = []
        users_map = self.ga_users_map()
        for ga in sorted(self.gas):
            s = ga_str(ga)
            if pattern and not (fnmatch.fnmatch(s, pattern) or pattern in s
                                or pattern.lower() in self.gas[ga]['name'].lower()):
                continue
            users = users_map.get(ga, [])
            if used is True and not users:
                continue
            if used is False and users:
                continue
            if tag and not match_tag_expr(
                    {t.lower() for d in users for t in d.tags}, tag):
                continue
            out.append(ga)
        return out

    def filter_devices(self, text='', unsynced=()):
        """Boolean filter over name + tags, same syntax as the GA tag filter:
        '&' = all terms, '|' = any group, terms are case-insensitive
        substrings — e.g. 'EG & light | OG'. Pseudo-tags name management
        state: ':unprogrammed' / ':up' (application never downloaded),
        ':unassigned' / ':ua' (IA never written), ':unsynced' / ':us' (IA or
        configuration differs from the device — `unsynced` is the set of
        those device ids; the editor computes it, it needs the knxprod)."""
        t = text.strip()
        return [d for d in self.devices
                if not t or match_tag_expr(
                    {d.name.lower(), *(x.lower() for x in d.tags),
                     *([':unprogrammed', ':up']
                       if not d.info.get('programmed') else []),
                     *([':unassigned', ':ua']
                       if not d.info.get('ia_assigned') else []),
                     *([':unsynced', ':us'] if d.id in unsynced else [])},
                    t)]

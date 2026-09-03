"""knxprod parser. Loads a .knxprod zip, exposes catalog + application programs.

Module instances are expanded at load: their parameters/refs/comobjects get
instance-unique ids and {{Arg}} templates substituted.
"""
import base64, io, re, zipfile
import xml.etree.ElementTree as ET

from . import knxcalc
from dataclasses import dataclass, field

# The XML namespace differs per knxprod — ETS5 is project/20, ETS6 project/23,
# /21, … — so it is read from each parsed root and carried on the object that
# parsed it. It used to be a module global that every entry point re-pointed:
# with several knxprods open at once (Project caches them) that made correct
# parsing depend on nobody doing a {ns} lookup outside those entry points, and
# the failure mode was an empty result, not an exception.
_DEFAULT_NS = '{http://knx.org/xml/project/20}'


def _ns(root):
    """The namespace prefix ('{...}') of a parsed root element."""
    return root.tag.split('}')[0] + '}' if root.tag.startswith('{') \
        else _DEFAULT_NS


def _tag(e): return e.tag.split('}')[1]


def _pct(w):
    """Grid <Column Width="25%"> -> 25. Absolute widths ('120') pass through
    as-is: they are stretch factors either way, and ETS grids use percentages."""
    try:
        return float(w.rstrip('%').strip() or 0)
    except ValueError:
        return 0


@dataclass
class ParamType:
    name: str
    kind: str            # enum | int | float | text | color | picture | hidden | none
    min: float = 0
    max: float = 0
    enums: list = field(default_factory=list)  # [(value:int, text:str)]
    ref: str = ''        # picture: baggage id
    align: str = ''      # picture: HorizontalAlignment
    bits: int = 0        # SizeInBit (for memory packing)
    uihint: str = ''     # TypeNumber UIHint, e.g. 'CheckBox' 
    enc: str = ''        # float Encoding, e.g. 'DPT 9'


@dataclass
class Param:
    id: str
    text: str
    suffix: str
    type_id: str
    value: str
    access: str          # ReadWrite | Read | None
    mem: tuple | None = None  # (segment_id, byte_offset, bit_offset) or None


@dataclass
class Segment:
    addr: int            # absolute address (AbsoluteSegment); 0 for relative
    size: int
    data: bytes | None   # initial image (EEPROM); None for RAM
    lsm: int = 0         # RelativeSegment LoadStateMachine (0 = absolute)
    offset: int = 0      # RelativeSegment offset within its LSM
    memtype: int = 3     # LdCtrlAbsSegment MemType: 2=RAM, 3=EEPROM (from loadproc)
    segflags: int = 0x80  # LdCtrlAbsSegment SegFlags; bit7 = programmed config
    mask: bytes | None = None   # <Mask>: 0xFF = byte owned by the application
                                # program, 0x00 = the device's own (its address,
                                # manufacturer data, factory identity)

    @property
    def is_config(self):
        """Holds programmed project configuration that can be read back and
        compared. RAM (memtype 2) is runtime state; segments without the
        SegFlags bit7 (e.g. a device serial/identity scratch area) are not
        part of the project. Both must be excluded from verify and decode."""
        return self.memtype != 2 and bool(self.segflags & 0x80)


@dataclass
class ParamRef:
    id: str
    param_id: str
    text: str | None     # overrides
    value: str | None
    access: str | None


@dataclass
class ComObj:
    id: str
    number: int
    text: str
    function_text: str
    size: str
    dpt: str
    flags: str           # e.g. "C-T"


@dataclass
class ComObjRef:
    id: str
    obj_id: str
    text: str | None
    function_text: str | None
    size: str | None
    dpt: str | None
    text_param_ref: str | None
    flag_overrides: dict = field(default_factory=dict)  # {'C':bool,...} present only


# dynamic tree nodes
@dataclass
class Block:
    id: str
    text: str
    text_param_ref: str | None
    children: list
    access: str = 'ReadWrite'    # 'None' = internal, ETS hides the page
    icon: str = ''               # icon name inside the program's IconFile zip
    layout: str = ''             # '' (stacked rows) | 'Grid' | 'Table'
    cols: list = field(default_factory=list)   # column widths, e.g. [25, 5, 70]
    heads: list = field(default_factory=list)  # Table: column header texts
    rows: list = field(default_factory=list)   # Table: row header texts
    inline: bool = False         # part of the parent page, never a page itself
    cell: str = ''               # 'row,col' when this node sits in a Grid parent


class Channel(Block):
    """Named channel group: a nav header in ETS, not a parameter page."""


@dataclass
class Calc:
    """One <ParameterCalculation>: alias -> pref_id for both sides, plus the
    JS that computes the R side from the L side."""
    lparams: list        # [(alias, pref_id)]
    rparams: list
    lr: str              # LRTransformation source


@dataclass
class Choose:
    param_ref: str
    whens: list          # [(test:str|None, children:list)]


@dataclass
class PRef:
    ref_id: str
    cell: str = ''


@dataclass
class CRef:
    ref_id: str


@dataclass
class Assign:
    """<Assign>: while this branch of the dynamic tree is active, the target
    parameter takes the source's value (or a literal). Products use it to feed
    a visible parameter's value into the module-internal one that page titles,
    channel names and object texts actually read."""
    target: str
    source: str | None
    value: str | None


@dataclass
class Separator:
    text: str
    uihint: str = ''     # '' | Headline | Information | Error | HorizontalRuler
    icon: str = ''       # Headline: icon name inside the program's IconFile zip
    cell: str = ''


class Program:
    def __init__(self):
        self.name = ''
        self.icon_file = ''                  # IconFile baggage id (nav icons)
        self.mask = ''                       # e.g. 'MV-0705'
        self.model = ''                      # ManagementModel of that mask,
                                             # e.g. 'BimM112' | 'SystemB' | 'Bcu1'
        self.procstyle = ''                  # LoadProcedureStyle: ProductProcedure
                                             # (BimM112) | MergedProcedure (SystemB)
                                             # | DefaultProcedure (BCU1)
        self.masterprocs: dict = {}          # (ProcedureType, ProcedureSubType) ->
                                             # the mask's KNX-standard default
                                             # steps (see KnxProd.mask_data)
        self.fragments: dict = {}            # MergeId -> [(tag, attrs)]: the knxprod's
                                             # own <LoadProcedure> blocks, unflattened
        self.manufacturer = 0                # KNX manufacturer id (int)
        self.tunnels = 0                     # KNXnet/IP additional addresses
        self.secure = False                  # IsSecureEnabled: the product supports
                                             # KNX Secure. ETS's own flag, and the
                                             # only gate — orthogonal to `tunnels`
                                             # (a secure actuator has no tunnels; a
                                             # pre-Secure IP interface has tunnels
                                             # and no security object).
        self.max_sec_grp_keys = 0            # MaxSecurityGroupKeyTableEntries; 0 =
                                             # undeclared (the 732), not "none" —
                                             # so never a `secure` signal
        self.app_number = 0
        self.app_version = 0
        self.types: dict[str, ParamType] = {}
        self.params: dict[str, Param] = {}
        self.prefs: dict[str, ParamRef] = {}
        self.comobjs: dict[str, ComObj] = {}
        self.corefs: dict[str, ComObjRef] = {}
        self.dynamic: list = []
        self.calcs: list[Calc] = []          # <ParameterCalculation> scripts
        self.assigns: set = set()            # <Assign> target prefs
        self._calcjs = None                  # them, compiled (see knxcalc)
        self._calc = {}                     # calc inputs -> outputs
        self.segments: dict[str, Segment] = {}
        self.addrtab = None                  # (segment_id, offset, max_entries)
        self.assoctab = None
        self.comobjtab = None
        self.loadproc: list = []             # [(tag, {attrs})] in order
        self._defaults = None                # pref defaults, built on demand

    # -- default value of a ParameterRef
    def default(self, pref_id):
        pr = self.prefs[pref_id]
        if pr.value is not None:
            return pr.value
        return self.params[pr.param_id].value

    def defaults(self):
        """{pref_id: default value} for every ParameterRef. A Program is
        immutable after load, so this is built once and shared."""
        if self._defaults is None:
            self._defaults = {pid: self.default(pid) for pid in self.prefs}
        return self._defaults

    @property
    def calc_inputs(self):
        """Every (alias, pref_id) a calculation reads."""
        return [r for c in self.calcs for r in c.lparams + c.rparams]

    def values(self, dev):
        """The device's effective pref values: defaults with its deviations
        applied, then the derived ones — calculated parameters, and the
        <Assign>s of whichever branches those make visible. The caller must
        not mutate the result."""
        v = knxcalc.apply(self, self.defaults() | dev.values)
        if not self.assigns:
            return v
        return knxcalc.apply(self, self.assign(v))

    def assign(self, values):
        """Run the dynamic tree's <Assign>s in document order. Each one writes
        into the map the walk itself reads, so a later <choose> sees what an
        earlier assignment did — which is how ETS resolves them."""
        v = dict(values)
        for n in iter_visible(self.dynamic, v):
            if isinstance(n, Assign):
                new = n.value if n.value is not None else v.get(n.source)
                if new is not None:
                    v[n.target] = new
        return v

    def source_of(self, values, pref_id):
        """The parameter an <Assign> currently feeds `pref_id` from — the
        field a user edits to change it — or `pref_id` itself when nothing
        assigns it. A target is usually assigned from several branches, so
        which source counts depends on `values`, hence the walk."""
        if not self.assigns:
            return pref_id
        live = {n.target: n.source for n in iter_visible(self.dynamic, values)
                if isinstance(n, Assign)}      # document order: last wins
        seen = set()
        while live.get(pref_id) and pref_id not in seen:
            seen.add(pref_id)
            pref_id = live[pref_id]
        return pref_id

    # ProcedureSubType -> the AppliesTo token its fragments carry
    _APPLIES = {'all': 'full', 'ap1': 'full'}

    def procedure(self, ptype='Load', subtype='ap1'):
        """The flat [(tag, attrs)] step sequence for one load procedure, or
        None when this product declares no such procedure.

        Three shapes exist, told apart by LoadProcedureStyle:
          ProductProcedure (BimM112) — the knxprod carries the whole sequence
                                       and knx_master.xml has no Load procedure
          MergedProcedure  (System B) — knx_master.xml holds the skeleton, the
                                       knxprod only fills its <LdCtrlMerge> slots
          DefaultProcedure (BCU1)    — knx_master.xml is the whole sequence
        The download flavour picked out of the knxprod's fragments via their
        AppliesTo attribute (full / par / grp) follows `subtype` — a full
        download reads the 'full' fragments, a parameters-only one the 'par'
        fragments, which differ (the Cheops allocates LSM 4 with Mode 1 for a
        full download and Mode 0 for a partial). Master steps never carry an
        AppliesTo, and a fragment without one applies to every flavour.

        This is CHOREOGRAPHY ONLY. The same tag means different things per
        model (LdCtrlRestart is A_Restart on BimM112 but a master reset on
        System B) and several attributes are placeholders rather than real
        values, so each model still needs its own walker — see Mgmt._run_*."""
        applies = self._APPLIES.get(subtype, subtype)
        master = self.masterprocs.get((ptype, subtype))
        if master is None:
            if ptype == 'Load' and self.procstyle == 'ProductProcedure':
                return list(self.loadproc)       # the knxprod IS the procedure
            return None
        out = []
        for tag, a in master:
            if tag != 'LdCtrlMerge':
                out.append((tag, a))
                continue
            # a slot with no matching fragment contributes nothing (normal)
            out += [(t, x) for t, x in self.fragments.get(a.get('MergeId'), [])
                    if applies in x.get('AppliesTo', applies).split(',')]
        return out


FLAGS = [('CommunicationFlag', 'C'), ('ReadFlag', 'R'), ('WriteFlag', 'W'),
         ('TransmitFlag', 'T'), ('UpdateFlag', 'U'), ('ReadOnInitFlag', 'I')]

ARG_RE = re.compile(r'\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}')


def _flags(e):
    return ' '.join(c for a, c in FLAGS if e.get(a) == 'Enabled')


def _parse_type(e):
    """<ParameterType> -> ParamType. The size and the kind both live on the
    single Type* child, not on the ParameterType element."""
    t = ParamType(e.get('Name'), 'none')
    for c in e:
        k = _tag(c)
        if not k.startswith('Type'):
            continue
        if c.get('SizeInBit'):
            t.bits = int(c.get('SizeInBit'))
        if k == 'TypeRestriction':
            if c.get('Base') == 'BinaryValue':
                t.kind = 'hidden'        # internal marker params, ETS hides them
            else:
                t.kind = 'enum'
                t.enums = [(int(en.get('Value')), en.get('Text', ''))
                           for en in c if _tag(en) == 'Enumeration']
        elif k == 'TypeNumber':
            t.kind = 'int'
            t.uihint = c.get('UIHint', '')       # 'CheckBox' for a 0/1 flag
            t.min, t.max = float(c.get('minInclusive', 0)), float(c.get('maxInclusive', 0))
        elif k == 'TypeFloat':
            t.kind = 'float'
            t.min, t.max = float(c.get('minInclusive', 0)), float(c.get('maxInclusive', 0))
            t.enc = c.get('Encoding', '')
            if not t.bits and t.enc == 'DPT 9':
                t.bits = 16
        elif k == 'TypeText':
            t.kind = 'text'
        elif k == 'TypeColor':
            t.kind = 'color'
        elif k == 'TypePicture':
            t.kind = 'picture'
            t.ref = c.get('RefId', '')
            t.align = c.get('HorizontalAlignment', '')
    return t


class _Loader:
    """Parses one ApplicationProgram element into a Program.

    remap/args are set while expanding a Module instance: ids get their
    ModuleDef prefix replaced by the instance prefix, texts get {{Arg}} filled.
    """

    def __init__(self, ap, ns):
        self.ap = ap
        self.ns = ns
        self.prog = Program()
        self.prog.name = ap.get('Name', '')
        self.moduledefs = {md.get('Id'): md
                           for md in ap.findall(f'{ns}ModuleDefs/{ns}ModuleDef')}
        self.remap = ('', '')    # (def_prefix, instance_prefix)
        self.args = {}

    def load(self):
        ap = self.ap
        self.prog.mask = ap.get('MaskVersion', '')
        self.prog.procstyle = ap.get('LoadProcedureStyle', '')
        self.prog.icon_file = ap.get('IconFile', '')
        self.prog.manufacturer = int(ap.get('Id', 'M-0000').split('_')[0][2:], 16)
        # only KNXnet/IP interfaces/routers carry tunnel addresses
        self.prog.tunnels = int(ap.get('AdditionalAddressesCount', 0))
        self.prog.secure = ap.get('IsSecureEnabled') == 'true'
        self.prog.max_sec_grp_keys = int(ap.get('MaxSecurityGroupKeyTableEntries', 0))
        self.prog.app_number = int(ap.get('ApplicationNumber', 0))
        self.prog.app_version = int(ap.get('ApplicationVersion', 0))
        st = ap.find(f'{self.ns}Static')
        for e in st.findall(f'{self.ns}ParameterTypes/{self.ns}ParameterType'):
            self.prog.types[e.get('Id')] = _parse_type(e)
        self._segments(st)
        self._static(st)
        self._tables(st)
        self._loadproc(st)
        self._seg_memtype()
        self.prog.dynamic = self._children(ap.find(f'{self.ns}Dynamic'))
        self.prog.assigns = {n.target for n in iter_all(self.prog.dynamic)
                             if isinstance(n, Assign)}
        return self.prog

    def _seg_memtype(self):
        """Carry MemType/SegFlags from the load procedure's LdCtrlAbsSegment
        steps onto the segments (by address) — that's where memory class and
        the programmed-config flag live, not on the <Code> segment element."""
        by_addr = {s.addr: s for s in self.prog.segments.values() if s.addr}
        for tag, a in self.prog.loadproc:
            if tag == 'LdCtrlAbsSegment' and 'Address' in a:
                s = by_addr.get(int(a['Address']))
                if s:
                    s.memtype = int(a.get('MemType', s.memtype))
                    s.segflags = int(a.get('SegFlags', s.segflags))

    # segments / tables / load procedure live only in the main Static
    def _segments(self, st):
        code = st.find(f'{self.ns}Code')
        for e in code if code is not None else []:
            tag = _tag(e)
            if tag not in ('AbsoluteSegment', 'RelativeSegment'):
                continue
            d = e.find(f'{self.ns}Data')
            data = base64.b64decode(d.text) if d is not None and d.text else None
            mk = e.find(f'{self.ns}Mask')
            mask = base64.b64decode(mk.text) if mk is not None and mk.text else None
            if tag == 'AbsoluteSegment':
                self.prog.segments[e.get('Id')] = Segment(
                    int(e.get('Address')), int(e.get('Size')), data, mask=mask)
            else:                        # RelativeSegment (System B and later)
                self.prog.segments[e.get('Id')] = Segment(
                    0, int(e.get('Size')), data,
                    lsm=int(e.get('LoadStateMachine', 0)),
                    offset=int(e.get('Offset', 0)), mask=mask)

    def _tables(self, st):
        for name, attr in (('AddressTable', 'addrtab'),
                           ('AssociationTable', 'assoctab'),
                           ('ComObjectTable', 'comobjtab')):
            e = st.find(f'{self.ns}{name}')
            if e is not None:
                setattr(self.prog, attr, (self._id(e.get('CodeSegment')),
                        int(e.get('Offset', 0)), int(e.get('MaxEntries', 0))))

    def _loadproc(self, st):
        # Two views of the same blocks. `loadproc` is every LdCtrl* step
        # flattened in document order — what BimM112 walks, since its knxprod
        # carries the whole procedure in one block. `fragments` keeps them
        # split by MergeId, which System B needs: there the knxprod holds only
        # the pieces that fill the <LdCtrlMerge> slots of the mask's skeleton
        # in knx_master.xml (see Program.procedure).
        lps = st.find(f'{self.ns}LoadProcedures')
        for lp in (lps if lps is not None else []):
            steps = [(_tag(c), dict(c.attrib)) for c in lp]
            self.prog.loadproc += steps
            # extend, not assign: two blocks may share a MergeId
            self.prog.fragments.setdefault(lp.get('MergeId'), []).extend(steps)

    def _memloc(self, me):
        """(<Memory>) -> (segment_id, byte_offset, bit_offset); adds module base."""
        off = int(me.get('Offset', 0))
        bo = me.get('BaseOffset')            # module ParamOffsBase arg id (raw)
        if bo:
            off += int(self.args.get('__num_' + bo, 0))
        return (self._id(me.get('CodeSegment')), off, int(me.get('BitOffset', 0)))

    def _add_param(self, e, union_loc):
        pid = self._id(e.get('Id'))
        mem = None
        if union_loc is not None:            # union member: offsets relative to union
            seg, boff, bbit = union_loc
            mem = (seg, boff + int(e.get('Offset', 0)),
                   bbit + int(e.get('BitOffset', 0)))
        else:
            me = e.find(f'{self.ns}Memory')
            if me is not None:
                mem = self._memloc(me)
        self.prog.params[pid] = Param(
            pid, self._txt(e.get('Text', '')), e.get('SuffixText', ''),
            e.get('ParameterType'), e.get('Value', ''),
            e.get('Access', 'ReadWrite'), mem)

    def _id(self, s):
        if s is None:
            return None
        d, i = self.remap
        return s.replace(d, i) if d else s

    def _txt(self, s):
        if s is None or not self.args:
            return s
        return ARG_RE.sub(lambda m: self.args.get(m.group(1), m.group(0)), s)

    def _static(self, st):
        p = self.prog
        params = st.find(f'{self.ns}Parameters')
        for c in params if params is not None else []:
            k = _tag(c)
            if k == 'Parameter':
                self._add_param(c, None)
            elif k == 'Union':               # members share the union's memory
                me = c.find(f'{self.ns}Memory')
                loc = self._memloc(me) if me is not None else None
                for pc in c:
                    if _tag(pc) == 'Parameter':
                        self._add_param(pc, loc)
        for e in st.iter(f'{self.ns}ParameterRef'):
            p.prefs[self._id(e.get('Id'))] = ParamRef(
                self._id(e.get('Id')), self._id(e.get('RefId')),
                self._txt(e.get('Text')), e.get('Value'), e.get('Access'))
        for e in st.iter(f'{self.ns}ParameterCalculation'):
            lr = e.find(f'{self.ns}LRTransformation')
            if lr is None or not (lr.text or '').strip():
                continue                     # RL-only: an edit of a computed
            def refs(tag):                   # parameter, which never happens
                el = e.find(f'{self.ns}{tag}')
                return [(x.get('AliasName'), self._id(x.get('RefId')))
                        for x in (el if el is not None else [])]
            p.calcs.append(Calc(refs('LParameters'), refs('RParameters'),
                                lr.text))
        for e in st.iter(f'{self.ns}ComObject'):
            bn = e.get('BaseNumber')
            base = int(self.args.get('__num_' + bn, 0)) if bn else 0
            p.comobjs[self._id(e.get('Id'))] = ComObj(
                self._id(e.get('Id')), base + int(e.get('Number', 0)),
                self._txt(e.get('Text', '')), e.get('FunctionText', ''),
                e.get('ObjectSize', ''), e.get('DatapointType', ''), _flags(e))
        for e in st.iter(f'{self.ns}ComObjectRef'):
            over = {c: e.get(a) == 'Enabled' for a, c in FLAGS if e.get(a)}
            p.corefs[self._id(e.get('Id'))] = ComObjRef(
                self._id(e.get('Id')), self._id(e.get('RefId')),
                self._txt(e.get('Text')), e.get('FunctionText'),
                e.get('ObjectSize'), e.get('DatapointType'),
                self._id(e.get('TextParameterRefId')), over)

    def _children(self, e):
        out = []
        for c in e:
            k = _tag(c)
            if k == 'ParameterBlock':
                cols = [col for cs in c if _tag(cs) == 'Columns' for col in cs]
                rows = [r for rs in c if _tag(rs) == 'Rows' for r in rs]
                out.append(Block(
                    self._id(c.get('Id')), self._txt(c.get('Text', '')),
                    self._id(c.get('TextParameterRefId')), self._children(c),
                    c.get('Access', 'ReadWrite'), c.get('Icon', ''),
                    c.get('Layout', ''), [_pct(x.get('Width', '')) for x in cols],
                    [self._txt(x.get('Text', '') or '') for x in cols],
                    [self._txt(x.get('Text', '') or '') for x in rows],
                    c.get('Inline') == 'true', c.get('Cell', '')))
            elif k == 'choose':
                whens = [(w.get('test'), self._children(w))
                         for w in c if _tag(w) == 'when']
                out.append(Choose(self._id(c.get('ParamRefId')), whens))
            elif k == 'ParameterRefRef':
                out.append(PRef(self._id(c.get('RefId')), c.get('Cell', '')))
            elif k == 'ComObjectRefRef':
                out.append(CRef(self._id(c.get('RefId'))))
            elif k == 'Assign':
                out.append(Assign(self._id(c.get('TargetParamRefRef')),
                                  self._id(c.get('SourceParamRefRef')),
                                  c.get('Value')))
            elif k == 'ParameterSeparator':
                out.append(Separator(self._txt(c.get('Text', '')),
                                     c.get('UIHint', ''), c.get('Icon', ''),
                                     c.get('Cell', '')))
            elif k == 'Module':
                out += self._module(c)
            elif k in ('ChannelIndependentBlock', 'Channel'):
                text = self._txt(c.get('Text') or '')
                if k == 'Channel' and text:
                    out.append(Channel(self._id(c.get('Id')), text,
                                       self._id(c.get('TextParameterRefId')),
                                       self._children(c), 'ReadWrite',
                                       c.get('Icon', '')))   # nav header
                else:
                    out += self._children(c)
            # Rename etc: ignored for now
        return out

    def _module(self, m):
        md = self.moduledefs[m.get('RefId')]
        args = {}
        for a in m:
            ref = a.get('RefId')
            arg = md.find(f'{self.ns}Arguments/{self.ns}Argument[@Id="{ref}"]')
            if arg is None:              # instance argument the def never declares
                continue
            args[arg.get('Name')] = a.get('Value', '')
            args['__num_' + ref] = a.get('Value', '')
        saved = self.remap, self.args
        self.remap, self.args = (md.get('Id'), m.get('Id')), args
        self._static(md.find(f'{self.ns}Static'))
        out = self._children(md.find(f'{self.ns}Dynamic'))
        self.remap, self.args = saved
        return out


class KnxProd:
    """One .knxprod zip. Each XML inside carries its own namespace, so every
    parse reads its own rather than sharing one."""

    def __init__(self, path):
        self.zf = zipfile.ZipFile(path)
        self.mdir = next((n.split('/')[0] for n in self.zf.namelist()
                          if '/' in n and n.endswith('Catalog.xml')), None)
        if self.mdir is None:
            raise ValueError(f'{path}: no */Catalog.xml — not a knxprod?')
        cat = ET.fromstring(self.zf.read(f'{self.mdir}/Catalog.xml'))
        ns = _ns(cat)
        self._baggages = None
        self._icons = {}
        self._dpts = None
        self._masks = None
        # catalog items: (name, application program file id)
        self.items = []
        for ci in cat.iter(f'{ns}CatalogItem'):
            h2p = ci.get('Hardware2ProgramRefId', '')      # ..._HP-0224-21-C696
            if '_HP-' not in h2p:
                continue                 # not a programmable catalog entry
            self.items.append((ci.get('Name'),
                               f"{self.mdir}_A-{h2p.split('_HP-')[1]}"))
        self.items.sort()

    def close(self):
        self.zf.close()

    def load_program(self, apid) -> Program:
        root = ET.fromstring(self.zf.read(f'{self.mdir}/{apid}.xml'))
        ns = _ns(root)
        prog = _Loader(root.find(f'.//{ns}ApplicationProgram'), ns).load()
        model, procs = self.mask_data(prog.mask)
        prog.model = model
        prog.masterprocs = procs
        return prog

    def mask_data(self, mask):
        """(ManagementModel, {(ProcedureType, ProcedureSubType): [(tag, attrs)]})
        for a mask version, read from the knx_master.xml every knxprod ships.

        The procedures are the KNX-standard defaults for that programming
        model. Later models keep only their product-specific deviations in the
        knxprod's own <LoadProcedures> and merge them into these; the oldest
        (BCU1) declare LoadProcedureStyle="DefaultProcedure" and carry no
        <LoadProcedures> at all, so the master data is the ONLY description of
        how to download them."""
        if self._masks is None:
            self._masks = {}
            r = self._master()
            ns = _ns(r)
            for mv in r.iter(f'{ns}MaskVersion'):
                procs = {}
                for p in mv.iter(f'{ns}Procedure'):
                    # first wins: a mask may declare the same (type, subtype)
                    # twice for different Access levels (MV-07B0 does, for
                    # Unload/all) and they are not interchangeable
                    procs.setdefault(
                        (p.get('ProcedureType'), p.get('ProcedureSubType')),
                        [(_tag(c), dict(c.attrib)) for c in p])
                self._masks[mv.get('Id')] = (mv.get('ManagementModel', ''), procs)
        return self._masks.get(mask, ('', {}))

    def baggage(self, ref_id):
        """Bytes of an embedded file (product images etc.), or None."""
        if self._baggages is None:
            self._baggages = {}
            try:
                r = ET.fromstring(self.zf.read(f'{self.mdir}/Baggages.xml'))
                for b in r.iter(f'{_ns(r)}Baggage'):
                    tp = b.get('TargetPath', '')
                    self._baggages[b.get('Id')] = (
                        f"{self.mdir}/Baggages/{tp + '/' if tp else ''}"
                        f"{b.get('Name')}")
            except KeyError:
                pass
        path = self._baggages.get(ref_id)
        return self.zf.read(path) if path else None

    def icons(self, ref_id):
        """{name: png bytes} of an IconFile baggage (a zip of Icon_*.png)."""
        if ref_id not in self._icons:
            out = {}
            data = self.baggage(ref_id) if ref_id else None
            if data:
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        out = {n.rsplit('/', 1)[-1].rsplit('.', 1)[0]: z.read(n)
                               for n in z.namelist() if not n.endswith('/')}
                except (zipfile.BadZipFile, KeyError):
                    pass
            self._icons[ref_id] = out
        return self._icons[ref_id]

    @property
    def dpts(self):
        """'DPST-1-1' -> '1.001 switch', 'DPT-1' -> '1.x 1-bit'."""
        if self._dpts is None:
            self._dpts = {}
            r = self._master()
            ns = _ns(r)
            for dt in r.iter(f'{ns}DatapointType'):
                n = dt.get('Number')
                self._dpts[dt.get('Id')] = f"{n}.x {dt.get('Text', '')}"
                for st in dt.iter(f'{ns}DatapointSubtype'):
                    self._dpts[st.get('Id')] = \
                        f"{n}.{int(st.get('Number')):03d} {st.get('Text', '')}"
        return self._dpts

    def _master(self):
        """The knx_master.xml root (an empty element when the zip lacks it)."""
        try:
            return ET.fromstring(self.zf.read('knx_master.xml'))
        except KeyError:
            return ET.Element('none')


# ---- evaluation ----------------------------------------------------------

_CMP = re.compile(r'(!=|>=|<=|>|<)?\s*(-?\d+)')


def test_matches(test, value):
    """KNX when@test: space-separated values, or comparison like !=4."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return str(test) == str(value)
    for tok in test.split():
        m = _CMP.fullmatch(tok)
        if not m:
            continue
        op, n = m.group(1) or '==', int(m.group(2))
        if {'==': v == n, '!=': v != n, '>': v > n,
                '<': v < n, '>=': v >= n, '<=': v <= n}[op]:
            return True
    return False


def active_children(choose, values):
    """Children of EVERY matching when — the tests are not exclusive (e.g.
    '>0' and '2' both apply at 2); the default (no test) only if none
    matched. Pinned by a real ETS-built System B group-object table."""
    default, out, matched = [], [], False
    val = values.get(choose.param_ref)
    for test, children in choose.whens:
        if test is None or test == 'default':
            default = children
        elif test_matches(test, val):
            out += children
            matched = True
    return out if matched else default


def iter_all(nodes):
    """Every node of a dynamic tree, both branches of every choose."""
    for n in nodes:
        yield n
        if isinstance(n, Choose):
            for _, ch in n.whens:
                yield from iter_all(ch)
        elif isinstance(n, Block):
            yield from iter_all(n.children)


def iter_visible(nodes, values, into_blocks=True):
    """Walk the dynamic tree with Chooses resolved against `values`, yielding
    every visible node. Descends into Blocks unless into_blocks is False."""
    for n in nodes:
        if isinstance(n, Choose):
            yield from iter_visible(active_children(n, values), values,
                                    into_blocks)
        else:
            yield n
            if into_blocks and isinstance(n, Block):
                yield from iter_visible(n.children, values, into_blocks)

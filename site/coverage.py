"""Device-support site: docs/ from site/index.sqlite (built by
private/tools/prodindex.py, apinfo.py and tests/test_corpus.py) plus
site/reports.json (verify reports filed by users, see reports.py). Runs in
the site workflow on every report; locally:
    python site/coverage.py && open docs/index.html

Pages:
  index.html      status legend, KPIs, per-manufacturer table (only the ones
                  I have product databases for), how to help
  products.html   every catalog item with a search box
  m/M-xxxx.html   one manufacturer's products
  masks.html      by mask (programming model) — the developer view

Per program the status is one of:
  tested      programmed + read back on the real bus (TESTED below)
  supported   knxmgmt.unsupported_reason is empty — expected to work, untested
  not-yet     a programming model or load step I have not implemented
  plugin      configured by a manufacturer ETS plugin (DLL): not reproducible
  fail        my parser cannot load the program (a bug on my side)
  unswept     not run yet"""
import html, json, sqlite3
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DB = HERE / 'index.sqlite'
REPORTS = HERE / 'reports.json'
OUT = HERE.parent / 'docs'    # published at https://b0bs0n.github.io/baccata/
REPO = 'https://github.com/b0bs0n/baccata'

# devices programmed and verified against the real bus: (M-xxxx_A-nnnn, note)
TESTED = [
    ('M-0008_A-20DC', 'Gira Schaltaktor 24f/Jalousie 12f, recovered + verified'),
    ('M-0048_A-7315', 'Theben Cheops S, verify matches'),
    ('M-0083_A-00B6', 'MDT BE-02, verify matches'),
    ('M-0080_A-7018', 'ESYLUX PD-C180i KNX ECO, TaskSegment/TaskCtrl1 + dynamic tables, param change programmed + verified, sparse write'),
]
# active manufacturers whose product databases I could not get (scout 2026-09-03);
# not rendered on the site, kept as a record
WANTED = {
    'Bticino': 'no public download', 'LEGRAND': 'admin.legrandoc.com unreachable',
    'Griesser': 'login', 'Feller': 'login', 'Basalte': 'login', 'Crestron': 'login',
    'LOYTEC': 'login', 'GEWISS': 'login', 'Intesis': 'login', 'Sauter': 'login',
    'Beckhoff': 'no public download', 'WAGO': 'zip on wago.com has no knxprod',
    'Somfy': 'no public download', 'WAREMA': 'no public download',
    'Zehnder': 'no public download', 'HDL': 'no public download',
    'Becker-Antriebe': 'no public download', 'Viessmann': 'no public download',
    'Uponor': 'no public download', 'Ekinex': 'no public download',
    'Insta': 'unverified page lead',
    'Eelectron': 'per-product pages, no index', 'Dinuy': 'per-product pages, no index',
    'Interra': 'Google Drive folder',
}

STATUS = ['tested', 'supported', 'not-yet', 'plugin', 'fail', 'unswept']
LABEL = {'tested': 'bus-tested', 'supported': 'supported', 'not-yet': 'not yet',
         'plugin': 'needs ETS plugin', 'fail': 'parser fails', 'unswept': 'unswept'}
BLURB = {
    'tested': 'programmed with Baccata and read back byte-for-byte on a real bus.',
    'supported': 'programming model and every load step implemented. '
                 'Should work; nobody has tried it on hardware yet.',
    'not-yet': 'a programming model (BCU2, System 300, couplers) or a load step '
               'I have not implemented. Fixable; a packet capture helps most.',
    'plugin': 'the product is configured by a manufacturer ETS plugin, a DLL '
              'inside the product database. Its logic is not in the XML, so '
              'there is nothing to reproduce. Blocked for good.',
    'fail': 'my parser raises on the product database. A bug on my side.',
    'unswept': 'not swept yet.',
}

CSS = """
body{font:15px/1.45 system-ui,sans-serif;margin:0 auto;padding:1em 2em;max-width:1200px;color:#222;background:#fff}
h1{margin-bottom:0}.sub{color:#666;margin-top:.2em}
nav a{margin-right:1.2em}nav{margin:.6em 0 1.4em}
.kpi{display:flex;gap:1em;flex-wrap:wrap;margin:1.2em 0}
.kpi div{border:1px solid #ddd;border-radius:6px;padding:.6em 1em;min-width:8em}
.kpi b{display:block;font-size:1.6em}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border-bottom:1px solid #eee;padding:.3em .6em;text-align:left;white-space:nowrap;vertical-align:top}
th{background:#f6f6f6;position:sticky;top:0}
td.n{text-align:right;font-variant-numeric:tabular-nums}
td.w{white-space:normal}
.bar{display:inline-block;height:.8em;vertical-align:middle}
.tested{background:#2a7}.supported{background:#8d8}.not-yet{background:#ea3}
.plugin{background:#c33}.fail{background:#a3c}.unswept{background:#ccc}
.tag{display:inline-block;padding:0 .5em;border-radius:3px;font-size:.85em;color:#000}
.tag.plugin,.tag.tested,.tag.fail{color:#fff}
dl.legend dt{font-weight:bold;margin-top:.5em}dl.legend dd{margin:0 0 0 1em}
input[type=search]{font:inherit;padding:.4em .6em;width:24em;max-width:100%}
.hidden{display:none}
details{margin:1em 0}summary{cursor:pointer;font-weight:bold}
code{font-size:.9em}
"""

# one search box + status select, one table: rows whose text does not contain
# every word, or whose status tag is not the selected one, vanish
FILTER_JS = """<script>
const q=document.querySelector('input[type=search]'),st=document.querySelector('#st'),rows=[...document.querySelectorAll('tbody tr')];
function f(){const w=q.value.toLowerCase().split(/\\s+/).filter(Boolean),c=st.value;
for(const r of rows){const t=r.textContent.toLowerCase();r.classList.toggle('hidden',(c&&!r.querySelector('.tag.'+c))||!w.every(x=>t.includes(x)))}}
q.addEventListener('input',f);st.addEventListener('change',f);
</script>"""


def status_select():
    return ('<select id=st><option value="">all statuses'
            + ''.join(f'<option value={st}>{esc(LABEL[st])}' for st in STATUS) + '</select>')


def esc(s):
    return html.escape(str(s if s is not None else ''))


def pct(a, b):
    return f'{100 * a / b:.0f}%' if b else '–'


def bar(counts, total):
    if not total:
        return ''
    return ''.join(f'<span class="bar {st}" style="width:{100 * counts[st] / total:.0f}%"></span>'
                   for st in STATUS if counts[st])


def tag(st):
    return f'<span class="tag {st}">{LABEL[st]}</span>'


def page(title, body, depth=0, search=False):
    up = '../' * depth
    nav = (f'<nav><a href="{up}index.html">Overview</a>'
           f'<a href="{up}products.html">Product search</a>'
           f'<a href="{up}masks.html">By programming model</a>'
           f'<a href="{REPO}">Baccata on GitHub</a></nav>')
    return (f'<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">'
            f'<title>{esc(title)}</title><style>{CSS}</style>{nav}{body}'
            + (FILTER_JS if search else ''))


def classify(status, unsup, apid, tested_apps):
    if status is None:
        return 'unswept', ''
    if status == 'fail':
        return 'fail', unsup
    if not unsup:
        return ('tested' if apid[:13] in tested_apps else 'supported'), ''
    if 'plugin' in unsup:
        return 'plugin', 'ETS plugin'
    # short label for the not-yet family
    if 'not implemented yet' in unsup:
        return 'not-yet', 'load step ' + unsup.split('load step ')[1].split(' (')[0]
    if 'programming model' in unsup:
        return 'not-yet', unsup.split('programming model ')[1].split(' is')[0]
    if 'no knx_master.xml' in unsup:
        return 'not-yet', 'no load procedure in database'
    return 'not-yet', unsup


def load_reports():
    """Verify reports by application (apid[:13]): ({key: [match reports]},
    {key: [mismatch/error reports]})."""
    try:
        reports = json.loads(REPORTS.read_text())
    except (OSError, ValueError):
        reports = []
    ok, findings = defaultdict(list), defaultdict(list)
    for r in reports:
        key = r.get('device', {}).get('apid', '')[:13]
        if not key:
            continue
        (ok if r.get('verify', {}).get('outcome') == 'match'
         else findings)[key].append(r)
    return ok, findings


def main():
    db = sqlite3.connect(DB)
    q = lambda sql: db.execute(sql).fetchall()
    verified, findings = load_reports()
    tested_apps = {k for k, _ in TESTED} | set(verified)
    mfrs = dict(q('select distinct mdir, mfr_name from product'))
    # per program: status
    prog = {}
    for sha, mdir, mask, apid, status, err, unsup, model in q(
            '''select p.sha256, p.mdir, p.mask, p.apid, s.status, s.error, s.unsupported, s.model
               from (select distinct sha256, mdir, mask, apid from product) p
               left join sweep s on s.sha256=p.sha256 and s.apid=p.apid'''):
        st, why = classify(status, unsup if status != 'fail' else err, apid, tested_apps)
        prog[sha, apid] = (mdir, mask, model or '', st, why)
    items = q('select sha256, mdir, item_name, order_no, apid, mask from product '
              'order by mfr_name, item_name')

    by_mfr = defaultdict(lambda: defaultdict(int))
    by_mask = defaultdict(lambda: defaultdict(int))
    reasons = defaultdict(lambda: defaultdict(int))
    models = defaultdict(set)
    total = defaultdict(int)
    for (sha, apid), (mdir, mask, model, st, why) in prog.items():
        by_mfr[mdir][st] += 1
        by_mask[mask or '?'][st] += 1
        total[st] += 1
        if model:
            models[mask].add(model)
        if why and st != 'fail':
            reasons[mdir][why] += 1
    n_prog = len(prog)
    n_items = len(items)
    n_files = len({sha for sha, _ in prog})

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'm').mkdir(exist_ok=True)

    # ---- index
    b = ['<h1>Which KNX devices can Baccata program?</h1>',
         f'<p class=sub>{n_files} product databases from {len(mfrs)} manufacturers, '
         f'{n_items} products, {n_prog} application programs, checked offline against '
         'the current code. Baccata refuses any device it cannot fully program and '
         'read back, so "supported" here is the test the app itself applies.</p>',
         '<div class=kpi>']
    for st in STATUS:
        if total[st]:
            b.append(f'<div><b>{total[st]}</b>{LABEL[st]} <small>({pct(total[st], n_prog)})</small></div>')
    b.append('</div>')
    b.append('<dl class=legend>' + ''.join(
        f'<dt>{tag(st)}</dt><dd>{BLURB[st]}</dd>' for st in STATUS) + '</dl>')

    b.append('<h2>By manufacturer</h2><p>Only manufacturers whose product databases I '
             'have. Click a name for its products, or use the '
             '<a href="products.html">product search</a>.</p>')
    b.append('<table><tr><th>manufacturer<th>products<th>programs<th>bus-tested<th>supported'
             '<th>not yet<th>plugin<th>fails<th><th>why not</tr>')
    n_items_by = defaultdict(int)
    for _, mdir, *_ in items:
        n_items_by[mdir] += 1
    for mdir, name in sorted(mfrs.items(), key=lambda kv: -sum(by_mfr[kv[0]].values())):
        c = by_mfr[mdir]
        n = sum(c.values())
        why = ', '.join(f'{k} ({v})' for k, v in sorted(reasons[mdir].items(), key=lambda kv: -kv[1]))
        b.append(f'<tr><td><a href="m/{mdir}.html">{esc(name)}</a><td class=n>{n_items_by[mdir]}'
                 f'<td class=n>{n}<td class=n>{c["tested"] or ""}<td class=n>{c["supported"] or ""}'
                 f'<td class=n>{c["not-yet"] or ""}<td class=n>{c["plugin"] or ""}'
                 f'<td class=n>{c["fail"] or ""}<td style="width:14%">{bar(c, n)}'
                 f'<td class=w><small>{esc(why)}</small></tr>')
    b.append('</table>')

    b.append(f'''<h2 id=help>How to help</h2>
<p>Everything above comes from product databases and offline checks. What moves a device
from "supported" to "bus-tested", or from "not yet" to "supported", is evidence from real
hardware:</p>
<ul>
<li><b>Verify a device.</b> In Baccata, <i>Import…</i> your ETS project (or add the device),
<i>Verify</i> it (read-only), then <i>Report…</i> — it files an
<a href="{REPO}/issues?q=label%3Averify-report">issue</a> with ids and checksums only, and this
page updates itself. A mismatch is as useful as a match.</li>
<li><b>A packet capture of ETS programming a device.</b> Every model in Baccata was built
from one: run Wireshark on the KNX/IP tunnel while ETS does a full download, and attach the
<code>.pcapng</code> plus the ETS project export (<code>.knxproj</code>). The capture pins
the exact bytes and the load sequence, so I can reproduce it without owning the device. Use
a <i>plain</i> (non-IP-Secure) tunnel so the frames are readable; a KNX Data Secure device is
fine if you send its FDSK too. Most wanted:
BCU2 (<code>MV-0020/0021/0025</code>), System 300 (<code>MV-0300</code>),
a BIM M112 device with <code>LdCtrlTaskPtr</code>/<code>TaskCtrl2</code> steps, a BCU1 device
with group objects, and a KNX Secure BIM M112 device.</li>
</ul>
<p>Not worth reporting: products marked "needs ETS plugin". Their configuration lives in a
manufacturer DLL; no capture changes that.</p>''')
    if verified or findings:
        b.append(f'<h2 id=reports>Verify reports</h2><p>{sum(map(len, verified.values()))} '
                 f'match(es), {sum(map(len, findings.values()))} finding(s) filed by users.</p>')
        b.append('<table><tr><th>app<th>mask<th>outcome<th>segments<th>issue</tr>')
        for key in sorted(set(verified) | set(findings)):
            for r in verified.get(key, []) + findings.get(key, []):
                v = r.get('verify', {})
                segs = ', '.join(f'{s.get("id")} {"ok" if s.get("match") else "differs"}'
                                 for s in v.get('segments', []))
                b.append(f'<tr><td><code>{esc(key)}</code><td><code>{esc(r["device"].get("mask"))}'
                         f'</code><td>{esc(v.get("outcome"))}<td class=w><small>{esc(segs)}</small>'
                         f'<td><a href="{esc(r.get("url"))}">#{esc(r.get("issue"))}</a></tr>')
        b.append('</table>')
    (OUT / 'index.html').write_text(page('Baccata device support', '\n'.join(b)))

    # ---- product table (shared by products.html and the per-manufacturer pages)
    def rows(sel):
        out = ['<table><thead><tr><th>manufacturer<th>product<th>order no.<th>program'
               '<th>mask<th>status<th>why</tr></thead><tbody>']
        for sha, mdir, name, order, apid, mask in sel:
            _, _, model, st, why = prog[sha, apid]
            key = apid[:13]
            if verified.get(key):
                why = f'verified by users ({len(verified[key])})'
            if findings.get(key):
                why = (why + '; ' if why else '') + ' '.join(
                    f'<a href="{esc(r["url"])}">finding #{esc(r["issue"])}</a>'
                    for r in findings[key])
            out.append(f'<tr><td>{esc(mfrs[mdir])}<td class=w>{esc(name)}<td>{esc(order)}'
                       f'<td><code>{esc(apid[7:20])}</code><td><code>{esc(mask)}</code> '
                       f'<small>{esc(model)}</small><td>{tag(st)}<td class=w><small>{why}</small></tr>')
        out.append('</tbody></table>')
        return '\n'.join(out)

    b = ['<h1>Product search</h1>',
         f'<p class=sub>{n_items} products. Type part of a product name, order number or '
         'manufacturer; more words narrow it down.</p>',
         f'<p><input type=search placeholder="e.g. mdt jalousie" autofocus> {status_select()}</p>', rows(items)]
    (OUT / 'products.html').write_text(page('Baccata product search', '\n'.join(b), search=True))

    for mdir, name in mfrs.items():
        c = by_mfr[mdir]
        n = sum(c.values())
        sel = [r for r in items if r[1] == mdir]
        b = [f'<h1>{esc(name)}</h1>',
             f'<p class=sub>{len(sel)} products, {n} application programs. '
             + ', '.join(f'{c[st]} {LABEL[st]}' for st in STATUS if c[st]) + '</p>',
             f'<p>{bar(c, n)}</p>',
             f'<p><input type=search placeholder="filter"> {status_select()}</p>', rows(sel)]
        (OUT / 'm' / f'{mdir}.html').write_text(page(f'{name} – Baccata', '\n'.join(b), depth=1, search=True))

    # ---- masks
    b = ['<h1>By programming model</h1>',
         '<p class=sub>The mask version names the device\'s system software, and with it '
         'the download procedure. Baccata dispatches on it.</p>',
         '<table><tr><th>mask<th>model<th>programs<th>bus-tested<th>supported<th>not yet'
         '<th>plugin<th>fails<th></tr>']
    for mask, c in sorted(by_mask.items(), key=lambda kv: -sum(kv[1].values())):
        n = sum(c.values())
        b.append(f'<tr><td><code>{esc(mask)}</code><td>{esc(", ".join(sorted(models[mask])))}'
                 f'<td class=n>{n}<td class=n>{c["tested"] or ""}<td class=n>{c["supported"] or ""}'
                 f'<td class=n>{c["not-yet"] or ""}<td class=n>{c["plugin"] or ""}'
                 f'<td class=n>{c["fail"] or ""}<td style="width:20%">{bar(c, n)}</tr>')
    b.append('</table><h2>Bus-tested devices</h2><table><tr><th>app<th>note</tr>')
    for key, note in TESTED:
        b.append(f'<tr><td><code>{key}</code><td>{esc(note)}</tr>')
    for key, rs in sorted(verified.items()):
        b.append(f'<tr><td><code>{key}</code><td>{len(rs)} user report(s), latest '
                 f'{esc(max(r.get("created", "") for r in rs))}</tr>')
    b.append('</table>')
    (OUT / 'masks.html').write_text(page('Baccata – programming models', '\n'.join(b)))
    print(f'{OUT}: {len(mfrs)} manufacturers, ' + ', '.join(f'{total[s]} {s}' for s in STATUS))


if __name__ == '__main__':
    main()

"""Verify report: what a user files after Verify so the device-support site
learns which application programs check out on real hardware.

Identifiers, numbers and hashes only. Product name and order number are
catalogue facts the site already publishes; nothing else about the
installation leaves the machine — no device names, addresses, group
addresses, parameter values, tags, comments, hosts, serials, project name.
`redact_check` is the test's proof of that.
"""
import hashlib, json, platform
from urllib.parse import quote

from . import __version__ as VERSION
from .knxip import ga_str

REPO = 'https://github.com/b0bs0n/baccata'
URL_MAX = 6000            # beyond this the body rides on the clipboard


def program_sha256(project, dev):
    """Hash of the application program XML itself, so the same program is
    recognised whether it came from the vendor file or a knxproj re-pack."""
    try:
        kp = project.prod(dev.product)
        return hashlib.sha256(
            kp.zf.read(f'{kp.mdir}/{dev.variant}.xml')).hexdigest()
    except Exception:
        return ''


def _product(project, dev):
    """(product text, order number) — from the import, else the catalog."""
    info = dev.info
    if info.get('product') or info.get('order_no'):
        return info.get('product', ''), info.get('order_no', '')
    try:
        name = next(n for n, a in project.prod(dev.product).items
                    if a == dev.variant)
    except Exception:
        name = ''
    return name, ''


def payload(project, dev, result, conn=None):
    """The report as a dict (the JSON block of the issue)."""
    prog = project.program_or_none(dev)
    product, order_no = _product(project, dev)
    sec = dev.sec or {}
    return {
        'report': 1, 'baccata': VERSION,
        'platform': f'{platform.system()} {platform.release()}',
        'device': {
            'manufacturer': dev.variant.split('_')[0],
            'apid': dev.variant,
            'app_number': prog.app_number if prog else None,
            'app_version': prog.app_version if prog else None,
            'mask': prog.mask if prog else '',
            'model': prog.model if prog else '',
            'procstyle': prog.procstyle if prog else '',
            'secure': bool(prog and prog.secure),
            'dyntab': bool(prog and prog.dyntab),
            'product': product, 'order_no': order_no,
            'program_sha256': program_sha256(project, dev)},
        'source': {'project': 'knxproj' if dev.info.get('ets_id') else 'baccata',
                   'ets': dev.info.get('ets')},
        'connection': {'type': (conn or {}).get('type', ''),
                       'data_secure': bool(sec.get('tool_key'))},
        'verify': {
            'outcome': result.outcome, 'error': result.error,
            'descriptor': result.descriptor, 'app_id_ok': result.app_id_ok,
            'segments': result.segments,
            'params_differ': result.params_differ,
            'links_differ': result.links_differ}}


def verify_report(project, dev, result, conn=None):
    """(issue title, issue body in Markdown with the JSON block)."""
    d = payload(project, dev, result, conn)
    dv = d['device']
    title = (f'Verify: {dv["apid"][:13]} {dv["mask"]} — {result.outcome}')
    head = [f'**{dv["product"] or dv["apid"]}**'
            + (f' ({dv["order_no"]})' if dv['order_no'] else ''),
            f'{dv["mask"]} {dv["model"]}, Baccata {VERSION}',
            f'Verify: **{result.outcome}**'
            + (f' — {result.error}' if result.error else '')]
    for seg in result.segments:
        head.append(f'- {seg["id"]}: {"ok" if seg["match"] else "differs"}'
                    + (f' ({seg["diff_count"]} byte(s))'
                       if seg['diff_count'] else ''))
    body = '\n'.join(head) + '\n\n```json\n' + json.dumps(d, indent=1) + '\n```\n'
    return title, body


def github_issue_url(title, body):
    """Prefilled new-issue URL for the verify-report form. A long body is
    left off (it is on the clipboard); the form says to paste it."""
    url = (f'{REPO}/issues/new?template=verify-report.yml'
           f'&title={quote(title)}')
    full = url + f'&report={quote(body)}'
    return full if len(full) <= URL_MAX else url


def redact_check(text, project, dev):
    """Strings from the installation that must not appear in `text`.
    Returns the offending ones (empty = clean)."""
    secrets = [dev.name, dev.ia, project.name, *dev.tags,
               dev.info.get('comment', ''), *map(str, dev.values.values()),
               *(ga_str(g) for gas in dev.links.values() for g in gas),
               *(c.get('host', '') for c in project.connections),
               *(c.get('password', '') for c in project.connections),
               *(v for v in (dev.sec or {}).values() if isinstance(v, str))]
    public = {dev.info.get('product', ''), dev.info.get('order_no', '')}
    return sorted({s for s in secrets
                   if s and len(s) > 1 and s not in public and s in text})

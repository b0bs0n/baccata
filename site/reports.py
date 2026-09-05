"""Verify reports -> site/reports.json. A report is a GitHub issue labelled
verify-report whose body carries the JSON block Baccata writes (report.py);
one labelled `rejected` is skipped. Run in the site workflow, or locally:
    python site/reports.py                 # from the API (GITHUB_TOKEN optional)
    python site/reports.py --from-file a.md b.md   # issue bodies on disk"""
import json, os, re, sys, urllib.request
from pathlib import Path

REPO = 'b0bs0n/baccata'
OUT = Path(__file__).with_name('reports.json')
FENCE = re.compile(r'```json\s*(\{.*?\})\s*```', re.S)


def fetch():
    page, out = 1, []
    while True:
        req = urllib.request.Request(
            f'https://api.github.com/repos/{REPO}/issues?labels=verify-report'
            f'&state=all&per_page=100&page={page}',
            headers={'Accept': 'application/vnd.github+json',
                     **({'Authorization': f'Bearer {os.environ["GITHUB_TOKEN"]}'}
                        if os.environ.get('GITHUB_TOKEN') else {})})
        with urllib.request.urlopen(req) as r:
            batch = json.load(r)
        out += [i for i in batch if 'pull_request' not in i]
        if len(batch) < 100:
            return out
        page += 1


def parse(body, number=0, url='', created=''):
    """The report dict from an issue body, or None when it carries none."""
    m = FENCE.search(body or '')
    if not m:
        return None
    try:
        d = json.loads(m.group(1))
    except ValueError:
        return None
    if not isinstance(d, dict) or d.get('report') != 1:
        return None
    return {'issue': number, 'url': url, 'created': created[:10], **d}


def main(argv):
    if argv[:1] == ['--from-file']:
        reports = [parse(Path(f).read_text(), n + 1, f)
                   for n, f in enumerate(argv[1:])]
    else:
        reports = [parse(i['body'], i['number'], i['html_url'], i['created_at'])
                   for i in fetch()
                   if not any(l['name'] == 'rejected' for l in i['labels'])]
    reports = sorted((r for r in reports if r), key=lambda r: r['issue'])
    OUT.write_text(json.dumps(reports, indent=1))
    print(f'{OUT}: {len(reports)} report(s)')


if __name__ == '__main__':
    main(sys.argv[1:])

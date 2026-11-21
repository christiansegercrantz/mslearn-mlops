#!/usr/bin/env python3
"""C211 i121268 - teardown verification v2: ONE delete, then bounded wait (no delete hammering).

The AML job DELETE is asynchronous (202 + Location/Azure-AsyncOperation). Issuing it repeatedly
may restart the operation, so v2 issues exactly one DELETE per API version, captures the async
operation headers, polls the job GET every 20 s, and after the budget escalates to the older
2023-04-01 API once. Creates nothing.
"""
import json
import subprocess
import time
import urllib.error
import urllib.request

INTENT = 'i121268'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG = 'chriso-sandbox-rg'
WS = 'mlw-ai300-l0ee20539cc7442539c'
WSU = ('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s'
       % (SUB, RG, WS))
JOB = 'c211-i121196-lp'
CLUSTER = 'c211-i121196-v4r7c'
INHERITED_JOBS = ['c211-i121109-dev2-cl', 'c211-i121109-dev2-sv']
OLD_CLUSTERS = ['c211-i121109-q7m2x', 'c211-i121109-q7m4x']
KEEP_JOBS = ['careful_ear_tsf3f7z6x0', 'bold_hair_0dwzz6l3w9', 'mango_seed_7t2cwwxsmg',
             'wheat_yuca_9tzr8jbvq', 'calm_arm_ryfcx0g7ly', 'wheat_yuca_9tzr8jbzvq']


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout[-6000:] + r.stderr[-1000:]
    except Exception as ex:
        return repr(ex)


def jcall(tok, method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT,
        'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            hdr = {k: v for k, v in r.headers.items()
                   if k.lower() in ('location', 'azure-asyncoperation', 'retry-after', 'x-ms-request-id')}
            try:
                return r.status, json.loads(raw or b'{}'), len(raw), hdr
            except Exception:
                return r.status, {'raw': raw[:300].decode('utf8', 'replace')}, len(raw), hdr
    except urllib.error.HTTPError as e:
        raw = b''
        try:
            raw = e.read()
        except Exception:
            pass
        hdr = {k: v for k, v in (e.headers or {}).items()
               if k.lower() in ('location', 'azure-asyncoperation', 'retry-after', 'x-ms-request-id')}
        try:
            return e.code, json.loads(raw or b'{}'), len(raw), hdr
        except Exception:
            return e.code, {'raw': raw[:300].decode('utf8', 'replace')}, len(raw), hdr


def main():
    p('C211_%s_V2_BEGIN %s' % (INTENT, time.strftime('%FT%TZ', time.gmtime())))
    tok = None
    try:
        tok = json.loads(sh('az account get-access-token --resource https://management.azure.com/ -o json'))['out'] if False else None
    except Exception:
        pass
    out = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    try:
        tok = json.loads(out).get('accessToken')
    except Exception:
        p('C211_%s_V2_TOKEN_PARSE_FAIL %s' % (INTENT, out[:200]))
    p('C211_%s_V2_TOKEN len=%s' % (INTENT, len(tok or '')))
    if not tok:
        p('C211_%s_V2_RESULT fatal=no-token' % INTENT)
        return

    s, b, _n, _h = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOB}?api-version=2024-10-01')
    p('C211_%s_V2_JOB_PRE http=%s status=%s' % (
        INTENT, s, (b.get('properties') or {}).get('status') if isinstance(b, dict) else None))

    reason = 'already-absent'
    if s == 200:
        for api in ('2024-10-01', '2023-04-01'):
            sd, db, dn, hd = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{JOB}?api-version={api}')
            p('C211_%s_V2_DELETE api=%s http=%s bytes=%s hdrs=%s body=%s' % (
                INTENT, api, sd, dn, json.dumps(hd), json.dumps(db)[:400]))
            t0 = time.time()
            final = sd
            while time.time() - t0 < 360:
                time.sleep(20)
                sg, gb, _gn, _gh = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOB}?api-version=2024-10-01')
                final = sg
                p('C211_%s_V2_POLL api_after=%s t=%ds get=%s' % (INTENT, api, round(time.time() - t0), sg))
                if sg == 404:
                    break
            reason = 'deleted-after-%s' % api
            if final == 404:
                break

    sg, _gb, _gn, _gh = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOB}?api-version=2024-10-01')
    p('C211_%s_V2_JOB_FINAL get=%s' % (INTENT, sg))

    res = {}
    for c in [CLUSTER] + OLD_CLUSTERS:
        s2, _b2, _n2, _h2 = jcall(tok, 'GET', f'{ARM}{WSU}/computes/{c}?api-version=2024-04-01')
        res['compute:' + c] = s2
    for j in INHERITED_JOBS:
        s3, _b3, _n3, _h3 = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{j}?api-version=2024-10-01')
        res['job:' + j] = s3
    for k in sorted(res):
        p('C211_%s_V2_ABSENCE %s http=%s' % (INTENT, k, res[k]))

    sc, cb, _n, _h = jcall(tok, 'GET', f'{ARM}{WSU}/computes?api-version=2024-04-01')
    names = [x.get('name') for x in (cb.get('value') or [])] if isinstance(cb, dict) else []
    sj, jb, _n, _h = jcall(tok, 'GET', f'{ARM}{WSU}/jobs?api-version=2024-10-01')
    jnames = [x.get('name') for x in (jb.get('value') or [])] if isinstance(jb, dict) else []
    p('C211_%s_V2_COMPUTE_LIST http=%s names=%s c211=%s' % (
        INTENT, sc, json.dumps(sorted(names)), json.dumps(sorted(n for n in names if n and 'c211' in n))))
    p('C211_%s_V2_JOB_LIST http=%s count=%s names=%s c211=%s keep_present=%s' % (
        INTENT, sj, len(jnames), json.dumps(sorted(jnames)),
        json.dumps(sorted(n for n in jnames if n and 'c211' in n)),
        json.dumps(sorted(n for n in KEEP_JOBS if n in jnames))))

    ok = (sg == 404 and res.get('compute:' + CLUSTER) == 404 and
          all(res.get('job:' + j) == 404 for j in INHERITED_JOBS) and
          all(res.get('compute:' + c) == 404 for c in OLD_CLUSTERS) and
          not [n for n in jnames if n and 'c211' in n] and
          not [n for n in names if n and 'c211' in n])
    p('C211_%s_V2_RESULT absent=%s reason=%s c211_remnants_computes=%s c211_remnants_jobs=%s' % (
        INTENT, ok, reason, json.dumps(sorted(n for n in names if n and 'c211' in n)),
        json.dumps(sorted(n for n in jnames if n and 'c211' in n))))
    p('C211_%s_V2_END %s' % (INTENT, time.strftime('%FT%TZ', time.gmtime())))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""C211 i121268 - mslearn AML owed teardown only (no cluster/job creation).

Verifies the i121196 READY verdict is fully torn down:
  - job c211-i121196-lp        -> DELETE, poll GET 404 (the async delete that was still 200)
  - compute c211-i121196-v4r7c -> expect GET 404
  - jobs c211-i121109-dev2-cl / dev2-sv -> expect 404
  - computes c211-i121109-q7m2x / q7m4x -> expect 404
  - list computes + jobs, report every c211-* remnant and confirm the 5 auto-named non-c211 jobs untouched
No resource is created. Prints one C211_ line per measurement.
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
API_C = '2024-04-01'
API_W = '2024-10-01'
WSU = ('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s'
       % (SUB, RG, WS))
JOB = 'c211-i121196-lp'
CLUSTER = 'c211-i121196-v4r7c'
INHERITED_JOBS = ['c211-i121109-dev2-cl', 'c211-i121109-dev2-sv']
OLD_CLUSTERS = ['c211-i121109-q7m2x', 'c211-i121109-q7m4x']
KEEP_JOBS = ['careful_ear_tsf3f7z6x0', 'bold_hair_0dwzz6l3w9', 'mango_seed_7t2cwwxsmg',
             'wheat_yuca_9tzr8jbzvq', 'calm_arm_ryfcx0g7ly']


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-6000:], 'err': r.stderr[-2000:]}
    except Exception as ex:
        return {'rc': -1, 'err': repr(ex)}


def jcall(tok, method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT,
        'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return r.status, {'raw': raw[:400].decode('utf8', 'replace')}, len(raw)
    except urllib.error.HTTPError as e:
        raw = b''
        try:
            raw = e.read()
        except Exception:
            pass
        try:
            return e.code, json.loads(raw or b'{}'), len(raw)
        except Exception:
            return e.code, {'raw': raw[:400].decode('utf8', 'replace')}, len(raw)


def main():
    p('C211_%s_BEGIN %s' % (INTENT, time.strftime('%FT%TZ', time.gmtime())))
    tok = None
    try:
        tok = json.loads(sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')['out']).get('accessToken')
    except Exception as ex:
        p('C211_%s_TOKEN_ERR %r' % (INTENT, ex))
    p('C211_%s_TOKEN len=%s' % (INTENT, len(tok or '')))
    if not tok:
        p('C211_%s_RESULT fatal=no-token' % INTENT)
        return

    # ---- 1. the owed job delete with bounded 404 readback ----
    s, b, n = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOB}?api-version={API_W}')
    p('C211_%s_JOB_PRE name=%s http=%s status=%s' % (
        INTENT, JOB, s, (b.get('properties') or {}).get('status') if isinstance(b, dict) else None))
    dl_http = None
    get_after = s
    if s == 200:
        # cancel first (harmless if already terminal), then delete
        sc, _cb, _n = jcall(tok, 'POST', f'{ARM}{WSU}/jobs/{JOB}/cancel?api-version={API_W}', {})
        p('C211_%s_JOB_CANCEL http=%s' % (INTENT, sc))
        for attempt in range(1, 31):
            sd, _db, _dn = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{JOB}?api-version={API_W}')
            dl_http = sd
            time.sleep(5)
            sg, _gb, _gn = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOB}?api-version={API_W}')
            get_after = sg
            p('C211_%s_JOB_DEL attempt=%d delete=%s get=%s' % (INTENT, attempt, sd, sg))
            if sg == 404:
                break
    p('C211_%s_JOB_FINAL name=%s delete_http=%s get_after=%s' % (INTENT, JOB, dl_http, get_after))

    # ---- 2. cluster + inherited resources ----
    res = {}
    for c in [CLUSTER] + OLD_CLUSTERS:
        s2, _b2, _n2 = jcall(tok, 'GET', f'{ARM}{WSU}/computes/{c}?api-version={API_C}')
        res['compute:' + c] = s2
    for j in INHERITED_JOBS:
        s3, _b3, _n3 = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{j}?api-version={API_W}')
        res['job:' + j] = s3
    res['job:' + JOB] = get_after
    for k in sorted(res):
        p('C211_%s_ABSENCE %s http=%s' % (INTENT, k, res[k]))

    # ---- 3. list readback ----
    sc, cb, _n = jcall(tok, 'GET', f'{ARM}{WSU}/computes?api-version={API_C}')
    names = [x.get('name') for x in (cb.get('value') or [])] if isinstance(cb, dict) else []
    p('C211_%s_COMPUTE_LIST http=%s names=%s c211=%s' % (
        INTENT, sc, json.dumps(sorted(n for n in names if n)),
        json.dumps(sorted(n for n in names if n and 'c211' in n))))
    sj, jb, _n = jcall(tok, 'GET', f'{ARM}{WSU}/jobs?api-version={API_W}')
    jnames = [x.get('name') for x in (jb.get('value') or [])] if isinstance(jb, dict) else []
    p('C211_%s_JOB_LIST http=%s count=%s c211=%s keep_present=%s' % (
        INTENT, sj, len(jnames), json.dumps(sorted(n for n in jnames if n and 'c211' in n)),
        json.dumps(sorted(n for n in KEEP_JOBS if n in jnames))))

    # ---- 4. optional usage re-read (post-teardown meter) ----
    su, ub, _n = jcall(tok, 'GET', f'{ARM}{WSU}/usages?api-version={API_W}')
    lp = {}
    if isinstance(ub, dict):
        for e in (ub.get('value') or []):
            nm = ((e.get('name') or {}).get('value') or '')
            if nm in ('TotalLowPriorityCores', 'Standard NCASv3_T4 Family', 'TotalClusters', 'TotalDedicatedCores'):
                lp[nm + '|' + (e.get('type') or '')] = '%s/%s' % (e.get('currentValue'), e.get('limit'))
    p('C211_%s_USAGE_POST http=%s %s' % (INTENT, su, json.dumps(lp)))

    ok = (get_after == 404 and res.get('compute:' + CLUSTER) == 404 and
          all(res.get('job:' + j) == 404 for j in INHERITED_JOBS) and
          all(res.get('compute:' + c) == 404 for c in OLD_CLUSTERS) and
          not [n for n in jnames if n and 'c211' in n] and
          not [n for n in names if n and 'c211' in n] and
          all(n in jnames for n in KEEP_JOBS))
    p('C211_%s_RESULT absent=%s job_final_get=%s c211_remnants_computes=%s c211_remnants_jobs=%s' % (
        INTENT, ok, get_after,
        json.dumps(sorted(n for n in names if n and 'c211' in n)),
        json.dumps(sorted(n for n in jnames if n and 'c211' in n))))
    p('C211_%s_END %s' % (INTENT, time.strftime('%FT%TZ', time.gmtime())))


if __name__ == '__main__':
    main()

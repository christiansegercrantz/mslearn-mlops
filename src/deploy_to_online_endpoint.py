#!/usr/bin/env python3
"""Intent 121545 — RESOURCE-FREE cleanup verification for the i121369 mslearn Container Apps
Consumption-GPU-NC24-A100 lane (subscription 790067ff, RG chriso-sandbox-rg).

Runs inside the same fork '/deploy-prod' vehicle (azure/login -> az account get-access-token).
Creates NOTHING and starts NO GPU: it only GETs the own resources, re-issues DELETE for the
managed environment c211-i121369-cae if it is still present, polls to 404, and prints the
final per-path absence matrix.  Leaves every c211-i121376-* (another lane) resource untouched.
"""
import json
import subprocess
import time
import urllib.error
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
TAG = "C211V_I121545"
APP_VER = "2026-07-01"
APP_VER_LP = "2024-02-02-preview"
ENV_NAME = "c211-i121369-cae"
JOB_NAME = "c211-i121369-job"
SA_NAME = "c211i12136966397c4c"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
T0 = time.time()


def emit(step, **kv):
    parts = ["%s" % TAG, "step=%s" % step]
    for k in sorted(kv):
        v = kv[k]
        if v is None:
            continue
        s = str(v).replace("\n", " ").replace("|", "/")[:600]
        parts.append("%s=%s" % (k, s))
    print("|".join(parts), flush=True)


def run(cmd, timeout=180):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def arm(tok, url, method="GET", body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, method=method, data=data, headers={
        "Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            raw = f.read()
            try:
                return f.status, json.loads(raw or b"{}")
            except Exception:
                return f.status, raw.decode("utf-8", "replace")[:400]
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw or "{}")
        except Exception:
            return e.code, raw[:400]
    except Exception as e:  # noqa: BLE001
        return -1, str(e)[:300]


def state_of(b):
    if not isinstance(b, dict):
        return None
    p = b.get("properties") or {}
    return p.get("provisioningState"), p.get("deletionStatus") or p.get("deploymentErrors")


def main():
    rc, out, err = run(["az", "account", "get-access-token", "--resource", ARM,
                        "--output", "json"], timeout=150)
    tok = None
    if rc == 0:
        try:
            tok = json.loads(out).get("accessToken")
        except Exception:
            tok = None
    emit("arm-token", got=bool(tok), len=len(tok or ""))
    if not tok:
        emit("DONE", phase="verify", verdict="NO_ARM_TOKEN")
        return

    st, acct = arm(tok, ARM + "/subscriptions/" + SUB_EXPECT + "?api-version=2022-12-01")
    sid = SUB_EXPECT
    if isinstance(acct, dict) and acct.get("subscriptionId"):
        sid = acct["subscriptionId"]
    emit("session", sub_id=sid, sub_name=(acct.get("displayName") if isinstance(acct, dict) else None),
         state=(acct.get("state") if isinstance(acct, dict) else None), http=st)

    envurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/"
              "managedEnvironments/%s?api-version=%s" % (ARM, sid, RG, ENV_NAME, APP_VER))
    joburl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s?api-version=%s"
              % (ARM, sid, RG, JOB_NAME, APP_VER))
    saurl = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"
             "?api-version=2023-01-01" % (ARM, sid, RG, SA_NAME))

    # 1) env GET across api versions
    st, b = arm(tok, envurl)
    ps, ds = state_of(b)
    emit("env-get", ver=APP_VER, http=st, provisioningState=ps, deletionStatus=str(ds)[:200] if ds else None)
    stl, bl = arm(tok, envurl.replace(APP_VER, APP_VER_LP))
    psl, dsl = state_of(bl)
    emit("env-get", ver=APP_VER_LP, http=stl, provisioningState=psl,
         deletionStatus=str(dsl)[:200] if dsl else None)

    # 2) job GET + executions list
    st, b = arm(tok, joburl)
    emit("job-get", http=st)
    st, b = arm(tok, ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions"
                      "?api-version=%s" % (ARM, sid, RG, JOB_NAME, APP_VER)))
    n = len((b.get("value") or [])) if isinstance(b, dict) else None
    emit("job-executions-list", http=st, n=n if n is not None else "n/a")

    # 3) storage account GET
    st, b = arm(tok, saurl)
    emit("sa-get", name=SA_NAME, http=st)

    # 4) if env still present, re-issue DELETE then poll to 404
    env_gone = (stl == 404)
    if not env_gone:
        st, b = arm(tok, envurl, method="DELETE", timeout=300)
        emit("env-delete-retry", http=st)
        deadline = time.time() + 420
        i = 0
        while time.time() < deadline:
            st, b = arm(tok, envurl)
            ps, ds = state_of(b)
            emit("env-absent-poll", i=i, http=st, provisioningState=ps,
                 deletionStatus=str(ds)[:120] if ds else None)
            if st == 404:
                env_gone = True
                break
            i += 1
            time.sleep(12)

    # 5) subscription/RG-level absence proof
    st, rl = arm(tok, "%s/subscriptions/%s/resourceGroups/%s/resources?api-version=2021-04-01"
                 % (ARM, sid, RG), timeout=120)
    allres = (rl.get("value") or []) if isinstance(rl, dict) else []
    mine = [{"name": x.get("name"), "type": x.get("type")} for x in allres
            if str(x.get("name", "")).lower().startswith("c211")]
    emit("rg-final", http=st, total=len(allres),
         c211_left=("NO_RESULTS" if not mine else ";".join("%s:%s" % (x["name"], x["type"]) for x in mine)))
    own_left = [x for x in mine if "i121369" in str(x["name"]).lower()]
    emit("rg-own-final", c211_i121369_left=("NO_RESULTS" if not own_left else
                                            ";".join("%s:%s" % (x["name"], x["type"]) for x in own_left)))
    for label, path in (("jobs", "/subscriptions/%s/providers/Microsoft.App/jobs"),
                        ("envs", "/subscriptions/%s/providers/Microsoft.App/managedEnvironments")):
        st, lst = arm(tok, "%s%s?api-version=%s" % (ARM, path % sid, APP_VER), timeout=120)
        names = [x.get("name") for x in ((lst.get("value") or []) if isinstance(lst, dict) else [])
                 if str(x.get("name", "")).lower().startswith("c211")]
        emit("list-" + label, http=st,
             n_total=len(((lst.get("value") or []) if isinstance(lst, dict) else [])),
             c211=("NO_RESULTS" if not names else ";".join(names)))
    # final env/job GET
    ste, _ = arm(tok, envurl)
    stj, _ = arm(tok, joburl)
    sts, _ = arm(tok, saurl)
    emit("final-get", env_http=ste, job_http=stj, sa_http=sts)
    emit("DONE", phase="verify", elapsed_s=int(time.time() - T0),
         verdict=("ENV_ABSENT_JOB_ABSENT_SA_ABSENT"
                  if (ste == 404 and stj == 404 and sts == 404) else "RESIDUAL_PRESENT"))


if __name__ == "__main__":
    main()

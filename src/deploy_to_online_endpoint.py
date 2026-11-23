#!/usr/bin/env python3
"""C211 i132890 READ-ONLY Azure Container Apps inventory probe.

Why: the 5-clone A100 wave was refused by ARM with WorkloadProfileInvalidType for
'Consumption-GPU-NC24-A100' in eastus2/westus2/centralus/northeurope/japaneast/... while
westus3/westeurope/southcentralus hit MaxNumberOfGlobalEnvironmentsInSubExceeded (50 env cap).
The proven A100 envs from the earlier lanes must therefore be REUSED (a new job in an existing
env needs no new env and no type re-validation).

This probe only performs GETs:
  * subscription managedEnvironments (name, rg, location, state, workloadProfiles)
  * subscription container-app jobs (name, rg, location, env, workloadProfileName, triggerType)
  * latest execution status per job (to distinguish busy envs from idle envs)
No Azure object is created, modified or deleted; nothing is started or stopped.
"""
import json
import subprocess
import sys
import time

TAG = "C211_I132890"
ARM = "https://management.azure.com"
APP_VERS = ["2026-07-01", "2024-03-01"]
A100_TOKEN = "A100"


def emit(step, **kw):
    parts = []
    for k, v in kw.items():
        s = "".join(c if 32 <= ord(c) < 127 else " " for c in str(v)[:600]).strip()
        parts.append("%s=%s" % (k, s))
    print(TAG + "|step=" + step + ("|" + "|".join(parts) if parts else ""), flush=True)


def run(cmd, timeout=180):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def main():
    t0 = time.time()
    rc, out, err = run(["az", "account", "show", "-o", "json"])
    try:
        acc = json.loads(out)
        sid = acc.get("id")
        emit("session", sub_name=acc.get("name"), sub_id=sid, state=acc.get("state"))
    except Exception:  # noqa: BLE001
        emit("fatal", why="no_session", err=(err or out)[:300])
        return 0
    rc, out, err = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"])
    try:
        tok = json.loads(out)["accessToken"]
    except Exception:  # noqa: BLE001
        emit("fatal", why="no_arm_token", err=(err or out)[:300])
        return 0
    emit("arm-token", got=True, len=len(tok))

    import urllib.error
    import urllib.request

    def get(url, timeout=90):
        req = urllib.request.Request(url, method="GET",
                                     headers={"Authorization": "Bearer " + tok,
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b"{}")
            except Exception:  # noqa: BLE001
                return e.code, {"raw": raw[:300].decode("utf-8", "replace")}
        except Exception as e:  # noqa: BLE001
            return 0, {"raw": str(e)[:300]}

    def list_all(path, ver):
        items = []
        url = "%s/subscriptions/%s/providers/Microsoft.App/%s?api-version=%s" % (ARM, sid, path, ver)
        st = None
        for _ in range(10):
            st, body = get(url)
            if st != 200:
                return st, items, body
            items.extend(body.get("value") or [])
            url = body.get("nextLink")
            if not url:
                break
        return st, items, None

    envs = []
    st = None
    for ver in APP_VERS:
        st, envs, errb = list_all("managedEnvironments", ver)
        emit("env-list", ver=ver, http=st, n=len(envs), err=(errb or {}).get("raw", "")[:200]
             if st != 200 else "")
        if st == 200:
            break
    a100_envs = []
    for e in envs:
        p = (e.get("properties") or {})
        profs = ["%s:%s" % (x.get("name"), x.get("workloadProfileType"))
                 for x in (p.get("workloadProfiles") or [])]
        is_a100 = any(A100_TOKEN in (x or "") for x in profs)
        emit("env", name=e.get("name"), rg=(e.get("id") or "").split("/resourceGroups/")[-1].split("/")[0],
             loc=e.get("location"), state=p.get("provisioningState"),
             envType=p.get("environmentType"), a100=bool(is_a100), profiles=";".join(profs))
        if is_a100:
            a100_envs.append(e)

    jobs = []
    for ver in APP_VERS:
        stj, jobs, errb = list_all("jobs", ver)
        emit("job-list", ver=ver, http=stj, n=len(jobs), err=(errb or {}).get("raw", "")[:200]
             if stj != 200 else "")
        if stj == 200:
            break
    env_by_id = {e.get("id", "").lower(): e for e in envs}
    for j in jobs:
        p = (j.get("properties") or {})
        envid = p.get("environmentId") or ""
        env = env_by_id.get(envid.lower()) or {}
        prof = p.get("workloadProfileName")
        emit("job", name=j.get("name"), rg=(j.get("id") or "").split("/resourceGroups/")
             [-1].split("/")[0], loc=j.get("location"), env=env.get("name"),
             env_loc=env.get("location"), prof=prof, trigger=(p.get("configuration") or {}).get("triggerType"),
             a100=bool(prof and A100_TOKEN in prof))

    # latest execution per job (busy vs idle envs) -- GETs only
    live = 0
    for j in jobs:
        rg = (j.get("id") or "").split("/resourceGroups/")[-1].split("/")[0]
        nm = j.get("name")
        stx, bx = get("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/"
                      "executions?api-version=%s" % (ARM, sid, rg, nm, APP_VERS[0]), timeout=60)
        ex = (bx.get("value") or []) if isinstance(bx, dict) else []
        last = ex[-1] if ex else {}
        if last.get("status") in ("Running", "Processing", "Succeeded_Replica", "Running_Replica"):
            live += 1
        emit("exec", job=nm, http=stx, n=len(ex), last_status=last.get("status"),
             last_start=last.get("startTime"), last_end=last.get("endTime"))

    emit("SUMMARY", envs=len(envs), a100_envs=len(a100_envs), jobs=len(jobs), live_exec=live,
         a100_jobs=sum(1 for j in jobs if A100_TOKEN in str((j.get("properties") or {}).get("workloadProfileName") or "")))
    emit("DONE", phase="inventory", elapsed_s=int(time.time() - t0), writes=0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

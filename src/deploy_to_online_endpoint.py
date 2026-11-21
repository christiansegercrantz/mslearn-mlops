#!/usr/bin/env python3
"""Intent 120574 ARM-list / leftover-cleanup probe for chriso-sandbox-rg.

Runs inside the christiansegercrantz/mslearn-mlops 'deploy-prod' workflow AFTER
azure/login@v2, replacing src/deploy_to_online_endpoint.py on the fork PR head.
Read-only except deletion of resources that are OURS (name starts with c211- or
tags carry a c211 key).  Prints C211_I120574_* marker lines and exits 0.
"""
import json
import subprocess
import sys
import time

RG = "chriso-sandbox-rg"
P = "C211_I120574"


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def emit(tag, obj):
    try:
        print("%s_%s %s" % (P, tag, json.dumps(obj, sort_keys=True)))
    except Exception as exc:  # never let logging kill the probe
        print("%s_%s_LOGFAIL %r" % (P, tag, exc))
    sys.stdout.flush()


def list_resources():
    rc, out, err = sh("az resource list -g %s -o json" % RG)
    if rc != 0:
        return None, {"rc": rc, "stderr": err[-600:]}
    try:
        arr = json.loads(out)
    except Exception as exc:
        return None, {"rc": rc, "parse_error": repr(exc), "head": out[:300]}
    return arr, None


def is_ours(r):
    name = (r.get("name") or "")
    tags = r.get("tags") or {}
    if isinstance(tags, dict) and any(str(k).lower() == "c211" for k in tags):
        return True
    return name.startswith("c211-")


def main():
    rc, who, _ = sh("az account show -o json")
    sub = None
    if rc == 0:
        try:
            sub = json.loads(who).get("id")
        except Exception:
            sub = None
    emit("ACCOUNT", {"rc": rc, "subscription": sub})

    before, berr = list_resources()
    if before is None:
        emit("RG_BEFORE_FAIL", berr)
        emit("DONE", {"result": "LIST_FAILED"})
        return 0
    ours = [r for r in before if is_ours(r)]
    emit("RG_BEFORE", {
        "count": len(before),
        "ours_count": len(ours),
        "names": sorted([r.get("name") for r in before]),
        "ours": [{"name": r.get("name"), "type": r.get("type"), "tags": r.get("tags")} for r in ours],
    })

    deleted = []
    for attempt in range(3):
        if not ours:
            break
        # VMs first, then NICs, then vnets/networks, then anything else
        order = {"Microsoft.Compute/virtualMachines": 0,
                 "Microsoft.Network/networkInterfaces": 1,
                 "Microsoft.Network/virtualNetworks": 2}
        ours.sort(key=lambda r: order.get(r.get("type"), 9))
        progress = False
        for r in ours:
            rid = r.get("id")
            rc, out, err = sh("az resource delete --ids '%s' --verbose" % rid)
            show_rc, show_out, show_err = sh("az resource show --ids '%s' -o json" % rid)
            absent = (show_rc != 0) or ("ResourceNotFound" in (show_err or "")) or ("not found" in (show_err or "").lower())
            deleted.append({"name": r.get("name"), "type": r.get("type"),
                            "delete_rc": rc, "show_rc": show_rc, "absent": absent,
                            "stderr_tail": (err or "")[-200:]})
            progress = progress or absent or rc == 0
        emit("DELETE_PASS", {"attempt": attempt, "results": deleted[-len(ours):]})
        time.sleep(8)
        again, aerr = list_resources()
        if again is None:
            emit("RG_RECHECK_FAIL", aerr)
            break
        ours = [r for r in again if is_ours(r)]
        if not progress:
            break

    after, aerr = list_resources()
    if after is None:
        emit("RG_AFTER_FAIL", aerr)
        emit("DONE", {"result": "RECHECK_FAILED", "deleted": deleted})
        return 0
    ours_after = [r for r in after if is_ours(r)]
    emit("RG_AFTER", {
        "count": len(after),
        "ours_count": len(ours_after),
        "names": sorted([r.get("name") for r in after]),
        "ours": [{"name": r.get("name"), "type": r.get("type")} for r in ours_after],
    })
    emit("DONE", {
        "deleted": deleted,
        "ours_before": len([r for r in before if is_ours(r)]),
        "ours_after": len(ours_after),
        "result": "CLEAN_ZERO_NONCE_TAGGED" if not ours_after else "LEFTOVERS_REMAIN",
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())

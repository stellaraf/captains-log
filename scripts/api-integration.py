#!/usr/bin/env python3
"""Real API/RBAC checks. Creates and removes temporary Keycloak service clients.

These clients exercise API authorization without changing the interactive MFA flow.
Requires the local stack and the private browser-issued test access token.
"""
import base64, json, pathlib, secrets, time, urllib.error, urllib.parse, urllib.request

root=pathlib.Path(__file__).resolve().parents[1]; local=root/'.local'
env=dict(line.split('=',1) for line in (local/'dev.env').read_text().splitlines() if '=' in line)
admin=(local/'test-access-token').read_text().strip()
api='http://127.0.0.1:18080/api'; kc='http://127.0.0.1:18089'; results=[]

def request(url,method='GET',data=None,token=None,form=False):
    headers={}
    if token:headers['Authorization']='Bearer '+token
    if data is not None:
        data=(urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
        headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
    req=urllib.request.Request(url,data,method=method,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=30) as r:return r.status,r.read()
    except urllib.error.HTTPError as e:return e.code,e.read()

def check(name,path,expected=200,method='GET',data=None,token=admin):
    code,body=request(api+path,method,data,token)
    if code!=expected:raise AssertionError(f'{name}: expected {expected}, received {code}: {body[:200]!r}')
    results.append({'check':name,'status':'passed'})
    return json.loads(body) if body else None

check('authentication required','/logs',401,token=None)
parts=admin.split('.');payload=json.loads(base64.urlsafe_b64decode(parts[1]+'==='));payload['sub']='forged-subject'
forged=parts[0]+'.'+base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')+'.'+parts[2]
check('forged signed claims rejected','/me',401,token=forged)
check('administrator identity','/me')
for q in ['addr.src in 10.0.0.0/8','addr.dst in ::/0','(app eq ssl) or (app eq web-browsing)','NOT (action eq allow)','rule eq "\' OR 1=1 --"']:
    check('parameterized query '+q,'/logs?'+urllib.parse.urlencode({'type':'unified','query':q,'limit':3}))
check('syntax error stays readable','/query/validate',400,'POST',{'query':'(addr.src in 10.0.0.0/8))'})
first=check('first page','/logs?type=traffic&limit=3')
if first['events']:
    event=first['events'][0]
    detail=check('stable event resource','/events/'+urllib.parse.quote(event['id'])+'?'+urllib.parse.urlencode({'at':event['received_at'],'type':event['log_type']}))
    assert detail['event']['id']==event['id'] and detail['event']['raw']==event['raw']
    firewall=check('stable firewall resource','/firewalls/'+urllib.parse.quote(event['serial']))
    assert firewall['firewall']['serial']==event['serial']
check('event lookup requires time and family','/events/'+'0'*32,400)
check('unknown firewall resource','/firewalls/NEBULALOG-NOT-FOUND',404)
if first['next_cursor']:
    second=check('cursor second page','/logs?type=traffic&limit=3&cursor='+urllib.parse.quote(first['next_cursor']))
    assert not ({r['id'] for r in first['events']} & {r['id'] for r in second['events']})
    check('cursor cannot cross filters','/logs?type=traffic&limit=3&query=action%20eq%20deny&cursor='+urllib.parse.quote(first['next_cursor']),400)
check('SQL identifier injection rejected','/logs?sort='+urllib.parse.quote('id; DROP TABLE events'),400)
check('oversized page rejected','/logs?limit=1000000',400)

status,body=request(kc+'/realms/master/protocol/openid-connect/token','POST',{'grant_type':'password','client_id':'admin-cli','username':'nlbootstrap','password':env['KC_ADMIN_PASSWORD']},form=True)
assert status==200; bootstrap=json.loads(body)['access_token']; base=kc+'/admin/realms/nebulalog/'
def management(path,method='GET',data=None):
    code,body=request(base+path,method,data,bootstrap)
    if code not in (200,201,204):raise AssertionError(f'Identity test setup failed ({code})')
    return json.loads(body) if body else None
nl=management('clients?clientId=nebulalog')[0]; clients=[]
try:
    tokens={}
    for role in ('VIEWER','ANALYST'):
        name='nebulalog-rbac-test-'+secrets.token_hex(8);secret=secrets.token_urlsafe(32)
        management('clients','POST',{'clientId':name,'enabled':True,'protocol':'openid-connect','publicClient':False,'secret':secret,'serviceAccountsEnabled':True,'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'fullScopeAllowed':True,'defaultClientScopes':['roles'],'protocolMappers':[{'name':'nebulalog-audience','protocol':'openid-connect','protocolMapper':'oidc-audience-mapper','config':{'included.client.audience':'nebulalog','access.token.claim':'true'}}]})
        client=management('clients?clientId='+name)[0];clients.append(client['id'])
        user=management('clients/'+client['id']+'/service-account-user')
        mapping=management('clients/'+nl['id']+'/roles/'+role)
        management('users/'+user['id']+'/role-mappings/clients/'+nl['id'],'POST',[mapping])
        code,body=request(kc+'/realms/nebulalog/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':name,'client_secret':secret},form=True)
        assert code==200;tokens[role]=json.loads(body)['access_token']
    viewer=tokens['VIEWER'];analyst=tokens['ANALYST']
    check('viewer search allowed','/logs?limit=1',token=viewer)
    check('viewer identity administration rejected','/identity/providers',403,token=viewer)
    check('analyst identity preview rejected','/identity/providers/okta/preview',403,'POST',{},analyst)
    original_preferences=check('administrator preferences','/preferences')
    viewer_preferences={'theme':'light' if original_preferences['theme']!='light' else 'dark','density':'comfortable','rail_collapsed':True}
    check('viewer may persist own display preferences','/preferences',200,'PUT',viewer_preferences,viewer)
    restored_preferences=check('display preferences persisted','/preferences',token=viewer)
    assert restored_preferences==viewer_preferences
    unchanged_preferences=check('preferences isolated by identity','/preferences')
    assert unchanged_preferences==original_preferences
    check('invalid preference enum rejected','/preferences',400,'PUT',{'theme':'invented','density':'compact','rail_collapsed':False},viewer)
    check('preference owner cannot be supplied','/preferences',400,'PUT',dict(viewer_preferences,owner_id=payload['sub']),viewer)
    check('viewer preferences reset','/preferences',200,'PUT',{'theme':'system','density':'compact','rail_collapsed':False},viewer)
    query={'name':'Ephemeral RBAC integration','description':'Synthetic test; removed by test','query':'app eq ssl','log_type':'traffic','columns':['src_ip'],'time_range':'1h','sort':'src_ip','order':'asc','favorite':False}
    check('viewer saved-filter write rejected','/filters',403,'POST',query,viewer)
    check('viewer export rejected','/exports',403,'POST',{'log_type':'traffic'},viewer)
    check('analyst retention write rejected','/retention',403,'PUT',{'global_days':90,'per_type':{}},analyst)
    check('analyst cache mutation rejected','/dns/cache',403,'DELETE',token=analyst)
    saved=check('analyst saved-filter creation','/filters',200,'POST',query,analyst)
    check('cross-owner filter edit rejected','/filters/'+saved['id'],404,'PUT',query,admin)
    visible=check('owner saved-filter persistence','/filters',token=analyst)
    restored=next(f for f in visible['filters'] if f['id']==saved['id']);assert restored['order']=='asc'
    check('owner saved-filter cleanup','/filters/'+saved['id'],200,'DELETE',token=analyst)
    check('invalid export column rejected','/exports',400,'POST',{'log_type':'traffic','columns':['raw;drop']},analyst)
finally:
    for ident in clients:management('clients/'+ident,'DELETE')
receipt={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'checks':results,'temporary_identity_clients_removed':True}
(local/'api-integration.json').write_text(json.dumps(receipt,indent=2))
print(f'Passed {len(results)} real API/RBAC checks; temporary identity clients removed.')

#!/usr/bin/env python3
"""Create the unique local Keycloak user with mandatory MFA enrollment."""
import argparse, json, os, pathlib, re, secrets, stat, urllib.request, urllib.parse
arguments = argparse.ArgumentParser(description=__doc__)
arguments.add_argument('--create-operator', metavar='USERNAME', help='Create a separate human administrator requiring initial MFA enrollment')
options = arguments.parse_args()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(NoRedirect())
root = pathlib.Path(__file__).resolve().parents[1]
local = root / '.local'
info = local.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit('.local must be an owner-only real directory (mode0700).')
env_path = local / 'dev.env'
info = env_path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit('dev.env must be an owner-only regular file, not a symbolic link.')
values = dict(line.split('=', 1) for line in env_path.read_text().splitlines() if line and not line.startswith('#'))
base = 'http://127.0.0.1:18089'
data = urllib.parse.urlencode(dict(grant_type='password', client_id='admin-cli', username='nlbootstrap', password=values['KC_ADMIN_PASSWORD'])).encode()
token = json.load(opener.open(urllib.request.Request(base+'/realms/master/protocol/openid-connect/token',data),timeout=15))['access_token']
def call(path, method='GET', body=None):
    req = urllib.request.Request(base+'/admin/realms/nebulalog/'+path, None if body is None else json.dumps(body).encode(), method=method, headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with opener.open(req,timeout=15) as r:
        b=r.read();return json.loads(b) if b else None
call('','PUT',{'displayName':'Captain’s Log','displayNameHtml':'Captain’s Log','loginTheme':'nebulalog'})
users=call('users?username=administrator&exact=true')
if not users:
    call('users','POST',{'username':'administrator','enabled':True,'emailVerified':True,'firstName':'Captain’s Log','lastName':'Administrator','email':'administrator@localhost.invalid','requiredActions':['CONFIGURE_TOTP'],'credentials':[{'type':'password','value':values['NL_ADMIN_PASSWORD'],'temporary':False}]})
    users=call('users?username=administrator&exact=true')
client=call('clients?clientId=nebulalog')[0]
role=call('clients/'+client['id']+'/roles/ADMINISTRATOR')
call('users/'+users[0]['id']+'/role-mappings/clients/'+client['id'],'POST',[role])
# A separate service identity can manage only identity-provider configuration.
# Never give the application the bootstrap administrator password or realm-admin.
manager_name = 'nebulalog-identity-manager'
managers = call('clients?clientId='+manager_name)
if managers and managers[0].get('attributes', {}).get('nebulalog-managed') != 'true':
    raise SystemExit('Refusing to replace an unrelated identity-manager client.')
manager_config = {'clientId':manager_name, 'enabled':False, 'protocol':'openid-connect', 'publicClient':False, 'secret':values['KC_IDENTITY_CLIENT_SECRET'], 'serviceAccountsEnabled':True, 'standardFlowEnabled':False, 'directAccessGrantsEnabled':False, 'fullScopeAllowed':True, 'defaultClientScopes':['roles'], 'attributes':{'nebulalog-managed':'true'}}
if not managers:
    call('clients', 'POST', manager_config)
    managers = call('clients?clientId='+manager_name)
service_user = call('clients/'+managers[0]['id']+'/service-account-user')
realm_management = call('clients?clientId=realm-management')[0]
allowed_roles = {'manage-identity-providers','view-identity-providers','view-realm'}
existing_roles = call('users/'+service_user['id']+'/role-mappings/clients/'+realm_management['id']+'/composite')
if {role['name'] for role in existing_roles} - allowed_roles:
    raise SystemExit('Identity-manager account has unexpected administration privileges; review and remove them before provisioning.')
if call('users/'+service_user['id']+'/role-mappings/clients/'+client['id']+'/composite'):
    raise SystemExit('Identity-manager account must not hold interactive Captain’s Log application roles.')
scoped_roles = [call('clients/'+realm_management['id']+'/roles/'+name) for name in sorted(allowed_roles)]
call('users/'+service_user['id']+'/role-mappings/clients/'+realm_management['id'], 'POST', scoped_roles)

broker_flow = 'nebulalog-broker-mfa'
flows = call('authentication/flows')
if not any(flow['alias'] == broker_flow for flow in flows):
    call('authentication/flows','POST',{'alias':broker_flow,'description':'Captain’s Log required OTP after external identity authentication','providerId':'basic-flow','topLevel':True,'builtIn':False})
    call('authentication/flows/'+broker_flow+'/executions/execution','POST',{'provider':'auth-otp-form'})
executions = call('authentication/flows/'+broker_flow+'/executions')
if len(executions) != 1 or executions[0].get('providerId') != 'auth-otp-form':
    raise SystemExit('Refusing to change an unexpected broker MFA flow; inspect its executions.')
execution = executions[0]
execution['requirement'] = 'REQUIRED'
call('authentication/flows/'+broker_flow+'/executions','PUT',execution)
manager_config['enabled'] = True
call('clients/'+managers[0]['id'], 'PUT', manager_config)

# Browser acceptance may have already enrolled the development test account.
# A human operator receives a separate unique credential and enrolls their own MFA.
if options.create_operator:
    username = options.create_operator
    if not re.fullmatch(r'[a-z][a-z0-9._-]{2,63}',username) or username == 'administrator':
        raise SystemExit('Choose a distinct operator username of3–64 lowercase letters, digits, dots, underscores or hyphens.')
    if values.get('NL_OPERATOR_USERNAME') not in (None,username):
        raise SystemExit('A different local operator is already recorded; credentials were not changed.')
    matches = call('users?username='+urllib.parse.quote(username)+'&exact=true')
    if matches and matches[0].get('attributes',{}).get('nebulalog-local-operator') != ['true']:
        raise SystemExit('Refusing to replace an unrelated operator account.')
    if 'NL_OPERATOR_USERNAME' not in values:
        values.update(NL_OPERATOR_USERNAME=username,NL_OPERATOR_PASSWORD=secrets.token_urlsafe(32)+'Aa1!')
        temporary_env = local / 'dev.env.next'
        with os.fdopen(os.open(temporary_env,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w') as file:
            file.write(''.join(f'{key}={value}\n' for key,value in values.items()))
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_env,env_path)
    if not matches:
        call('users','POST',{'username':username,'enabled':True,'emailVerified':True,'firstName':'Stellar','lastName':'Administrator','email':username+'@localhost.invalid','attributes':{'nebulalog-local-operator':['true']},'requiredActions':['CONFIGURE_TOTP'],'credentials':[{'type':'password','value':values['NL_OPERATOR_PASSWORD'],'temporary':False}]})
        matches = call('users?username='+urllib.parse.quote(username)+'&exact=true')
    call('users/'+matches[0]['id']+'/role-mappings/clients/'+client['id'],'POST',[role])

path=root/'.local/login.txt'
temporary = root / '.local/login.txt.next'
with os.fdopen(os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w') as f:
    username = values.get('NL_OPERATOR_USERNAME','administrator')
    password = values.get('NL_OPERATOR_PASSWORD',values['NL_ADMIN_PASSWORD'])
    f.write('Captain’s Log local development\nURL: http://127.0.0.1:18080\nUsername: '+username+'\nPassword: '+password+'\nMFA enrollment is required on first login.\n')
    f.flush()
    os.fsync(f.fileno())
os.replace(temporary, path)
print('Local administrator, required broker OTP flow and scoped identity manager are configured. Private credentials: .local/login.txt')

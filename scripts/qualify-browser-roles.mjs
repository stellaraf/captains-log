// Explicit opt-in acceptance against an isolated loopback application fixture.
import { createRequire } from 'node:module';
const { chromium } = createRequire(new URL('../web/package.json', import.meta.url))('@playwright/test');
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
assert.ok(process.env.ROLE_FIXTURE, 'ROLE_FIXTURE must name a private fixture configuration');
const configStat=fs.lstatSync(process.env.ROLE_FIXTURE);
assert.ok(configStat.isFile() && configStat.uid===process.getuid() && !(configStat.mode&0o077), 'Fixture configuration must be an owner-only regular file');
const c=JSON.parse(fs.readFileSync(process.env.ROLE_FIXTURE,'utf8'));
const origin=new URL(c.origin);
assert.equal(origin.protocol,'http:');assert.equal(origin.hostname,'127.0.0.1');
assert.ok(origin.port && !['18080','18180','18089'].includes(origin.port), 'Use a disposable loopback listener');
assert.equal(origin.origin,c.origin);
assert.equal(c.users.length,4);
assert.deepEqual(c.users.map(u=>u.role).sort(),['ADMINISTRATOR','ANALYST','UNASSIGNED','VIEWER']);
assert.equal(new Set(c.users.map(u=>u.username)).size,4);
for(const user of c.users){assert.match(user.username,/^scope-[a-z]+$/);assert.match(user.otpHex,/^[a-f0-9]{64}$/);assert.ok(typeof user.password==='string' && user.password.length>=14);}
const evidenceStat=fs.lstatSync(c.evidence);
assert.ok(evidenceStat.isDirectory() && evidenceStat.uid===process.getuid() && !(evidenceStat.mode&0o077), 'Evidence directory must be private');
const browser=await chromium.launch({channel:'chrome',headless:true});
const results=[];
function totp(hex){const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const d=crypto.createHmac('sha256',Buffer.from(hex,'hex')).update(counter).digest();return String((d.readUInt32BE(d.at(-1)&15)&0x7fffffff)%1000000).padStart(6,'0');}
try {
 for(const user of c.users){
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  try {
   const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto(c.origin+'/logs/traffic');await page.locator('#username').waitFor({timeout:30000});
   await page.locator('#username').fill(user.username);await page.locator('#password').fill(user.password);await page.locator('#kc-login').click();
   await page.locator('#otp').waitFor({timeout:30000});
   const tokenReply=page.waitForResponse(r=>r.url().includes('/protocol/openid-connect/token')&&r.status()===200,{timeout:45000});
   await page.locator('#otp').fill(totp(user.otpHex));await page.locator('#kc-login').click();
   const tokens=await(await tokenReply).json();const access=tokens.access_token;assert.equal(typeof access,'string');
   const claims=JSON.parse(Buffer.from(access.split('.')[1],'base64url').toString());
   const expected=user.role==='UNASSIGNED'?[]:user.role==='ADMINISTRATOR'?['ADMINISTRATOR','VIEWER']:[user.role];
   assert.deepEqual((claims.resource_access?.nebulalog?.roles??[]).sort(),expected);
   assert.deepEqual(Object.keys(claims.resource_access??{}).sort(),expected.length?['nebulalog']:[]);
   assert.ok(!claims.realm_access?.roles?.length);assert.ok(claims.sub);assert.equal(claims.preferred_username,user.username);
   assert.ok([claims.aud].flat().includes('nebulalog'));assert.equal(claims.azp,'nebulalog');
   const headers={Authorization:'Bearer '+access};
   const me=await context.request.get(c.origin+'/api/me',{headers});
   if(expected.length){assert.equal(me.status(),200);assert.equal((await me.json()).role,user.role);await page.getByLabel('Filter query').waitFor({timeout:45000});}
   else {assert.equal(me.status(),403);assert.match((await me.json()).error,/No Captain/);}
   const read=await context.request.get(c.origin+'/api/filters',{headers});assert.equal(read.status(),expected.length?200:403);
   const write=await context.request.post(c.origin+'/api/filters',{headers,data:{name:'Scope fixture '+user.role,description:'Ephemeral role acceptance',query:'( port.dst eq 443 )',log_type:'traffic',columns:['received_at','serial'],time_range:'24h',sort:'received_at',order:'desc'}});
   const canWrite=['ADMINISTRATOR','ANALYST'].includes(user.role);assert.equal(write.status(),canWrite?200:403);
   if(canWrite){const saved=await write.json();assert.ok(saved.id);const removed=await context.request.delete(c.origin+'/api/filters/'+saved.id,{headers});assert.equal(removed.status(),200);}
   const admin=await context.request.delete(c.origin+'/api/dns/cache',{headers});assert.equal(admin.status(),user.role==='ADMINISTRATOR'?200:403);
   assert.deepEqual(errors,[]);
   await page.screenshot({path:c.evidence+'/'+user.role.toLowerCase()+'.png',fullPage:true});
   results.push({role:user.role,password_and_totp:true,application_roles:expected,unrelated_client_and_realm_roles_excluded:true,unscoped_application_role_excluded:true,subject_and_username_present:true,audience_valid:true,me_status:me.status(),read_status:read.status(),write_status:write.status(),admin_status:admin.status(),temporary_filter_removed:canWrite,page_errors:errors});
   fs.writeFileSync(c.evidence+'/result.json',JSON.stringify({passed:results.length===c.users.length,users:results,browser:browser.version(),tokens_persisted:false},null,2));
  }finally{await context.close();}
 }
}finally{await browser.close();}

const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {createHash}=require('node:crypto');
const root=path.join(__dirname,'..');
const load=()=>import('../api/_lib/soc.js');
const full=()=>({panel:'report',notes:'Investigating',inspected:['MAIL-01'],timeline:['MAIL-01','PROXY-02','AUTH-02','AUTH-03'],report:{classification:'credential-phishing',severity:'high',user:'alex',endpoint:'NC-WS-014',iocs:'payroll-review.example\n203.0.113.44\n198.51.100.77',summary:'PROXY-02 shows credential submission and AUTH-02 shows unauthorized access. Preserve evidence, revoke sessions and reset credentials; no proven endpoint malware.',evidence:['MAIL-01','PROXY-02','AUTH-02','EDR-01'],containment:['revoke','reset','block','preserve']}});

test('complete evidence-backed report passes; guesswork and unsafe containment fail',async()=>{
  const {grade,validateState}=await load();
  const result=grade(validateState(full()));assert.equal(result.score,100);assert.equal(result.passed,true);
  const guessed=full();guessed.report.containment.push('wipe');assert.equal(grade(validateState(guessed)).passed,false);
  const wrong=full();wrong.report.user='jordan';assert.equal(grade(validateState(wrong)).passed,false);
  const empty=grade(validateState({}));assert.equal(empty.score,0);assert.equal(empty.passed,false);
});
test('timeline must be chronological and grounded in real scenario evidence',async()=>{
  const {grade,validateState}=await load();const state=full();state.timeline.reverse();
  assert.equal(grade(validateState(state)).checks.find(c=>c.objective==='Incident timeline').ok,false);
  assert.throws(()=>validateState({timeline:['DROP TABLE users']}));
  assert.throws(()=>validateState({report:{evidence:['AUTH-99']}}));
  assert.throws(()=>validateState({report:{containment:['shell']}}));
  assert.throws(()=>validateState({notes:'x'.repeat(8001)}));
  assert.throws(()=>validateState({report:{evidence:['MAIL-01','MAIL-01']}}));
});
test('notes and summaries are untrusted text; fabricated grading/reward fields are discarded',async()=>{
  const {validateState}=await load();const state=validateState({...full(),notes:'<img src=x onerror=alert(1)>',reward_xp:9000,result:{passed:true}});
  assert.equal(state.notes,'<img src=x onerror=alert(1)>');assert.equal(state.reward_xp,undefined);assert.equal(state.result,undefined);
});
test('terminal and literal SIEM search cannot execute injected commands',async()=>{
  const {scenario}=await load();const context=vm.createContext({window:{addEventListener(){}},Map,console});
  vm.runInContext(fs.readFileSync(path.join(root,'assets/soc-workspace.js'),'utf8'),context);
  const {terminal,search}=context.window.CyberSOC;
  for(const command of ['cat /etc/passwd','logs auth; curl evil','show AUTH-02; rm -rf /','$(id)','<script>alert(1)</script>']) assert.match(terminal(scenario,command),/not allowed/);
  assert.equal(search(scenario,"' OR 1=1 --").length,0);
  assert.match(terminal(scenario,'logs proxy alex'),/PROXY-02/);
  assert.match(terminal(scenario,'show MAIL-01'),/Return-Path/);
});
function response(){return {headers:{},statusCode:200,setHeader(k,v){this.headers[k]=v;},status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}};}
async function api(client){
  const lib=await load();const source=fs.readFileSync(path.join(root,'api/soc.js'),'utf8').replace(/^import .*;\n/gm,'').replace('export default async function handler','async function handler');
  const context=vm.createContext({...lib,createHash,createClient:()=>client,Buffer,process:{env:{SUPABASE_URL:'https://example.supabase.co',SUPABASE_SECRET_KEY:'test-only'}},console:{error(){}},Date,Map});vm.runInContext(source,context);return context.handler;
}
test('SOC API rejects anonymous/expired requests before database access',async()=>{
  const handler=await api({auth:{getUser:async()=>({error:{message:'expired'}})},from(){assert.fail('DB accessed without auth');}});
  for(const authorization of [undefined,'Bearer expired']){const res=response();await handler({method:'GET',headers:{authorization}},res);assert.equal(res.statusCode,401);assert.equal(res.headers['Cache-Control'],'no-store');}
});
test('SOC API scopes reads and writes to verified identity, ignoring forged user and score',async()=>{
  const filters=[];let args;
  const client={auth:{getUser:async()=>({data:{user:{id:'verified-user'}}})},from:()=>({select:()=>({eq(k,v){filters.push([k,v]);return this;},maybeSingle:async()=>({data:null})})}),rpc:async(name,p)=>{args=p;return {data:{record:{revision:1}}};}};
  const handler=await api(client);const read=response();await handler({method:'GET',headers:{authorization:'Bearer valid'}},read);
  assert.equal(filters[0][1],'verified-user');assert.equal(read.body.scenario.answer,undefined);
  const res=response();await handler({method:'POST',headers:{authorization:'Bearer valid'},body:{action:'submit',requestId:'00000000-0000-4000-8000-000000000001',revision:0,user_id:'victim',state:full(),result:{score:0},reward_xp:9999}},res);
  assert.equal(res.statusCode,200);assert.equal(args.p_user,'verified-user');assert.equal(args.p_result.score,100);assert.equal(args.p_state.reward_xp,undefined);
});
test('SOC API returns conflict and rejects invalid or oversized submissions',async()=>{
  const handler=await api({auth:{getUser:async()=>({data:{user:{id:'agent'}}})},rpc:async()=>({data:{conflict:true,record:{revision:2}}})});
  const base={action:'save',revision:0,requestId:'00000000-0000-4000-8000-000000000001',state:full()};
  for(const [body,status] of [[base,409],[{...base,revision:-1},400],[{...base,state:{notes:'a'.repeat(70000)}},413],[{...base,state:{timeline:['bogus']}},400]]){const res=response();await handler({method:'POST',headers:{authorization:'Bearer valid'},body},res);assert.equal(res.statusCode,status);}
});
test('SOC API limits repeated invalid tokens before making more auth service calls',async()=>{
  let calls=0;const handler=await api({auth:{getUser:async()=>{calls++;return {error:{code:'expired'}};}}});
  let res;
  for(let i=0;i<91;i++){res=response();await handler({method:'GET',headers:{authorization:'Bearer invalid','x-forwarded-for':'192.0.2.1'}},res);}
  assert.equal(calls,90);assert.equal(res.statusCode,429);assert.equal(res.headers['Retry-After'],'60');
});

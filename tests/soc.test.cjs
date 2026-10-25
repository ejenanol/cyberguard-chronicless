const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {createHash}=require('node:crypto');
const root=path.join(__dirname,'..');
const load=()=>import('../api/_lib/soc.js');
const full=()=>({panel:'report',notes:'Investigating',inspected:['MAIL-01'],timeline:['MAIL-01','PROXY-02','AUTH-02','AUTH-03'],report:{classification:'credential-phishing',severity:'high',user:'alex',endpoint:'NC-WS-014',iocs:'payroll-review.example\n203.0.113.44\n198.51.100.77',summary:'PROXY-02 shows credential submission and AUTH-02 shows unauthorized access. Preserve evidence, revoke sessions and reset credentials; no proven endpoint malware.',evidence:['MAIL-01','DNS-01','PROXY-02','AUTH-02','EDR-01'],containment:['revoke','reset','block','preserve']}});

test('complete evidence-backed report passes; guesswork and unsafe containment fail',async()=>{
  const {grade,validateState}=await load();
  const result=grade(validateState(full()));assert.equal(result.score,100);assert.equal(result.passed,true);assert.equal(result.assessment_version,2);
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
  const legacyState={...args.p_state};delete legacyState.selectedEvidence;
  assert.equal(args.p_hash,createHash('sha256').update(JSON.stringify({action:'submit',state:legacyState})).digest('hex'),'old submission receipts retain the same fingerprint');
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
test('event inspector selection is optional for old saves and validated when supplied',async()=>{
  const {validateState}=await load();
  assert.equal(validateState({}).selectedEvidence,null);
  assert.equal(validateState({selectedEvidence:'AUTH-02'}).selectedEvidence,'AUTH-02');
  assert.throws(()=>validateState({selectedEvidence:'<img src=x onerror=alert(1)>'}));
  assert.throws(()=>validateState({selectedEvidence:'AUTH-99'}));
});

for(const [label,change,objective] of [
  ['email inspection',state=>{state.inspected=[];},'Email inspection'],
  ['email citation',state=>{state.report.evidence=state.report.evidence.filter(id=>id!=='MAIL-01');},'Email inspection'],
  ['recorded timeline',state=>{state.timeline=[];},'Incident timeline'],
  ['chronological timeline',state=>{state.timeline.reverse();},'Incident timeline'],
  ['indicators',state=>{state.report.iocs='';},'Indicators']
]) test(`integrated chapter cannot pass without ${label}, even at 90 points`,async()=>{
  const {grade,validateState}=await load();const state=full();change(state);
  const result=grade(validateState(state));
  assert.equal(result.score,90);assert.equal(result.passed,false);assert.equal(result.assessment_version,2);
  assert.equal(result.checks.find(check=>check.objective===objective).ok,false);
  assert.equal(result.objectives.includes(objective),false);
});

test('integrated investigation must cite all four existing log sources',async()=>{
  const {grade,validateState}=await load();
  for(const evidenceId of ['DNS-01','PROXY-02','AUTH-02','EDR-01']) {
    const state=full();state.report.evidence=state.report.evidence.filter(id=>id!==evidenceId);
    const result=grade(validateState(state));
    assert.equal(result.score,85,`${evidenceId} is needed for correlation`);
    assert.equal(result.passed,false);assert.equal(result.checks.find(check=>check.objective==='Correlated evidence').ok,false);
  }
});
const completionRequest=()=>({action:'complete',revision:4,requestId:'00000000-0000-4000-8000-000000000009'});
test('chapter completion uses verified identity and the completion RPC, ignoring forged browser awards',async()=>{
  const calls=[];const receipt={revision:5,reward_xp:150,chapter_completed_at:'2026-10-24T01:00:00.000Z'};
  const handler=await api({auth:{getUser:async()=>({data:{user:{id:'verified-owner'}}})},rpc:async(name,args)=>{calls.push({name,args});return {data:{record:receipt,duplicate:calls.length>1}};}});
  const request={...completionRequest(),user_id:'victim',reward_xp:9999,result:{passed:true},chapter_completed_at:'forged',state:{report:{}}};
  for(let i=0;i<2;i++) {
    const res=response();await handler({method:'POST',headers:{authorization:'Bearer valid'},body:request},res);
    assert.equal(res.statusCode,200);assert.equal(res.body.record.chapter_completed_at,receipt.chapter_completed_at);assert.equal(res.body.record.reward_xp,150);
  }
  assert.equal(calls.length,2);
  for(const call of calls) {
    assert.equal(call.name,'complete_soc_chapter');
    assert.deepEqual(JSON.parse(JSON.stringify(call.args)),{p_user:'verified-owner',p_scenario:'phishing-soc-v1',p_revision:4});
  }
});
test('forged passing result cannot bypass a missing server assessment award',async()=>{
  const handler=await api({auth:{getUser:async()=>({data:{user:{id:'learner'}}})},rpc:async()=>({data:{not_passed:true}})});
  const res=response();await handler({method:'POST',headers:{authorization:'Bearer valid'},body:{...completionRequest(),result:{passed:true,score:100},reward_xp:150,chapter_completed_at:'forged'}},res);
  assert.equal(res.statusCode,422);assert.equal(res.body.record,undefined);
});
test('completion preserves revision conflicts and treats absent receipts/storage errors as unavailable',async()=>{
  for(const [reply,status] of [
    [{data:{conflict:true,record:{revision:8}}},409],
    [{data:{record:{revision:5,reward_xp:150}}},503],
    [{error:{code:'PGRST202'}},503]
  ]) {
    const handler=await api({auth:{getUser:async()=>({data:{user:{id:'learner'}}})},rpc:async()=>reply});
    const res=response();await handler({method:'POST',headers:{authorization:'Bearer valid'},body:completionRequest()},res);
    assert.equal(res.statusCode,status);
    if(status===409)assert.equal(res.body.record.revision,8);
    else assert.equal(res.body.record,undefined);
  }
});
test('anonymous completion and invalid completion envelopes never reach the write RPC',async()=>{
  let writes=0;const handler=await api({auth:{getUser:async()=>({data:{user:{id:'learner'}}})},rpc:async()=>{writes++;return {data:{}};}});
  let res=response();await handler({method:'POST',headers:{},body:completionRequest()},res);assert.equal(res.statusCode,401);
  for(const body of [{...completionRequest(),revision:-1},{...completionRequest(),requestId:'forged'},{...completionRequest(),revision:1.5}]) {
    res=response();await handler({method:'POST',headers:{authorization:'Bearer valid'},body},res);assert.equal(res.statusCode,400);
  }
  assert.equal(writes,0);
});
test('existing empty investigation records are normalised for integrated chapter entry',async()=>{
  const handler=await api({auth:{getUser:async()=>({data:{user:{id:'learner'}}})},from:()=>({select:()=>({eq(){return this;},maybeSingle:async()=>({data:{revision:0,state:{},reward_xp:0,result:null,chapter_completed_at:null}})})})});
  const res=response();await handler({method:'GET',headers:{authorization:'Bearer valid'}},res);
  assert.equal(res.statusCode,200);assert.equal(res.body.record.state.version,1);assert.equal(res.body.record.state.panel,'briefing');
  assert.equal(res.body.record.state.report.evidence.length,0);assert.equal(res.body.record.chapter_completed_at,null);
});

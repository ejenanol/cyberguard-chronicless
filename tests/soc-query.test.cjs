const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const load=async()=>{await import('../assets/soc-query.js');return globalThis.CyberSOCQuery;};
const synthetic={email:{id:'MAIL-01',time:'2026-10-23T09:00:00Z',from:'Payroll <payroll@example.invalid>',to:['alex@example.invalid'],subject:'Payroll review',headers:'spf=fail',body:'Inert form',attachment:{name:'Payroll.html',mime:'text/html',sha256:'ab'.repeat(32),preview:'Offline attachment preview'}},logs:[
  {id:'A-01',time:'2026-10-23T09:02:00Z',source:'auth',user:'Alex',host:'NC-WS-014',detail:'Successful office sign-in'},
  {id:'A-02',time:'2026-10-23T09:07:00Z',source:'auth',user:'alex',host:'unmanaged',detail:'Suspicious sign-in'},
  {id:'P-01',time:'2026-10-23T09:03:00Z',source:'proxy',user:'alex',host:'NC-WS-014',detail:'POST form | username,password; values redacted'},
  {id:'D-01',time:'2026-10-23T09:01:00Z',source:'dns',user:'alex',host:'NC-WS-014',detail:'Query payroll-review.example'},
  {id:'E-01',time:'2026-10-23T08:55:00Z',source:'endpoint',user:'alex',host:'NC-WS-014',detail:'Browser process start',processId:'PROC-02',pid:5120,parentPid:4240,name:'msedge.exe',commandLine:'"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"',filePath:'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',sha256:'cd'.repeat(32),signature:'Microsoft Corporation; valid'}
]};
test('query tables, literal filters, projection and UTC sorting use synthetic records only',async()=>{
  const {run}=await load();
  const result=run(synthetic,'sIgNiNlOgS | WHERE USER == "alex" | project ID, Time, Detail | sort by TIME asc | take 10');
  assert.equal(result.table,'SigninLogs');assert.deepEqual(result.columns,['id','time','detail']);
  assert.deepEqual(result.rows,[{id:'A-02',time:'2026-10-23T09:07:00Z',detail:'Suspicious sign-in'}]);
  assert.equal(result.total,1);assert.equal(result.limited,false);
  assert.deepEqual(run(synthetic,'SecurityEvents | sort by time asc | take 2').rows.map(row=>row.id),['E-01','D-01']);
  assert.deepEqual(run(synthetic,'SecurityEvents | sort by time | take 2').rows.map(row=>row.id),['A-02','P-01']);
  assert.deepEqual(run(synthetic,'SecurityEvents | where user != "alex"').rows.map(row=>row.id),['A-01']);
  assert.deepEqual(run(synthetic,'SecurityEvents | where host == "NC-WS-014" | where source == "auth"').rows.map(row=>row.id),['A-01']);
  for(const [table,ids] of [['DnsEvents',['D-01']],['ProxyEvents',['P-01']],['DeviceEvents',['E-01']]])assert.deepEqual(run(synthetic,table).rows.map(row=>row.id),ids);
});
test('text predicates use documented exact, word and phrase semantics',async()=>{
  const {run}=await load();
  assert.deepEqual(run(synthetic,'SecurityEvents | where detail contains "SIGN-IN"').rows.map(row=>row.id),['A-01','A-02']);
  assert.deepEqual(run(synthetic,'SecurityEvents | where detail has "SIGN"').rows.map(row=>row.id),['A-01','A-02']);
  assert.deepEqual(run(synthetic,'SecurityEvents | where detail has "signi"').rows,[]);
  assert.deepEqual(run(synthetic,'SecurityEvents | where detail startswith "post"').rows.map(row=>row.id),['P-01']);
  assert.deepEqual(run(synthetic,'SecurityEvents | where user == "ALEX"').rows,[]);
  assert.throws(()=>run(synthetic,'SecurityEvents | where detail has "sign in"'),/has expects one word/);
});
test('quoted pipes, quotes, backslashes and attack-like literal text stay data',async()=>{
  const {run}=await load();
  assert.deepEqual(run(synthetic,'ProxyEvents | where detail contains "form | username"').rows.map(row=>row.id),['P-01']);
  assert.deepEqual(run(synthetic,"ProxyEvents | where detail contains 'form | username'").rows.map(row=>row.id),['P-01']);
  assert.deepEqual(run(synthetic,'DeviceEvents | where commandLine contains "\\\"C:\\\\Program Files"').rows.map(row=>row.id),['E-01']);
  for(const term of ['$(id)','<img onerror=alert(1)>',"\"; DROP TABLE auth.users; --",'https://external.example.invalid']){
    assert.equal(run(synthetic,'SecurityEvents | where detail contains '+JSON.stringify(term)).rows.length,0);
  }
});
test('integer process filters and projection preserve endpoint telemetry',async()=>{
  const {run}=await load();
  const result=run(synthetic,'DeviceEvents | where pid >= 5000 | where parentPid == 4240 | project id, processId, pid, parentPid, name, signature');
  assert.deepEqual(result.rows,[{id:'E-01',processId:'PROC-02',pid:5120,parentPid:4240,name:'msedge.exe',signature:'Microsoft Corporation; valid'}]);
  assert.deepEqual(run(synthetic,'SecurityEvents | where pid < 100').rows,[],'missing metadata is not a fabricated PID');
  assert.throws(()=>run(synthetic,'DeviceEvents | where pid > "5000"'),/integer values only/);
  assert.throws(()=>run(synthetic,'SecurityEvents | where pid == 9007199254740992'),/safe whole numbers/);
});
test('email queries expose headers and inert attachment metadata consistently',async()=>{
  const {run}=await load();
  const result=run(synthetic,'EmailEvents | where headers contains "SPF=FAIL" | project id, from, to, attachmentName, attachmentMime, attachmentSha256');
  assert.deepEqual(result.rows,[{id:'MAIL-01',from:synthetic.email.from,to:'alex@example.invalid',attachmentName:'Payroll.html',attachmentMime:'text/html',attachmentSha256:'ab'.repeat(32)}]);
  assert.equal(run(synthetic,'EmailEvents | where detail contains "spf=fail"').rows.length,1);
  assert.throws(()=>run(synthetic,'SigninLogs | project headers'),/Unknown or unavailable column/);
});
test('query parsing rejects unsupported execution, expressions and malformed pipelines with useful errors',async()=>{
  const {run}=await load();
  const invalid=[
    '',null,'auth.users','SecurityEvents; DROP TABLE auth.users','fetch("https://example.invalid")',
    'SecurityEvents | eval alert(1)','SecurityEvents | join EmailEvents','SecurityEvents | summarize count()',
    'SecurityEvents | where user matches regex ".*"','SecurityEvents | where user == alex',
    'SecurityEvents | where user == "alex" or 1 == 1','SecurityEvents | where user == "alex"; alert(1)',
    'SecurityEvents | where user == "alex','SecurityEvents | where user == "alex\\n"',
    'SecurityEvents | where user == "al\nex"','SecurityEvents | where unknown == "alex"',
    'SecurityEvents | where __proto__ == "x"','SecurityEvents | project id, id','SecurityEvents | project id,',
    'SecurityEvents | project id | where host == "NC-WS-014"','SecurityEvents | sort by unknown asc',
    'SecurityEvents | sort by time sideways','SecurityEvents | take 0','SecurityEvents | take 101','SecurityEvents | take -1',
    'SecurityEvents | take 1.5','SecurityEvents || take 2','SecurityEvents |','SecurityEvents\u0000',
    'x'.repeat(2001),'SecurityEvents'+(' | take 1'.repeat(13))
  ];
  for(const query of invalid)assert.throws(()=>run(synthetic,query),error=>error.name==='QueryError'&&error.message.length>10,String(query));
});
test('queries are bounded and do not mutate source rows or honor inherited fields',async()=>{
  const {run}=await load();
  const dataset={...synthetic,logs:Array.from({length:120},(_,i)=>({...synthetic.logs[0],id:'ROW-'+i}))};
  const before=JSON.stringify(dataset),result=run(dataset,'SecurityEvents');
  assert.equal(result.rows.length,100);assert.equal(result.total,120);assert.equal(result.limited,true);
  assert.equal(run(dataset,'SecurityEvents | take 5').total,5);
  result.rows[0].detail='changed output';assert.equal(JSON.stringify(dataset),before);
  const inherited=Object.assign(Object.create({pid:9999}),synthetic.logs[0]);
  assert.deepEqual(run({...synthetic,logs:[inherited]},'SecurityEvents | where pid == 9999').rows,[]);
  assert.throws(()=>run({logs:Array(5001).fill({})},'SecurityEvents'),/5,000 source records/);
  assert.throws(()=>run(null,'SecurityEvents'),/dataset is unavailable/);
  assert.deepEqual(run({...synthetic,email:null},'EmailEvents').rows,[]);
});
test('beginner examples run on the actual shared scenario and exported browser API needs no external service',async()=>{
  const api=await load(),{scenario}=await import('../api/_lib/soc.js');
  for(const example of api.examples)assert.doesNotThrow(()=>api.run(scenario,example.query),example.label);
  const context={window:{}};vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../assets/soc-query.js'),'utf8'),context);
  assert.equal(typeof context.window.CyberSOCQuery.run,'function');
  assert.match(context.window.CyberSOCQuery.help,/not Microsoft KQL or a live Sentinel connection/);
  assert.match(context.window.CyberSOCQuery.help,/100 returned rows/);
  assert.equal(context.window.CyberSOCQuery.run(synthetic,'ProxyEvents | take 1').rows[0].id,'P-01');
  const auth=api.run(scenario,'SigninLogs | where user == "alex" | sort by time asc');
  assert.deepEqual(auth.rows.map(row=>row.id),['AUTH-01','AUTH-02','AUTH-03']);
});

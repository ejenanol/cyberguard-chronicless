const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const load=()=>import('../api/_lib/soc.js');

function passing(){
  const evidence=['MAIL-01','DNS-01','PROXY-01','PROXY-02','AUTH-02','AUTH-03','EDR-01','EDR-05'];
  return {panel:'attack',inspected:[...evidence],timeline:['MAIL-01','PROXY-02','AUTH-02','AUTH-03'],
    report:{classification:'credential-phishing',severity:'high',user:'alex',endpoint:'NC-WS-014',iocs:'payroll-review.example\n203.0.113.44\n198.51.100.77',summary:'PROXY-02 establishes credential submission and AUTH-02 establishes unauthorized access. Revoke sessions, reset credentials, block the lure and preserve evidence. No endpoint malware was demonstrated.',evidence:[...evidence],containment:['revoke','reset','block','preserve']},
    console:{stage:'reconstruct',selectedProcess:'PROC-02',expandedProcesses:['PROC-01'],inspectedProcesses:['PROC-02'],relationships:[
      ['path-lure','confirmed',['MAIL-01','DNS-01']],['path-submit','confirmed',['PROXY-01','PROXY-02']],
      ['path-signin','confirmed',['PROXY-02','AUTH-02']],['path-mailbox','confirmed',['AUTH-02','AUTH-03']],
      ['path-execution','rejected',['EDR-01','EDR-05']]
    ].map(([id,status,evidence])=>({id,status,evidence,note:'These inspected records support this finding within the captured evidence window.'}))}
  };
}

test('Sentinel assessment requires grounded relationship decisions and endpoint inspection, not opening a view',async()=>{
  const {validateState,grade}=await load();
  const full=grade(validateState(passing()));assert.equal(full.score,100);assert.equal(full.passed,true);assert.equal(full.assessment_version,3);
  assert.equal(full.checks.length,10);assert.equal(full.checks.reduce((n,c)=>n+c.points,0),100);
  const opened=passing();opened.console.relationships=[];opened.console.inspectedProcesses=[];
  const result=grade(validateState(opened));assert.equal(result.score,75);assert.equal(result.passed,false);
  assert.equal(result.checks.find(c=>c.objective==='Supported attack path').ok,false);
  assert.equal(result.checks.find(c=>c.objective==='Endpoint process inspection').ok,false);
  for(const change of [
    state=>{state.console.relationships[4].status='confirmed';},
    state=>{state.console.relationships[0].status='hypothesis';},
    state=>{state.console.relationships[1].note='';},
    state=>{state.console.relationships[2].evidence=['PROXY-02'];},
    state=>{state.inspected=state.inspected.filter(id=>id!=='AUTH-03');},
    state=>{state.report.evidence=state.report.evidence.filter(id=>id!=='PROXY-01');}
  ]){
    const state=passing();change(state);const r=grade(validateState(state));
    assert.equal(r.passed,false);assert.equal(r.checks.find(c=>c.objective==='Supported attack path').ok,false);
  }
  const noBrowser=passing();noBrowser.console.inspectedProcesses=['PROC-03'];
  assert.equal(grade(validateState(noBrowser)).checks.find(c=>c.objective==='Endpoint process inspection').ok,false);
});

test('legacy workspace defaults and submission fingerprint retain their exact shape without a console extension',async()=>{
  const {validateState}=await load();
  const expected={version:1,panel:'briefing',selectedEvidence:null,query:'',source:'all',notes:'',hint:0,inspected:[],timeline:[],report:{classification:'',severity:'',user:'',endpoint:'',iocs:'',summary:'',evidence:[],containment:[]}};
  const normalized=validateState({});assert.deepEqual(normalized,expected);assert.equal(Object.hasOwn(normalized,'console'),false);
  const hash=state=>createHash('sha256').update(JSON.stringify({action:'submit',state})).digest('hex');
  assert.equal(hash(normalized),hash(expected));
  const enriched=validateState({...passing(),console:{...passing().console,entityNotes:[{id:'alex',note:'<img src=x onerror=alert(1)>'}],selectedEntity:'alex',selectedRelationship:'path-signin',query:'SigninLogs | where user == "alex" | take 10',lastQuery:'SecurityEvents | take 20'}});
  assert.equal(enriched.console.entityNotes[0].note,'<img src=x onerror=alert(1)>');
  assert.equal(enriched.console.selectedRelationship,'path-signin');assert.equal(enriched.console.stage,'reconstruct');
});

test('console selections and annotations are bounded and cannot invent evidence, processes or server assessment fields',async()=>{
  const {validateState}=await load();
  for(const console of [null,[],{version:99},{stage:'execute'}, {query:'x'.repeat(2001)},
    {selectedProcess:'malware.exe'},{selectedEntity:'<svg onload=alert(1)>'},
    {selectedRelationship:'made-up-edge'},{inspectedProcesses:['PROC-02','PROC-02']},
    {relationships:[{id:'path-lure',status:'assessed',note:''}]},
    {relationships:[{id:'path-lure',status:'confirmed',evidence:['AUTH-99']}]},
    {relationships:[{id:'path-lure',status:'confirmed',note:'x'.repeat(1201)}]},
    {entityNotes:[{id:'alex',note:'a'},{id:'alex',note:'b'}]}
  ])assert.throws(()=>validateState({console}));
  const state=validateState({console:{...passing().console,reward_xp:9999,passed:true}});
  assert.equal(state.console.reward_xp,undefined);assert.equal(state.console.passed,undefined);
});

test('synthetic graphs, process starts, parent relationships and network pivots agree with the evidence',async()=>{
  const {scenario}=await load();
  assert.match(scenario.simulation,/synthetic training simulation inspired by Microsoft Sentinel/i);
  assert.match(scenario.simulation,/No live Microsoft integration/);
  const events=new Map([[scenario.email.id,scenario.email],...scenario.logs.map(e=>[e.id,e])]);
  const entities=new Set(scenario.entities.map(e=>e.id));
  for(const entity of scenario.entities)for(const id of entity.evidence)assert.ok(events.has(id));
  for(const edge of scenario.relationships){
    assert.ok(entities.has(edge.from));assert.ok(entities.has(edge.to));
    assert.equal(edge.status,undefined);assert.equal(edge.correct,undefined);
    assert.ok(edge.evidence.some(id=>events.get(id)?.time===edge.time));
    for(const id of edge.evidence)assert.ok(events.has(id));
  }
  for(const alert of scenario.incident.alerts)for(const id of alert.evidence)assert.ok(events.has(id));
  for(const process of scenario.processes){
    const start=events.get(process.evidence[0]);
    for(const field of ['pid','parentPid','host','user','commandLine','filePath','sha256','signature'])assert.equal(process[field],start[field],`${process.id} ${field}`);
    assert.equal(process.startTime,start.time);assert.equal(start.processId,process.id);
    assert.ok(!process.filePath.includes(String.fromCharCode(92).repeat(2)),'Windows path uses normal separators');
    if(process.parentId){const parent=scenario.processes.find(p=>p.id===process.parentId);assert.equal(parent.pid,process.parentPid);assert.equal(parent.host,process.host);assert.ok(parent.startTime<=process.startTime);}
    for(const connection of process.network){
      assert.ok(connection.time>=process.startTime);
      assert.ok(connection.evidence.some(id=>events.get(id)?.time===connection.time));
      assert.ok(connection.evidence.some(id=>events.get(id)?.detail.includes(connection.destination)) || connection.destination==='203.0.113.44');
      for(const id of connection.evidence)assert.ok(events.has(id));
    }
  }
  assert.equal(scenario.processes.some(p=>p.parentId==='PROC-02'),false,'no invented malware process chain');
  assert.match(events.get('EDR-01').detail,/No child process, executable download or persistence detected/);
});

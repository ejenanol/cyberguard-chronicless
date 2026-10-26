// Server-only assessment. Never import this file into a browser asset.
export const scenarioId = 'phishing-soc-v1';
export const scenario = {
  id: scenarioId, title: 'NexaCorp: The payroll lure',
  briefing: 'Maya Chen: Three staff received suspicious payroll messages. Determine what actually happened to each recipient, preserve evidence, and recommend proportionate containment. All systems, addresses and actions here are simulated. Never visit an indicator.',
  objectives: ['Inspect the message and attachment', 'Classify the incident', 'Identify the affected user and endpoint', 'Correlate authentication, DNS, proxy and endpoint evidence', 'Build an ordered incident timeline', 'Extract indicators of compromise', 'Choose proportionate containment', 'Submit an evidence-backed severity assessment', 'Establish supported attack-path relationships', 'Inspect the relevant endpoint process'],
  email: {
    id: 'MAIL-01', time: '2026-10-23T09:00:00Z',
    from: 'NexaCorp Payroll <payroll@nexac0rp.example>',
    to: ['alex@nexacorp.example', 'jordan@nexacorp.example', 'sam@nexacorp.example'],
    subject: 'URGENT: Confirm payroll details before 10:00',
    headers: 'Return-Path: <dispatch@mailer.example>\nReply-To: help@nexac0rp.example\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail\nMessage-ID: <payroll-1023@mailer.example>',
    body: 'Your payment will be suspended unless you verify immediately at https://payroll-review.example/login. See Payroll_Update.html for instructions. — Payroll Support',
    attachment: {name: 'Payroll_Update.html', mime: 'text/html', size: '6.2 KB', sha256: 'ab'.repeat(32), preview: 'Offline preview: an HTML form branded NexaCorp sends username and password fields to https://payroll-review.example/collect. No executable payload or macros observed.'}
  },
  logs: [
    {id:'AUTH-01', time:'2026-10-23T08:50:00Z',source:'auth',user:'alex',host:'NC-WS-014',detail:'Successful sign-in from office 192.0.2.10; managed device; MFA satisfied'},
    {id:'DNS-01',time:'2026-10-23T09:02:10Z',source:'dns',user:'alex',host:'NC-WS-014',detail:'Query payroll-review.example -> 203.0.113.44'},
    {id:'PROXY-01',time:'2026-10-23T09:02:12Z',source:'proxy',user:'alex',host:'NC-WS-014',detail:'GET https://payroll-review.example/login HTTP 200'},
    {id:'PROXY-02',time:'2026-10-23T09:03:04Z',source:'proxy',user:'alex',host:'NC-WS-014',detail:'POST https://payroll-review.example/collect HTTP 200; form fields username,password; values redacted'},
    {id:'EDR-01',time:'2026-10-23T09:03:05Z',source:'endpoint',user:'alex',host:'NC-WS-014',detail:'Browser accessed HTML attachment and remote form. No child process, executable download or persistence detected',processId:'PROC-02',pid:5120,parentPid:4240},
    {id:'AUTH-02',time:'2026-10-23T09:07:00Z',source:'auth',user:'alex',host:'unmanaged',detail:'Successful password + MFA sign-in from 198.51.100.77; new device; user reports no travel or approval'},
    {id:'AUTH-03',time:'2026-10-23T09:08:00Z',source:'auth',user:'alex',host:'unmanaged',detail:'New session used to access payroll mailbox from 198.51.100.77'},
    {id:'DNS-02',time:'2026-10-23T09:04:00Z',source:'dns',user:'jordan',host:'NC-WS-022',detail:'Query payroll-review.example -> 203.0.113.44'},
    {id:'PROXY-03',time:'2026-10-23T09:04:01Z',source:'proxy',user:'jordan',host:'NC-WS-022',detail:'GET https://payroll-review.example/login BLOCKED by web filter; no POST observed'},
    {id:'EDR-02',time:'2026-10-23T09:04:02Z',source:'endpoint',user:'jordan',host:'NC-WS-022',detail:'Blocked page closed. No payload, process or persistence detected'},
    {id:'AUTH-04',time:'2026-10-23T09:05:00Z',source:'auth',user:'sam',host:'NC-WS-031',detail:'Routine office sign-in from 192.0.2.12; managed device'},
    {id:'PROXY-04',time:'2026-10-23T09:05:10Z',source:'proxy',user:'sam',host:'NC-WS-031',detail:'GET https://hr.nexacorp.example/payroll HTTP 200; independently opened official intranet'},
    {id:'EDR-03',time:'2026-10-23T09:06:00Z',source:'endpoint',user:'sam',host:'NC-WS-031',detail:'Reported MAIL-01 without opening attachment'},
    {id:'DNS-03',time:'2026-10-23T09:10:00Z',source:'dns',user:'sam',host:'NC-WS-031',detail:'Query updates.nexacorp.example -> 192.0.2.20; approved software update'},
    {id:'EDR-04',time:'2026-10-23T08:40:00Z',source:'endpoint',user:'alex',host:'NC-WS-014',processId:'PROC-01',pid:4240,parentPid:744,name:'explorer.exe',commandLine:"C:\\Windows\\explorer.exe",filePath:"C:\\Windows\\explorer.exe",sha256:null,signature:'Microsoft Windows · valid synthetic signature',detail:'Interactive desktop shell started. Parent PID 744 was outside this collection window; no parent process record is available.'},
    {id:'EDR-05',time:'2026-10-23T08:55:00Z',source:'endpoint',user:'alex',host:'NC-WS-014',processId:'PROC-02',pid:5120,parentPid:4240,name:'msedge.exe',commandLine:"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default",filePath:"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",sha256:null,signature:'Microsoft Corporation · valid synthetic signature',detail:'Microsoft Edge started from explorer.exe (PID 4240). Browser PID 5120 is associated with the web activity described in PROXY-01, PROXY-02 and EDR-01. No executable child was recorded in this evidence window.'},
    {id:'EDR-06',time:'2026-10-23T09:09:59Z',source:'endpoint',user:'sam',host:'NC-WS-031',processId:'PROC-03',pid:6336,parentPid:812,name:'NexaCorpUpdater.exe',commandLine:"\"C:\\Program Files\\NexaCorp\\NexaCorpUpdater.exe\" --scheduled",filePath:"C:\\Program Files\\NexaCorp\\NexaCorpUpdater.exe",sha256:'cd'.repeat(32),signature:'NexaCorp IT · approved synthetic signature',detail:'Approved scheduled software updater started from service PID 812 (outside the captured process set). Related DNS-03 records a routine update lookup, not evidence of the payroll lure executing. No network connection record for this process is included.'}
  ],
  simulation: 'Synthetic training simulation inspired by Microsoft Sentinel. No live Microsoft integration.',
  datasetNotes: 'Additional synthetic process-start records make the existing clean-browser finding inspectable. They do not add a malware execution chain. Missing hashes and parents are explicitly unavailable; all addresses, signatures and hashes are training data.',
  incident: {
    id:'NC-SOC-001', title:'NexaCorp: The payroll lure', severity:'Medium (initial alert)',
    status:'Active investigation', owner:'Maya Chen · NexaCorp SOC', time:'2026-10-23T09:06:00Z',
    alerts:[
      {id:'ALERT-01',title:'Payroll message reported by recipient',time:'2026-10-23T09:06:00Z',severity:'Medium',evidence:['MAIL-01','EDR-03'],entities:['mail','sam','alert-mail']},
      {id:'ALERT-02',title:'Unfamiliar successful identity access',time:'2026-10-23T09:07:00Z',severity:'High',evidence:['AUTH-02'],entities:['alex','signin-ip','signin']}
    ]
  },
  entities:[
    {id:'mail',type:'email',label:'Reported payroll message',time:'2026-10-23T09:00:00Z',evidence:['MAIL-01']},
    {id:'lure',type:'domain',label:'payroll-review.example',time:'2026-10-23T09:02:10Z',evidence:['MAIL-01','DNS-01']},
    {id:'submission',type:'activity',label:'Web form activity',time:'2026-10-23T09:03:04Z',user:'alex',host:'NC-WS-014',evidence:['PROXY-02']},
    {id:'signin',type:'activity',label:'Unfamiliar identity access',time:'2026-10-23T09:07:00Z',user:'alex',host:'unmanaged',evidence:['AUTH-02']},
    {id:'mailbox',type:'activity',label:'Mailbox session activity',time:'2026-10-23T09:08:00Z',user:'alex',host:'unmanaged',evidence:['AUTH-03']},
    {id:'alex',type:'user',label:'alex',evidence:['AUTH-01','PROXY-02','AUTH-02']},
    {id:'device',type:'device',label:'NC-WS-014',user:'alex',host:'NC-WS-014',evidence:['DNS-01','PROXY-02','EDR-01']},
    {id:'hosting-ip',type:'ip',label:'203.0.113.44',evidence:['DNS-01']},
    {id:'signin-ip',type:'ip',label:'198.51.100.77',evidence:['AUTH-02','AUTH-03']},
    {id:'alert-mail',type:'alert',label:'ALERT-01 · reported message',time:'2026-10-23T09:06:00Z',evidence:['MAIL-01','EDR-03']},
    {id:'browser',type:'process',label:'msedge.exe · PID 5120',processId:'PROC-02',user:'alex',host:'NC-WS-014',time:'2026-10-23T08:55:00Z',evidence:['EDR-05','EDR-01']},
    {id:'execution',type:'hypothesis',label:'Endpoint payload execution?',user:'alex',host:'NC-WS-014',evidence:['EDR-01']},
    {id:'jordan',type:'user',label:'jordan',evidence:['DNS-02','PROXY-03','EDR-02']},
    {id:'sam',type:'user',label:'sam',evidence:['AUTH-04','PROXY-04','EDR-03','DNS-03']}
  ],
  // These are candidate relationships, not assessment answers. The learner must
  // inspect the referenced records, choose a verdict and justify it in the casebook.
  relationships:[
    {id:'path-lure',from:'mail',to:'lure',label:'Message → web destination',time:'2026-10-23T09:02:10Z',evidence:['MAIL-01','DNS-01'],entities:['mail','lure','alex'],view:'attack'},
    {id:'path-submit',from:'lure',to:'submission',label:'Web destination → form activity',time:'2026-10-23T09:03:04Z',evidence:['PROXY-01','PROXY-02'],entities:['lure','submission','device','alex'],view:'attack'},
    {id:'path-signin',from:'submission',to:'signin',label:'Form activity → identity access',time:'2026-10-23T09:07:00Z',evidence:['PROXY-02','AUTH-02'],entities:['submission','signin','alex','signin-ip'],view:'attack'},
    {id:'path-mailbox',from:'signin',to:'mailbox',label:'Identity access → mailbox activity',time:'2026-10-23T09:08:00Z',evidence:['AUTH-02','AUTH-03'],entities:['signin','mailbox','alex','signin-ip'],view:'attack'},
    {id:'path-execution',from:'browser',to:'execution',label:'Browser → endpoint payload execution?',time:'2026-10-23T09:03:05Z',evidence:['EDR-01','EDR-05'],entities:['browser','execution','device','alex'],view:'attack'},
    {id:'graph-identity-device',from:'alex',to:'device',label:'Identity observed on device',time:'2026-10-23T09:03:04Z',evidence:['AUTH-01','PROXY-02'],entities:['alex','device'],view:'graph'},
    {id:'graph-domain-ip',from:'lure',to:'hosting-ip',label:'DNS resolution',time:'2026-10-23T09:02:10Z',evidence:['DNS-01'],entities:['lure','hosting-ip'],view:'graph'},
    {id:'graph-device-browser',from:'device',to:'browser',label:'Process recorded on device',time:'2026-10-23T08:55:00Z',evidence:['EDR-05'],entities:['device','browser'],view:'graph'},
    {id:'graph-report-alert',from:'sam',to:'alert-mail',label:'Reported message',time:'2026-10-23T09:06:00Z',evidence:['EDR-03'],entities:['sam','alert-mail','mail'],view:'graph'}
  ],
  processes:[
    {id:'PROC-01',name:'explorer.exe',pid:4240,parentPid:744,parentId:null,host:'NC-WS-014',user:'alex',startTime:'2026-10-23T08:40:00Z',commandLine:"C:\\Windows\\explorer.exe",filePath:"C:\\Windows\\explorer.exe",sha256:null,signature:'Microsoft Windows · valid synthetic signature',evidence:['EDR-04'],network:[]},
    {id:'PROC-02',name:'msedge.exe',pid:5120,parentPid:4240,parentId:'PROC-01',host:'NC-WS-014',user:'alex',startTime:'2026-10-23T08:55:00Z',commandLine:"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default",filePath:"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",sha256:null,signature:'Microsoft Corporation · valid synthetic signature',evidence:['EDR-05','EDR-01'],network:[
      {time:'2026-10-23T09:02:12Z',destination:'203.0.113.44',port:443,protocol:'HTTPS',evidence:['DNS-01','PROXY-01']},
      {time:'2026-10-23T09:03:04Z',destination:'203.0.113.44',port:443,protocol:'HTTPS',evidence:['PROXY-02']}
    ]},
    {id:'PROC-03',name:'NexaCorpUpdater.exe',pid:6336,parentPid:812,parentId:null,host:'NC-WS-031',user:'sam',startTime:'2026-10-23T09:09:59Z',commandLine:"\"C:\\Program Files\\NexaCorp\\NexaCorpUpdater.exe\" --scheduled",filePath:"C:\\Program Files\\NexaCorp\\NexaCorpUpdater.exe",sha256:'cd'.repeat(32),signature:'NexaCorp IT · approved synthetic signature',evidence:['EDR-06','DNS-03'],network:[]}
  ],
  actions: [
    {id:'revoke',label:'Revoke Alex’s active sessions'},
    {id:'reset',label:'Reset Alex’s credentials and re-enrol MFA via a trusted channel'},
    {id:'block',label:'Block the lure domain and quarantine matching messages'},
    {id:'preserve',label:'Preserve email, identity and endpoint evidence; investigate mailbox activity'},
    {id:'wipe',label:'Immediately wipe every recipient workstation'},
    {id:'ignore',label:'Close the alert because MFA was present'}
  ],
  hints: [
    'Start with MAIL-01. Compare the claimed identity, reply address and authentication results. A familiar logo proves nothing.',
    'Search payroll-review.example, then alex. Compare a page visit with a credential POST and subsequent sign-ins. Check the blocked request too.',
    'Order the credential submission before the unfamiliar successful sign-in. Cite both IDs. An endpoint that visited a lure is not automatically infected.'
  ],
  fields: ['classification','severity','user','endpoint','iocs','evidence','timeline','containment','summary']
};
const ids = new Set(['MAIL-01', ...scenario.logs.map(row => row.id)]);
const allowedActions = new Set(scenario.actions.map(row => row.id));
const panels = new Set(['briefing','email','logs','timeline','terminal','report','overview','graph','attack','processes','queries']);
const entityIds=new Set(scenario.entities.map(row=>row.id));
const relationshipIds=new Set(scenario.relationships.map(row=>row.id));
const processIds=new Set(scenario.processes.map(row=>row.id));
function text(value, max) {
  if (typeof value !== 'string' || value.length > max) throw new Error('Invalid text field');
  return value;
}
function list(value, max, valid) {
  if (!Array.isArray(value) || value.length > max || value.some(v => typeof v !== 'string' || !valid(v)) || new Set(value).size !== value.length) throw new Error('Invalid selection');
  return value;
}
function selected(value, valid) {
  if(value==null) return null;
  if(typeof value!=='string' || !valid.has(value)) throw new Error('Invalid console selection');
  return value;
}
function records(value,max,convert) {
  if(!Array.isArray(value) || value.length>max) throw new Error('Invalid annotations');
  const result=value.map(row=>{
    if(!row || typeof row!=='object' || Array.isArray(row)) throw new Error('Invalid annotation');
    return convert(row);
  });
  if(new Set(result.map(row=>row.id)).size!==result.length) throw new Error('Duplicate annotation');
  return result;
}
function validateConsole(value) {
  if(!value || typeof value!=='object' || Array.isArray(value) || (value.version!==undefined && value.version!==1)) throw new Error('Invalid console');
  const stage=value.stage ?? 'triage';
  if(!['triage','investigate','reconstruct','respond'].includes(stage)) throw new Error('Invalid investigation stage');
  return {
    version:1,stage,query:text(value.query ?? 'SecurityEvents | take 20',2000),lastQuery:text(value.lastQuery ?? '',2000),
    selectedEntity:selected(value.selectedEntity,entityIds),selectedRelationship:selected(value.selectedRelationship,relationshipIds),selectedProcess:selected(value.selectedProcess,processIds),
    expandedProcesses:list(value.expandedProcesses ?? [],processIds.size,id=>processIds.has(id)),
    inspectedProcesses:list(value.inspectedProcesses ?? [],processIds.size,id=>processIds.has(id)),
    relationships:records(value.relationships ?? [],relationshipIds.size,row=>{
      const id=selected(row.id,relationshipIds);
      if(!id || !['hypothesis','confirmed','rejected'].includes(row.status)) throw new Error('Invalid relationship verdict');
      return {id,status:row.status,evidence:list(row.evidence ?? [],ids.size,id=>ids.has(id)),note:text(row.note ?? '',1200)};
    }),
    entityNotes:records(value.entityNotes ?? [],entityIds.size,row=>{
      const id=selected(row.id,entityIds);if(!id) throw new Error('Invalid entity note');
      return {id,note:text(row.note ?? '',1200)};
    })
  };
}
export function validateState(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid workspace');
  const report = input.report || {};
  if(input.selectedEvidence != null && !ids.has(input.selectedEvidence)) throw new Error('Invalid selected evidence');
  const state={
    version:1, panel:panels.has(input.panel) ? input.panel : 'briefing',
    selectedEvidence:input.selectedEvidence ?? null,
    query:text(input.query ?? '',120), source:['all','auth','dns','proxy','endpoint'].includes(input.source) ? input.source : 'all',
    notes:text(input.notes ?? '',8000), hint:Math.max(0,Math.min(3,Number.isInteger(input.hint)?input.hint:0)),
    inspected:list(input.inspected ?? [],ids.size,id=>ids.has(id)),
    timeline:list(input.timeline ?? [],ids.size,id=>ids.has(id)),
    report:{
      classification:text(report.classification ?? '',40), severity:text(report.severity ?? '',20),
      user:text(report.user ?? '',60), endpoint:text(report.endpoint ?? '',60),
      iocs:text(report.iocs ?? '',1200), summary:text(report.summary ?? '',4000),
      evidence:list(report.evidence ?? [],ids.size,id=>ids.has(id)),
      containment:list(report.containment ?? [],6,id=>allowedActions.has(id))
    }
  };
  // Omit the extension for old saves/submission receipts. Normalizing an absent
  // console into defaults here would change the fingerprint of uncertain retries.
  if(Object.prototype.hasOwnProperty.call(input,'console')) state.console=validateConsole(input.console);
  return state;
}
export function grade(state) {
  const r=state.report;
  const checks = [
    {objective:'Email inspection',points:10,ok:state.inspected.includes('MAIL-01') && r.evidence.includes('MAIL-01'),explanation:'MAIL-01 shows a lookalike sender, failed authentication and a credential-collecting HTML form.'},
    {objective:'Classification',points:10,ok:r.classification==='credential-phishing',explanation:'This is credential phishing with account takeover, not proven endpoint malware.'},
    {objective:'Affected identity and endpoint',points:10,ok:r.user.trim().toLowerCase()==='alex' && r.endpoint.trim().toUpperCase()==='NC-WS-014',explanation:'Alex submitted credentials from NC-WS-014. Jordan was blocked; Sam used the official intranet.'},
    {objective:'Correlated evidence',points:10,ok:['DNS-01','PROXY-02','AUTH-02','EDR-01'].every(id=>r.evidence.includes(id)),explanation:'DNS-01 connects the lure domain to its hosting IP; PROXY-02 establishes credential submission; AUTH-02 establishes suspicious successful access; EDR-01 limits claims about malware. Correlate all four sources.'},
    {objective:'Incident timeline',points:10,ok:['MAIL-01','PROXY-02','AUTH-02','AUTH-03'].every(id=>state.timeline.includes(id)) && state.timeline.every((id,i,a)=>i===0 || evidenceTime(a[i-1])<=evidenceTime(id)),explanation:'09:00 lure → 09:03 credential POST → 09:07 unfamiliar sign-in → 09:08 mailbox access. Keep the entire timeline chronological.'},
    {objective:'Indicators',points:5,ok:['payroll-review.example','203.0.113.44','198.51.100.77'].every(ioc=>r.iocs.toLowerCase().split(/[\s,;]+/).includes(ioc)),explanation:'Separate the lure domain and hosting IP (203.0.113.44) from the sign-in source (198.51.100.77). All are synthetic.'},
    {objective:'Containment',points:10,ok:['revoke','reset','block','preserve'].every(id=>r.containment.includes(id)) && !r.containment.some(id=>['wipe','ignore'].includes(id)),explanation:'Revoke sessions, reset credentials and MFA, block/quarantine the lure, and preserve evidence. No evidence justifies wiping every endpoint.'},
    {objective:'Severity and report',points:10,ok:r.severity==='high' && r.summary.trim().length>=80 && ['PROXY-02','AUTH-02'].every(id=>r.summary.includes(id)),explanation:'High severity: confirmed unauthorized account access. Cite the credential submission and sign-in evidence, explain scope and uncertainty, and record containment.'},
    {objective:'Supported attack path',points:15,ok:gradePath(state),explanation:'Support the message-to-domain, form-submission, unfamiliar sign-in and mailbox-access relationships with inspected, cited records and a rationale. The browser telemetry does not support endpoint payload execution; reject that branch with its evidence. A hypothesis is not a confirmed incident step.'},
    {objective:'Endpoint process inspection',points:10,ok:!!state.console?.inspectedProcesses.includes('PROC-02') && ['EDR-01','EDR-05'].every(id=>state.inspected.includes(id) && r.evidence.includes(id)),explanation:'Inspect the legitimate msedge.exe process (PID 5120, parent explorer.exe PID 4240) and cite EDR-05 plus EDR-01. Browser activity supports credential exposure; no executable child or persistence was recorded. Missing hashes and uncaptured parents are not evidence of malware.'}
  ];
  const score=checks.reduce((sum,c)=>sum+(c.ok?c.points:0),0);
  // The integrated chapter requires the entire investigation, not a high score
  // that skips triage, the timeline or indicators. Keep partial scores for feedback.
  const passed=checks.every(check=>check.ok);
  return {assessment_version:3,score,passed,checks,objectives:checks.filter(c=>c.ok).map(c=>c.objective),debrief:'Maya Chen: Correlation beats assumptions. Three recipients did not mean three compromised endpoints. Contain the confirmed identity compromise, preserve evidence and investigate mailbox scope. A clean endpoint event does not erase the identity incident.'};
}
function evidenceTime(id) {return id==='MAIL-01'?scenario.email.time:scenario.logs.find(row=>row.id===id)?.time || '';}

// Server-only verdict rubric. Candidate relationships in scenario contain no key.
function gradePath(state) {
  const verdicts=new Map((state.console?.relationships || []).map(row=>[row.id,row]));
  const required=[
    ['path-lure','confirmed',['MAIL-01','DNS-01']],
    ['path-submit','confirmed',['PROXY-01','PROXY-02']],
    ['path-signin','confirmed',['PROXY-02','AUTH-02']],
    ['path-mailbox','confirmed',['AUTH-02','AUTH-03']],
    ['path-execution','rejected',['EDR-01','EDR-05']]
  ];
  return required.every(([id,status,evidence])=>{
    const row=verdicts.get(id);
    return row?.status===status && row.note.trim().length>=20 && evidence.every(id=>row.evidence.includes(id) && state.inspected.includes(id) && state.report.evidence.includes(id));
  });
}

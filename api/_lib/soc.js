// Server-only assessment. Never import this file into a browser asset.
export const scenarioId = 'phishing-soc-v1';
export const scenario = {
  id: scenarioId, title: 'NexaCorp: The payroll lure',
  briefing: 'Maya Chen: Three staff received suspicious payroll messages. Determine what actually happened to each recipient, preserve evidence, and recommend proportionate containment. All systems, addresses and actions here are simulated. Never visit an indicator.',
  objectives: ['Inspect the message and attachment', 'Classify the incident', 'Identify the affected user and endpoint', 'Correlate authentication, DNS, proxy and endpoint evidence', 'Build an ordered incident timeline', 'Extract indicators of compromise', 'Choose proportionate containment', 'Submit an evidence-backed severity assessment'],
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
    {id:'EDR-01',time:'2026-10-23T09:03:05Z',source:'endpoint',user:'alex',host:'NC-WS-014',detail:'Browser accessed HTML attachment and remote form. No child process, executable download or persistence detected'},
    {id:'AUTH-02',time:'2026-10-23T09:07:00Z',source:'auth',user:'alex',host:'unmanaged',detail:'Successful password + MFA sign-in from 198.51.100.77; new device; user reports no travel or approval'},
    {id:'AUTH-03',time:'2026-10-23T09:08:00Z',source:'auth',user:'alex',host:'unmanaged',detail:'New session used to access payroll mailbox from 198.51.100.77'},
    {id:'DNS-02',time:'2026-10-23T09:04:00Z',source:'dns',user:'jordan',host:'NC-WS-022',detail:'Query payroll-review.example -> 203.0.113.44'},
    {id:'PROXY-03',time:'2026-10-23T09:04:01Z',source:'proxy',user:'jordan',host:'NC-WS-022',detail:'GET https://payroll-review.example/login BLOCKED by web filter; no POST observed'},
    {id:'EDR-02',time:'2026-10-23T09:04:02Z',source:'endpoint',user:'jordan',host:'NC-WS-022',detail:'Blocked page closed. No payload, process or persistence detected'},
    {id:'AUTH-04',time:'2026-10-23T09:05:00Z',source:'auth',user:'sam',host:'NC-WS-031',detail:'Routine office sign-in from 192.0.2.12; managed device'},
    {id:'PROXY-04',time:'2026-10-23T09:05:10Z',source:'proxy',user:'sam',host:'NC-WS-031',detail:'GET https://hr.nexacorp.example/payroll HTTP 200; independently opened official intranet'},
    {id:'EDR-03',time:'2026-10-23T09:06:00Z',source:'endpoint',user:'sam',host:'NC-WS-031',detail:'Reported MAIL-01 without opening attachment'},
    {id:'DNS-03',time:'2026-10-23T09:10:00Z',source:'dns',user:'sam',host:'NC-WS-031',detail:'Query updates.nexacorp.example -> 192.0.2.20; approved software update'}
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
const panels = new Set(['briefing','email','logs','timeline','terminal','report']);
function text(value, max) {
  if (typeof value !== 'string' || value.length > max) throw new Error('Invalid text field');
  return value;
}
function list(value, max, valid) {
  if (!Array.isArray(value) || value.length > max || value.some(v => typeof v !== 'string' || !valid(v)) || new Set(value).size !== value.length) throw new Error('Invalid selection');
  return value;
}
export function validateState(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid workspace');
  const report = input.report || {};
  if(input.selectedEvidence != null && !ids.has(input.selectedEvidence)) throw new Error('Invalid selected evidence');
  return {
    version:1, panel:panels.has(input.panel) ? input.panel : 'briefing',
    selectedEvidence:input.selectedEvidence ?? null,
    query:text(input.query ?? '',120), source:['all','auth','dns','proxy','endpoint'].includes(input.source) ? input.source : 'all',
    notes:text(input.notes ?? '',8000), hint:Math.max(0,Math.min(3,Number.isInteger(input.hint)?input.hint:0)),
    inspected:list(input.inspected ?? [],20,id=>ids.has(id)),
    timeline:list(input.timeline ?? [],15,id=>ids.has(id)),
    report:{
      classification:text(report.classification ?? '',40), severity:text(report.severity ?? '',20),
      user:text(report.user ?? '',60), endpoint:text(report.endpoint ?? '',60),
      iocs:text(report.iocs ?? '',1200), summary:text(report.summary ?? '',4000),
      evidence:list(report.evidence ?? [],15,id=>ids.has(id)),
      containment:list(report.containment ?? [],6,id=>allowedActions.has(id))
    }
  };
}
export function grade(state) {
  const r=state.report;
  const checks = [
    {objective:'Email inspection',points:10,ok:state.inspected.includes('MAIL-01') && r.evidence.includes('MAIL-01'),explanation:'MAIL-01 shows a lookalike sender, failed authentication and a credential-collecting HTML form.'},
    {objective:'Classification',points:10,ok:r.classification==='credential-phishing',explanation:'This is credential phishing with account takeover, not proven endpoint malware.'},
    {objective:'Affected identity and endpoint',points:15,ok:r.user.trim().toLowerCase()==='alex' && r.endpoint.trim().toUpperCase()==='NC-WS-014',explanation:'Alex submitted credentials from NC-WS-014. Jordan was blocked; Sam used the official intranet.'},
    {objective:'Correlated evidence',points:15,ok:['DNS-01','PROXY-02','AUTH-02','EDR-01'].every(id=>r.evidence.includes(id)),explanation:'DNS-01 connects the lure domain to its hosting IP; PROXY-02 establishes credential submission; AUTH-02 establishes suspicious successful access; EDR-01 limits claims about malware. Correlate all four sources.'},
    {objective:'Incident timeline',points:10,ok:['MAIL-01','PROXY-02','AUTH-02','AUTH-03'].every(id=>state.timeline.includes(id)) && state.timeline.every((id,i,a)=>i===0 || evidenceTime(a[i-1])<=evidenceTime(id)),explanation:'09:00 lure → 09:03 credential POST → 09:07 unfamiliar sign-in → 09:08 mailbox access. Keep the entire timeline chronological.'},
    {objective:'Indicators',points:10,ok:['payroll-review.example','203.0.113.44','198.51.100.77'].every(ioc=>r.iocs.toLowerCase().split(/[\s,;]+/).includes(ioc)),explanation:'Separate the lure domain and hosting IP (203.0.113.44) from the sign-in source (198.51.100.77). All are synthetic.'},
    {objective:'Containment',points:15,ok:['revoke','reset','block','preserve'].every(id=>r.containment.includes(id)) && !r.containment.some(id=>['wipe','ignore'].includes(id)),explanation:'Revoke sessions, reset credentials and MFA, block/quarantine the lure, and preserve evidence. No evidence justifies wiping every endpoint.'},
    {objective:'Severity and report',points:15,ok:r.severity==='high' && r.summary.trim().length>=80 && ['PROXY-02','AUTH-02'].every(id=>r.summary.includes(id)),explanation:'High severity: confirmed unauthorized account access. Cite the credential submission and sign-in evidence, explain scope and uncertainty, and record containment.'}
  ];
  const score=checks.reduce((sum,c)=>sum+(c.ok?c.points:0),0);
  // The integrated chapter requires the entire investigation, not a high score
  // that skips triage, the timeline or indicators. Keep partial scores for feedback.
  const passed=checks.every(check=>check.ok);
  return {assessment_version:2,score,passed,checks,objectives:checks.filter(c=>c.ok).map(c=>c.objective),debrief:'Maya Chen: Correlation beats assumptions. Three recipients did not mean three compromised endpoints. Contain the confirmed identity compromise, preserve evidence and investigate mailbox scope. A clean endpoint event does not erase the identity incident.'};
}
function evidenceTime(id) {return id==='MAIL-01'?scenario.email.time:scenario.logs.find(row=>row.id===id)?.time || '';}

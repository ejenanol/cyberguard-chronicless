const {test,expect}=require('@playwright/test');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const sdk=fs.readFileSync(path.join(__dirname,'../support/sdk-fixture.js'),'utf8');
const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';
const heading='🎣 NexaCorp: The payroll lure';
const headers={Authorization:'Bearer test-A'};
function game(overrides={}){
  return {user_id:A,username:'agent',email:'agent@example.test',profile:'pro',xp:0,done_chaps:[],codex:[],player_name:'Agent',chap_idx:0,chal_idx:0,checkpoint:{screen:'title'},updated_at:'2026-10-22T00:00:00Z',...overrides};
}
function workspace(overrides={}){
  return {version:1,panel:'email',selectedEvidence:null,query:'',source:'all',notes:'',hint:0,inspected:[],timeline:[],report:{classification:'',severity:'',user:'',endpoint:'',iocs:'',summary:'',evidence:[],containment:[]},...overrides};
}
function findings(panel='report'){
  return workspace({panel,notes:'Saved investigation, not a new attempt',inspected:['MAIL-01'],timeline:['MAIL-01','DNS-01','PROXY-02','AUTH-02','AUTH-03'],report:{classification:'credential-phishing',severity:'high',user:'alex',endpoint:'NC-WS-014',iocs:'payroll-review.example\n203.0.113.44\n198.51.100.77',summary:'PROXY-02 proves credential submission and AUTH-02 records unauthorized access. Revoke sessions, reset credentials and preserve mailbox evidence; EDR-01 does not prove endpoint malware.',evidence:['MAIL-01','DNS-01','PROXY-02','AUTH-02','EDR-01'],containment:['revoke','reset','block','preserve']}});
}
async function visit(page,seed){
  if(seed)await page.addInitScript(({id,row})=>{const key='test-game:'+id;if(!localStorage.getItem(key))localStorage.setItem(key,JSON.stringify(row));},{id:A,row:seed});
  await page.route('https://cdn.jsdelivr.net/**',route=>route.fulfill({contentType:'text/javascript',body:sdk}));
  await page.goto('/');
  await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
}
async function inWorkspace(page){await expect(page.getByRole('heading',{name:heading})).toBeVisible();}
async function tab(page,panel){await page.locator(`[data-tab="${panel}"]`).click();}
async function saved(page){await expect(page.locator('[data-status]')).toHaveText('Saved to cloud',{timeout:15000});}
async function reload(page){await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();await inWorkspace(page);}
async function signOutIn(page){
  page.once('dialog',dialog=>dialog.accept());
  await page.getByRole('button',{name:'SIGN OUT',exact:true}).click();
  await page.getByLabel('AGENT ID / EMAIL',{exact:true}).fill('agent@example.test');
  await page.getByLabel('SECURITY KEY',{exact:true}).fill('test-password');
  await page.getByRole('button',{name:'⚡ AUTHENTICATE'}).click();
  await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await inWorkspace(page);
}
async function seedSoc(request,record){const response=await request.post('/__test/seed-soc',{data:record});expect(response.ok()).toBe(true);}
async function api(request,body,token='test-A'){
  return request.post('/api/soc',{headers:{Authorization:'Bearer '+token},data:body});
}
async function record(request,token='test-A'){
  const response=await request.get('/api/soc',{headers:{Authorization:'Bearer '+token}});expect(response.ok()).toBe(true);return (await response.json()).record;
}
async function fillReport(page){
  await tab(page,'email');await page.getByLabel('Cite MAIL-01 in report').check();await page.getByRole('button',{name:'Add email to timeline'}).click();
  await tab(page,'logs');
  for(const id of ['DNS-01','PROXY-02','AUTH-02','AUTH-03','EDR-01']){
    await page.getByLabel('Literal search').fill(id);await page.getByRole('button',{name:'Search',exact:true}).click();
    await page.getByLabel('Cite '+id,{exact:true}).check();
    if(id!=='EDR-01')await page.getByRole('button',{name:'Add to timeline',exact:true}).click();
  }
  await tab(page,'report');
  const r=findings().report;
  await page.getByLabel('Incident classification').selectOption(r.classification);
  await page.getByLabel('Severity',{exact:true}).selectOption(r.severity);
  await page.getByLabel('Confirmed affected username').fill(r.user);
  await page.getByLabel('Endpoint used for credential submission').fill(r.endpoint);
  await page.getByLabel('Indicators (one per line; domain and relevant IP addresses)').fill(r.iocs);
  for(const id of r.containment)await page.locator(`[data-containment="${id}"]`).check();
  await page.getByLabel('Analyst summary — evidence IDs, impact, scope, uncertainty and response').fill(r.summary);
}
async function assess(page){await page.getByRole('button',{name:'Submit for assessment'}).click();await expect(page.getByRole('heading',{name:'Last server assessment · 100/100 · Passed'})).toBeVisible();}

test.beforeEach(async({request})=>{await request.post('/__test/reset');});

test('Chapter 1 Start connects Maya briefing, all four stages, debrief and server completion',async({page,request})=>{
  await page.setViewportSize({width:1280,height:1000});
  await visit(page,game());
  const chapter=page.locator('[aria-label="Chapter 1: Phishing & Social Engineering"]');
  await expect(chapter).toContainText('150 XP');await expect(chapter).not.toContainText('425 XP');
  await expect(page.locator('.soc-launch')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Open SOC investigation',exact:true})).toHaveCount(0);
  await page.screenshot({path:test.info().outputPath('chapter-one-menu.png'),animations:'disabled'});
  await page.getByRole('button',{name:'Start Chapter 1',exact:true}).click();
  await expect(page.locator('#typer-out')).toContainText(/Maya/i);
  await expect(page.locator('#typer-out')).toContainText('NexaCorp');
  await expect(page.locator('#typer-out')).not.toContainText('Three employees fell');
  await page.screenshot({path:test.info().outputPath('chapter-one-briefing.png'),animations:'disabled'});
  await page.getByRole('button',{name:'BEGIN INVESTIGATION ▶',exact:true}).click();await inWorkspace(page);
  await expect(page.locator('[data-tab="email"]')).toHaveAttribute('aria-pressed','true');
  const stages=page.getByRole('navigation',{name:'Investigation stages',exact:true});
  for(const label of ['Triage','Investigate','Reconstruct','Respond'])await expect(stages.getByRole('button',{name:label,exact:true})).toBeVisible();
  await fillReport(page);await saved(page);
  const draft=await record(request);expect(draft.state.report.evidence).toEqual(expect.arrayContaining(['DNS-01','PROXY-02','AUTH-02','EDR-01']));
  await assess(page);expect(await page.evaluate(()=>ST.xp)).toBe(150);
  const completed=page.waitForResponse(response=>response.url().endsWith('/api/soc')&&response.request().method()==='POST'&&response.request().postDataJSON().action==='complete');
  await page.getByRole('button',{name:'Complete Chapter 1',exact:true}).click();
  expect((await completed).status()).toBe(200);
  await expect(page.getByText('CHAPTER 1 COMPLETE',{exact:true})).toBeVisible();
  expect((await record(request)).chapter_completed_at).toBeTruthy();
  expect(await page.evaluate(()=>ST.doneChaps)).toContain(1);
  expect(await page.evaluate(()=>ST.codex.some(entry=>entry.term==='Phishing'))).toBe(true);
  await expect.poll(()=>page.evaluate(()=>JSON.parse(localStorage.getItem('test-game:'+ST.authUser.id)).xp)).toBe(0);
  await page.getByRole('button',{name:'→ NEXT CHAPTER',exact:true}).click();
  await expect(page.getByRole('button',{name:'Replay Chapter 1',exact:true})).toBeVisible();
  await page.locator('[onclick="startChap(1)"]').click();
  await page.getByRole('button',{name:'BEGIN MISSIONS ▶',exact:true}).click();
  await expect(page.getByText('MISSION 2-A: Spot the Vishing Call',{exact:true})).toBeVisible();
});

for(const panel of ['email','logs','timeline','report']){
  test(`Resume restores ${panel} stage after refresh, logout and Chapter 1 card entry`,async({page,request})=>{
    const state=findings(panel);state.notes='Resume at '+panel;state.selectedEvidence=panel==='logs'?'AUTH-02':null;
    await seedSoc(request,{state,revision:4});
    await visit(page,game({xp:275,chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);
    await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Resume at '+panel);
    await reload(page);await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    await signOutIn(page);await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    await page.locator('[data-exit]').click();
    await page.getByRole('button',{name:'Resume Chapter 1',exact:true}).click();await inWorkspace(page);
    await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Resume at '+panel);
    expect((await record(request)).state.timeline).toEqual(state.timeline);
    expect(await page.evaluate(()=>ST.xp)).toBe(275);
  });
}

for(const mission of [0,1,2]){
  test(`legacy Chapter 1 mission ${mission} maps to triage without losing XP or inventing citations`,async({page,request})=>{
    const xp=[100,175,250][mission];
    const old={screen:'challenge',selOpt:1,classifyAnswers:{a:0},foundSpots:['em']};
    await visit(page,game({xp,chal_idx:mission,checkpoint:old,codex:[{term:'Retained learning',def:'Keep this entry'}]}));
    await expect(page.getByRole('button',{name:'BEGIN INVESTIGATION ▶',exact:true})).toBeVisible();
    expect(await page.evaluate(()=>ST.xp)).toBe(xp);
    await expect.poll(()=>page.evaluate(()=>JSON.parse(localStorage.getItem('test-game:'+ST.authUser.id)).checkpoint.chapter1Legacy?.chalIdx)).toBe(mission);
    const backup=await page.evaluate(()=>JSON.parse(localStorage.getItem('test-game:'+ST.authUser.id)).checkpoint.chapter1Legacy);
    expect(backup.checkpoint.selOpt).toBe(1);
    await page.getByRole('button',{name:'BEGIN INVESTIGATION ▶',exact:true}).click();await inWorkspace(page);await saved(page);
    await expect(page.locator('[data-tab="email"]')).toHaveAttribute('aria-pressed','true');
    expect((await record(request)).state.report.evidence).toEqual([]);
    expect(await page.evaluate(()=>ST.xp)).toBe(xp);
    expect(await page.evaluate(()=>ST.codex.some(entry=>entry.term==='Retained learning'))).toBe(true);
  });
}

test('grandfathered chapter completion remains replayable and later chapters stay unlocked',async({page,request})=>{
  await seedSoc(request,{revision:0,reward_xp:0,chapter_completed_at:true,state:workspace()});
  await visit(page,game({xp:900,done_chaps:[1,2],checkpoint:{screen:'title'},codex:[{term:'Existing achievement',def:'Preserved'}]}));
  await expect(page.getByRole('button',{name:'Replay Chapter 1',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>ST.doneChaps)).toEqual([1,2]);expect(await page.evaluate(()=>ST.xp)).toBe(900);
  await page.getByRole('button',{name:'Replay Chapter 1',exact:true}).click();
  await expect(page.locator('#typer-out')).toContainText(/Maya/i);
  await page.getByRole('button',{name:'REPLAY INVESTIGATION ▶',exact:true}).click();await inWorkspace(page);await saved(page);
  expect(await page.evaluate(()=>ST.doneChaps)).toEqual([1,2]);expect(await page.evaluate(()=>ST.xp)).toBe(900);
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('');
});

test('Replay resets the cached draft once and never repeats an already earned reward',async({page,request})=>{
  const submission=await api(request,{action:'submit',revision:0,requestId:randomUUID(),state:findings()});expect(submission.ok()).toBe(true);
  const earned=await submission.json();
  const receipt=await api(request,{action:'complete',revision:earned.record.revision,requestId:randomUUID()});expect(receipt.ok()).toBe(true);
  await visit(page,game({xp:275,done_chaps:[1],chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Saved investigation, not a new attempt');
  await page.locator('[data-exit]').click();await page.getByRole('button',{name:'Replay Chapter 1',exact:true}).click();
  await page.getByRole('button',{name:'REPLAY INVESTIGATION ▶',exact:true}).click();await inWorkspace(page);await saved(page);
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('');
  let replay=await record(request);expect(replay.state.report.evidence).toEqual([]);expect(replay.reward_xp).toBe(150);expect(replay.chapter_completed_at).toBeTruthy();
  await page.getByLabel('Analyst notes (private to your account)').fill('Fresh replay note');await saved(page);await reload(page);
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Fresh replay note');
  await fillReport(page);await saved(page);await request.post('/__test/unthrottle');await assess(page);
  expect(await page.evaluate(()=>ST.xp)).toBe(425);replay=await record(request);expect(replay.reward_xp).toBe(150);
});

test('chapter completion rejects forged success and survives a failed completion request and retry',async({page,request})=>{
  const forged=await api(request,{action:'complete',revision:0,requestId:randomUUID(),passed:true,result:{passed:true},reward_xp:150});expect(forged.status()).toBe(422);
  expect((await record(request)).chapter_completed_at).toBeFalsy();
  await visit(page,game({chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);await fillReport(page);await saved(page);await assess(page);
  let fail=true;await page.route('**/api/soc',async route=>{
    if(route.request().method()==='POST'&&route.request().postDataJSON().action==='complete'&&fail){fail=false;await route.abort('failed');return;}
    await route.continue();
  });
  await page.getByRole('button',{name:'Complete Chapter 1',exact:true}).click();
  await expect(page.locator('[data-status]')).toContainText(/failed|pending|retry/i);
  await expect(page.getByRole('heading',{name:'Last server assessment · 100/100 · Passed'})).toBeVisible();
  expect(await page.evaluate(()=>ST.doneChaps.includes(1))).toBe(false);expect((await record(request)).chapter_completed_at).toBeFalsy();
  await page.getByRole('button',{name:'Retry sync',exact:true}).click();
  await expect(page.getByText('CHAPTER 1 COMPLETE',{exact:true})).toBeVisible();
  const completed=await record(request);expect(completed.chapter_completed_at).toBeTruthy();expect(completed.reward_xp).toBe(150);
  const again=await api(request,{action:'complete',revision:0,requestId:randomUUID()});expect(again.status()).toBe(200);
  expect(Date.parse((await again.json()).record.chapter_completed_at)).toBe(Date.parse(completed.chapter_completed_at));
  expect((await record(request)).reward_xp).toBe(150);
});

test('new assessments require all four evidence sources before chapter completion',async({page,request})=>{
  await visit(page,game({chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);await fillReport(page);
  await tab(page,'logs');await page.getByLabel('Literal search').fill('DNS-01');await page.getByRole('button',{name:'Search',exact:true}).click();await page.getByLabel('Cite DNS-01',{exact:true}).uncheck();
  await tab(page,'report');await saved(page);await page.getByRole('button',{name:'Submit for assessment'}).click();
  await expect(page.getByRole('heading',{name:/Last server assessment.*Keep investigating/})).toBeVisible();
  await expect(page.getByRole('button',{name:'Complete Chapter 1',exact:true})).toHaveCount(0);
  expect(await page.evaluate(()=>ST.socReward)).toBe(0);
  const denied=await api(request,{action:'complete',revision:(await record(request)).revision,requestId:randomUUID()});expect(denied.status()).toBe(422);
});

test('another user cannot claim an assessed agent’s chapter completion',async({request})=>{
  const result=await api(request,{action:'submit',revision:0,requestId:randomUUID(),state:findings()});expect(result.status()).toBe(200);
  const own=await record(request);expect(own.reward_xp).toBe(150);
  const forged=await api(request,{action:'complete',revision:own.revision,requestId:randomUUID(),user_id:A,reward_xp:150},'test-B');expect(forged.status()).toBe(422);
  expect((await record(request)).chapter_completed_at).toBeFalsy();expect((await record(request,'test-B')).reward_xp).toBe(0);
});


test('completion retry uses the latest acknowledged draft revision after notes change',async({page,request})=>{
  const graded=await api(request,{action:'submit',revision:0,requestId:randomUUID(),state:findings()});expect(graded.status()).toBe(200);
  await visit(page,game({chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);
  let fail=true;await page.route('**/api/soc',async route=>{
    if(route.request().method()==='POST'&&route.request().postDataJSON().action==='complete'&&fail){fail=false;await route.abort('failed');return;}
    await route.continue();
  });
  await page.getByRole('button',{name:'Complete Chapter 1',exact:true}).click();await expect(page.locator('[data-status]')).toContainText('completion failed');
  await page.getByLabel('Analyst notes (private to your account)').fill('Latest notes after failed completion');
  await expect(page.locator('[data-status]')).toContainText('Saved to cloud; Chapter 1 completion pending');
  await page.getByRole('button',{name:'Retry sync',exact:true}).click();
  await expect(page.getByText('CHAPTER 1 COMPLETE',{exact:true})).toBeVisible();
  const cloud=await record(request);expect(cloud.state.notes).toBe('Latest notes after failed completion');expect(cloud.reward_xp).toBe(150);expect(cloud.chapter_completed_at).toBeTruthy();
});

test('chapter briefing preserves earlier mission learning as a non-rewarding field guide',async({page})=>{
  await visit(page,game());await page.getByRole('button',{name:'Start Chapter 1',exact:true}).click();
  await page.getByText('Phishing field guide · earlier mission learning',{exact:true}).click();
  await expect(page.getByRole('heading',{name:'Verify through a trusted source',exact:true})).toBeVisible();
  await expect(page.getByText(/Always verify through a trusted independent channel/)).toBeVisible();
  expect(await page.evaluate(()=>ST.xp)).toBe(0);await expect(page.getByRole('button',{name:'BEGIN INVESTIGATION ▶',exact:true})).toBeVisible();
});


test('an uncertain completion response retries the already committed receipt without duplicate rewards',async({page,request})=>{
  const submitted=await api(request,{action:'submit',revision:0,requestId:randomUUID(),state:findings()});expect(submitted.status()).toBe(200);
  await visit(page,game({chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);
  let drop=true;await page.route('**/api/soc',async route=>{
    if(route.request().method()==='POST'&&route.request().postDataJSON().action==='complete'&&drop){drop=false;await route.fetch();await route.abort('failed');return;}
    await route.continue();
  });
  await page.getByRole('button',{name:'Complete Chapter 1',exact:true}).click();await expect(page.locator('[data-status]')).toContainText('completion failed');
  const committed=await record(request);expect(committed.chapter_completed_at).toBeTruthy();expect(committed.reward_xp).toBe(150);
  await page.getByRole('button',{name:'Retry sync',exact:true}).click();await expect(page.getByText('CHAPTER 1 COMPLETE',{exact:true})).toBeVisible();
  const retried=await record(request);expect(Date.parse(retried.chapter_completed_at)).toBe(Date.parse(committed.chapter_completed_at));expect(retried.reward_xp).toBe(150);expect(await page.evaluate(()=>ST.xp)).toBe(150);
});


test('a clean offline backup reconnects without editing and restores confirmed reward metadata',async({page,request})=>{
  const submitted=await api(request,{action:'submit',revision:0,requestId:randomUUID(),state:findings()});expect(submitted.status()).toBe(200);
  await visit(page,game({xp:275,chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);
  await page.getByLabel('Analyst notes (private to your account)').fill('Clean cloud-backed draft');await saved(page);
  const before=await record(request);
  await page.route('**/api/soc',route=>route.abort('failed'));await reload(page);
  await expect(page.locator('[data-status]')).toContainText('Offline: restored local draft');
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Clean cloud-backed draft');
  await page.unroute('**/api/soc');await page.getByRole('button',{name:'Retry sync',exact:true}).click();
  await expect(page.locator('[data-status]')).toHaveText('Loaded cloud save');
  await expect(page.getByText('425 XP',{exact:true})).toBeVisible();
  const after=await record(request);expect(after.revision).toBe(before.revision);expect(after.state.notes).toBe(before.state.notes);
});


test('a stale workspace cannot send one agent’s private draft under a different signed-in account',async({page,request})=>{
  await visit(page,game({chal_idx:3,checkpoint:{screen:'challenge'}}));await inWorkspace(page);
  await page.getByLabel('Analyst notes (private to your account)').fill('Agent A private draft');await saved(page);
  await page.evaluate(user=>{sb.auth.getSession=async()=>({data:{session:{user:{id:user},access_token:'test-B'}}});},B);
  await page.getByLabel('Analyst notes (private to your account)').fill('Agent A private edit after session changed');
  await expect(page.locator('[data-status]')).toContainText('signed-in agent changed');
  const other=await record(request,'test-B');expect(other.revision).toBe(0);expect(other.state.notes).toBe('');
  expect((await record(request)).state.notes).toBe('Agent A private draft');
});

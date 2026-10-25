const {test,expect}=require('@playwright/test');
const fs=require('node:fs');
const path=require('node:path');
const sdk=fs.readFileSync(path.join(__dirname,'../support/sdk-fixture.js'),'utf8');

async function open(page){
  await page.route('https://cdn.jsdelivr.net/**',route=>route.fulfill({contentType:'text/javascript',body:sdk}));
  await page.goto('/');
  await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByRole('heading',{name:'🎣 NexaCorp: The payroll lure'})).toBeVisible();
}
async function tab(page,name){await page.locator(`[data-tab="${name}"]`).click();}
async function saved(page){await expect(page.locator('[data-status]')).toHaveText('Saved to cloud',{timeout:15000});}

test.beforeEach(async({request})=>{await request.post('/__test/reset');});

test('chapter menu consolidates the investigation in the Chapter 1 resume card',async({page})=>{
  await open(page);
  await page.locator('[data-exit]').click();
  await expect(page.getByText('Ch.1: Phishing & Social Engineering',{exact:false})).toBeVisible();
  await expect(page.getByText('Ch.2: Vishing Attack',{exact:false})).toBeVisible();
  await expect(page.getByRole('button',{name:'Open SOC investigation',exact:true})).toHaveCount(0);
  await expect(page.locator('.soc-launch')).toHaveCount(0);
  await page.getByRole('button',{name:'Resume Chapter 1',exact:true}).click();
  await expect(page.getByRole('heading',{name:'🎣 NexaCorp: The payroll lure'})).toBeVisible();
  expect(await page.evaluate(()=>({chapter:ST.chapIdx,mission:ST.chalIdx,types:GD[0].challenges.map(m=>m.type)}))).toEqual({
    chapter:0,mission:3,types:['email_spot','classify','mcq','soc_investigation']
  });
});

test('investigation tasks remain visible beside tools and distinguish drafts from assessment',async({page})=>{
  await open(page);
  const tasks=page.getByRole('complementary',{name:'Investigation tasks',exact:true});
  await expect(tasks).toBeVisible();
  await expect(tasks.getByText('Inspect the message and attachment',{exact:true})).toBeVisible();
  await expect(tasks.getByText('Choose proportionate containment',{exact:true})).toBeVisible();
  await tab(page,'email');
  await page.getByLabel('Cite MAIL-01 in report').check();
  await tab(page,'logs');
  await expect(tasks).toBeVisible();
  await expect(tasks.getByText('Inspect the message and attachment',{exact:true})).toBeVisible();
  // Evidence collection is a draft activity; it must not claim server correctness.
  await expect(tasks.locator('[data-state="draft"]')).not.toHaveCount(0);
  await expect(tasks.locator('[data-state="assessed"]')).toHaveCount(0);
  await page.screenshot({path:test.info().outputPath('lab-workspace-desktop.png'),fullPage:true});
});

test('event inspector supports correlation, evidence collection and checkpointed selection',async({page})=>{
  await open(page);await tab(page,'logs');
  await page.locator('[data-inspect="AUTH-02"]').click();
  const inspector=page.getByRole('complementary',{name:'Event inspector',exact:true});
  await expect(inspector).toContainText('AUTH-02');
  await expect(inspector).toContainText('198.51.100.77');
  await inspector.locator('[data-pivot-user="alex"]').click();
  await expect(page.getByLabel('Literal search')).toHaveValue('alex');
  await expect(inspector).toContainText('AUTH-02');
  await inspector.locator('[data-inspector-cite]').click();
  await expect(page.getByLabel('Cite AUTH-02',{exact:true})).toBeChecked();
  await inspector.locator('[data-inspector-timeline]').click();
  await saved(page);
  await page.setViewportSize({width:1440,height:1000});
  await page.screenshot({path:test.info().outputPath('lab-workspace-desktop.png'),fullPage:false});
  await page.reload();await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(page.getByRole('complementary',{name:'Event inspector',exact:true})).toContainText('AUTH-02');
  await expect(page.getByLabel('Literal search')).toHaveValue('alex');
  await expect(page.getByLabel('Cite AUTH-02',{exact:true})).toBeChecked();
  await tab(page,'timeline');
  await expect(page.locator('.soc-panel')).toContainText('AUTH-02');
});

test('guided report sections retain findings while tools and notes remain accessible',async({page})=>{
  await open(page);await tab(page,'report');
  await page.locator('[data-report-section="classification"]').click();
  await page.getByLabel('Incident classification').selectOption('credential-phishing');
  await page.locator('[data-report-section="scope"]').click();
  await page.getByLabel('Confirmed affected username').fill('alex');
  await page.getByLabel('Endpoint used for credential submission').fill('NC-WS-014');
  await page.getByLabel('Analyst notes (private to your account)').fill('Scope must distinguish a blocked visit from credential submission.');
  await tab(page,'email');
  await expect(page.getByRole('complementary',{name:'Investigation tasks',exact:true})).toBeVisible();
  await tab(page,'report');
  await expect(page.getByLabel('Incident classification')).toHaveValue('credential-phishing');
  await expect(page.getByLabel('Confirmed affected username')).toHaveValue('alex');
  await expect(page.getByLabel('Endpoint used for credential submission')).toHaveValue('NC-WS-014');
  await expect(page.getByLabel('Analyst notes (private to your account)')).toHaveValue('Scope must distinguish a blocked visit from credential submission.');
  await saved(page);
});

test('observable collection deduplicates indicators and saves them as unassessed draft findings',async({page})=>{
  await open(page);await tab(page,'email');
  // The lure and sender are observable evidence, not automatic assertions of compromise.
  await page.locator('[data-collect="payroll-review.example"]').click();
  await page.locator('[data-collect="nexac0rp.example"]').click();
  await expect(page.locator('[data-collect="payroll-review.example"]')).toBeDisabled();
  const casebook=page.getByRole('complementary',{name:'Analyst casebook',exact:true});
  await expect(casebook.locator('.soc-indicator-list')).toContainText('payroll-review.example');
  await expect(casebook.locator('.soc-indicator-list')).toContainText('nexac0rp.example');
  await tab(page,'logs');await page.locator('[data-inspect="DNS-01"]').click();
  await page.getByRole('complementary',{name:'Event inspector',exact:true}).locator('[data-collect="203.0.113.44"]').click();
  await expect(casebook.locator('.soc-indicator-list')).toContainText('203.0.113.44');
  await tab(page,'report');
  const indicators=page.getByLabel('Indicators (one per line; domain and relevant IP addresses)');
  expect((await indicators.inputValue()).split('\n')).toEqual(['payroll-review.example','nexac0rp.example','203.0.113.44']);
  await expect(page.getByRole('complementary',{name:'Investigation tasks',exact:true}).locator('[data-state="assessed"]')).toHaveCount(0);
  await saved(page);await page.reload();
  await page.getByRole('button',{name:'CONTINUE WHERE I LEFT OFF'}).click();
  await expect(indicators).toHaveValue('payroll-review.example\nnexac0rp.example\n203.0.113.44');
});

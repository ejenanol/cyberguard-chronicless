// Test-only findings. Never imported by a browser asset or a production handler.
const consoleEvidence=['MAIL-01','DNS-01','PROXY-01','PROXY-02','AUTH-02','AUTH-03','EDR-01','EDR-05'];
const decisions=[
  ['path-lure','confirmed',['MAIL-01','DNS-01'],'The message destination resolves in DNS; these records connect the lure to its domain.'],
  ['path-submit','confirmed',['PROXY-01','PROXY-02'],'The same browser visits the form and submits credential fields; values remain redacted.'],
  ['path-signin','confirmed',['PROXY-02','AUTH-02'],'Credential submission precedes the unfamiliar successful sign-in and the user denies approval.'],
  ['path-mailbox','confirmed',['AUTH-02','AUTH-03'],'The new identity session is subsequently used to access the payroll mailbox.'],
  ['path-execution','rejected',['EDR-01','EDR-05'],'The legitimate browser is observed, but the endpoint event records no executable payload or child process.']
];
function passingConsole(stage='respond'){
  return {version:1,stage,query:'SecurityEvents | take 20',lastQuery:'',selectedEntity:null,selectedRelationship:null,
    selectedProcess:'PROC-02',expandedProcesses:['PROC-01'],inspectedProcesses:['PROC-02'],entityNotes:[],
    relationships:decisions.map(([id,status,evidence,note])=>({id,status,evidence:[...evidence],note}))};
}
async function investigateConsole(page){
  await page.locator('[data-tab="attack"]').click();
  for(const [id,status,evidence,note] of decisions){
    await page.locator(`[data-console-relation="${id}"]`).click();
    await page.getByLabel('Relationship finding',{exact:true}).selectOption(status);
    for(const evidenceId of evidence)await page.getByLabel(`Use ${evidenceId} for this relationship`,{exact:true}).check();
    await page.getByLabel('Relationship rationale',{exact:true}).fill(note);
  }
  await page.locator('[data-tab="processes"]').click();
  const parent=page.locator('[data-console-expand="PROC-01"]');
  if(await parent.getAttribute('aria-expanded')!=='true')await parent.click();
  await page.locator('[data-console-process="PROC-02"]').click();
  await page.locator('[data-tab="report"]').click();
}
module.exports={consoleEvidence,decisions,passingConsole,investigateConsole};

/* The browser receives evidence and assessment results, never the grading rules. */
(function () {
  'use strict';
  const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const clone = value => JSON.parse(JSON.stringify(value));
  const tabs = ['overview','briefing','email','logs','graph','attack','processes','queries','timeline','terminal','report'];
  const title = value => value[0].toUpperCase()+value.slice(1);
  let active;
  const panelStage = panel => ['report'].includes(panel)?'respond':['attack','timeline'].includes(panel)?'reconstruct':['logs','graph','processes','queries','terminal'].includes(panel)?'investigate':'triage';
  function normalizeState(state) {
    const normalized={...emptyState(),...state,report:{...emptyState().report,...state?.report}};
    const defaults={version:1,stage:panelStage(normalized.panel),query:'SecurityEvents | take 20',lastQuery:'',selectedEntity:null,selectedRelationship:null,selectedProcess:null,expandedProcesses:[],inspectedProcesses:[],relationships:[],entityNotes:[]};
    normalized.console={...defaults,...state?.console};
    return normalized;
  }
  // JSONB can reorder object keys; ordering is not an analyst edit.
  function equalState(a,b) {
    const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
    return JSON.stringify(stable(a))===JSON.stringify(stable(b));
  }
  async function request(client,body,expectedUser) {
    const {data:{session}} = await client.auth.getSession();
    if(!session?.access_token) throw new Error('Sign in again to save the investigation.');
    if(expectedUser&&session.user?.id!==expectedUser)throw new Error('The signed-in agent changed. Reopen the investigation for your current account.');
    const response = await fetch('/api/soc',{
      method:body?'POST':'GET', signal:AbortSignal.timeout(10000), headers:{Authorization:`Bearer ${session.access_token}`,...(body?{'Content-Type':'application/json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{})
    });
    const data = await response.json();
    if(!response.ok) throw Object.assign(new Error(data.error || 'Investigation request failed.'),{status:response.status,record:data.record});
    return data;
  }
  function summary(record) {
    return {reward_xp:record.reward_xp||0,chapter_completed_at:record.chapter_completed_at||null,
      started:record.revision>0,panel:record.state?.panel||'briefing'};
  }
  function notify(s) {
    // Only cloud records establish the completion/reward projection in the game.
    s.options.onStatus?.(summary(s.record));
    s.options.onReward(s.record.reward_xp||0);
  }
  function releaseWaiters(s) {
    s.saving=false;
    for(const resolve of s.waiters||[]) resolve();s.waiters=[];
    const submitButton=s.root?.querySelector('[data-submit]');if(submitButton) submitButton.disabled=!!s.conflict;
    const completeButton=s.root?.querySelector('[data-complete]');if(completeButton) completeButton.disabled=!!s.conflict;
  }
  function search(scenario,query='',source='all') {
    const q=query.toLowerCase();
    return scenario.logs.filter(row=>(source==='all'||row.source===source) && Object.values(row).join(' ').toLowerCase().includes(q));
  }
  // No eval, shell, network tools or command interpolation. Output is plain text.
  function terminal(scenario,line) {
    const input=String(line).trim();
    if(/[;&|`$<>\r\n]/.test(input)) return 'Command not allowed. Type help. Input is never executed.';
    if(input==='help') return 'Simulated commands only:\nhelp\nemail\nlogs [auth|dns|proxy|endpoint|all] [literal search]\nshow <evidence-id>\nNo commands execute on a host. Use the timeline and report panels to record findings.';
    if(input==='email') return JSON.stringify(scenario.email,null,2);
    const show=/^show ([A-Z]+-\d{2})$/.exec(input);
    if(show) {const item=show[1]===scenario.email.id?scenario.email:scenario.logs.find(row=>row.id===show[1]);return item?JSON.stringify(item,null,2):'Evidence ID not found.';}
    const logs=/^logs(?: (all|auth|dns|proxy|endpoint))?(?: ([^\r\n]{1,120}))?$/.exec(input);
    if(logs) return search(scenario,logs[2]||'',logs[1]||'all').map(row=>`${row.id} ${row.time} ${row.user} ${row.host} ${row.detail}`).join('\n') || 'No matching synthetic events.';
    return 'Command not allowed. Type help. Input is never executed.';
  }
  function localRead(key) {try {return JSON.parse(localStorage.getItem(key)||'null');} catch {return null;}}
  function status(s,message) {
    s.status=message;
    const node=s.root?.querySelector('[data-status]');if(node) node.textContent=message;
    const retry=s.root?.querySelector('[data-retry]');if(retry) retry.hidden=!/pending|failed|local only|offline/i.test(message) || !!s.conflict;
  }
  function tabId() {
    try {let id=sessionStorage.getItem('cyberguard-soc-tab');if(!id){id=crypto.randomUUID();sessionStorage.setItem('cyberguard-soc-tab',id);}return id;}
    catch {return 'shared';}
  }
  function persistLocal(s,broadcast=true) {
    try {
      const snapshot=JSON.stringify({revision:s.revision,state:s.state,pending:s.dirty,inflight:s.pending||null,completion:s.completionRequest||null,scenario:s.scenario,record:s.record,origin:s.tab});
      localStorage.setItem(s.key,snapshot);
      if(broadcast)localStorage.setItem(s.baseKey,snapshot);
      return true;
    }
    catch {status(s,'Local storage failed; keep this tab open and retry cloud sync.');return false;}
  }
  function change(s,redraw=false) {
    s.generation++;s.dirty=true;
    if(persistLocal(s)) status(s,s.conflict?'Conflict: local draft retained; choose which version to keep.':'Saved on this device; cloud sync pending');
    clearTimeout(s.timer);s.timer=setTimeout(()=>flush(s),600);
    if(redraw) draw(s);
  }
  async function flush(s,submit=false) {
    clearTimeout(s.timer);
    if(s.saving) {
      if(submit) {await new Promise(resolve=>(s.waiters ||= []).push(resolve));return flush(s,true);}
      return false;
    }
    if(submit && s.pending?.action==='save') {if(!await flush(s)) return false;}
    if(s.conflict || (!s.dirty && !submit && !s.pending)) return false;
    s.saving=true;status(s,submit?'Assessing and saving…':'Saving to cloud…');
    // Keep the exact request after an uncertain network failure. A submit receipt
    // makes retries safe even if the database committed before the response failed.
    const body=s.pending || {action:submit?'submit':'save',revision:s.revision,requestId:crypto.randomUUID(),state:clone(s.state)};
    s.pending=body;persistLocal(s);
    try {
      const {record}=await request(s.client,body,s.user);
      s.revision=record.revision;s.record=record;s.pending=null;s.needsRefresh=false;
      s.dirty=!equalState(s.state,body.state);
      if(!s.dirty) s.state=normalizeState(clone(record.state));
      notify(s);
      persistLocal(s);
      status(s,(s.dirty?'Saved on this device; cloud sync pending':'Saved to cloud')+(s.completionRequest?'; Chapter 1 completion pending':''));
      if(body.action==='submit') {draw(s);}
      return true;
    } catch(error) {
      if(error.status===409) {
        s.pending=null;s.conflict={record:error.record};
        status(s,'Conflict: local draft retained; choose which version to keep.');draw(s);
      } else {
        // Validation and throttling are definitive failures; network/503 are uncertain.
        if(error.status && error.status!==503) s.pending=null;
        status(s,`${error.message} Cloud sync failed; local draft retained.`);persistLocal(s);
      }
      return false;
    } finally {
      releaseWaiters(s);
      if(s.dirty && !s.pending && !s.conflict && /^(Saved)/.test(s.status)) s.timer=setTimeout(()=>flush(s),600);
    }
  }
  async function completeChapter(s) {
    clearTimeout(s.timer);
    if(s.saving) {await new Promise(resolve=>(s.waiters ||= []).push(resolve));return completeChapter(s);}
    if(s.conflict) return false;
    // Do not leave the chapter while notes or the final report still need syncing.
    if(s.pending||s.dirty) {
      if(!await flush(s)) return false;
      if(s.pending||s.dirty) return completeChapter(s);
    }
    s.saving=true;
    s.completionRequest ||= {action:'complete',revision:s.revision,requestId:crypto.randomUUID()};
    // An acknowledged note save may advance our revision after a failed attempt.
    // Completion receipts are monotonic, so updating it preserves idempotence.
    s.completionRequest.revision=s.revision;
    persistLocal(s);status(s,'Recording Chapter 1 completion…');
    const button=s.root?.querySelector('[data-complete]');if(button) button.disabled=true;
    try {
      const {record}=await request(s.client,s.completionRequest,s.user);
      if(!record?.chapter_completed_at) throw new Error('The server did not confirm chapter completion.');
      s.record=record;s.revision=record.revision;s.completionRequest=null;s.needsRefresh=false;
      // A learner may have edited a note while completion was in flight. Keep it.
      s.dirty=!equalState(s.state,record.state);
      notify(s);persistLocal(s);
      status(s,s.dirty?'Chapter completed; cloud sync pending for your latest notes.':'Chapter 1 completion saved');
      s.options.onComplete(record);
      return true;
    } catch(error) {
      if(error.status===409) {
        s.completionRequest=null;s.conflict={record:error.record};
        status(s,'Conflict: local draft retained; choose which version to keep before completing the chapter.');draw(s);
      } else {
        if(error.status&&error.status!==503) s.completionRequest=null;
        status(s,`Chapter completion failed: ${error.message} Your investigation is retained; retry when connected.`);
        persistLocal(s);
      }
      return false;
    } finally {
      releaseWaiters(s);
      if(s.dirty&&!s.pending&&!s.conflict&&/^(Chapter completed)/.test(s.status))s.timer=setTimeout(()=>flush(s),600);
    }
  }
  async function retrySync(s) {
    if(s.completionRequest)return completeChapter(s);
    if(s.dirty||s.pending)return flush(s);
    // A clean cached draft still needs a real read after an offline refresh.
    // Retrying must not require the learner to edit data just to reconnect.
    if(s.saving){await new Promise(resolve=>(s.waiters ||= []).push(resolve));return retrySync(s);}
    if(s.conflict)return false;
    s.saving=true;status(s,'Checking cloud save…');
    try {
      const {record,scenario}=await request(s.client,undefined,s.user);
      if(s.dirty){s.needsRefresh=true;return false;}
      s.scenario=scenario;s.record=record;s.revision=record.revision;s.state=normalizeState(clone(record.state));s.needsRefresh=false;
      notify(s);persistLocal(s);status(s,'Loaded cloud save');draw(s);return true;
    }catch(error){s.needsRefresh=true;status(s,`${error.message} Cloud reconnect failed; local draft retained.`);return false;}
    finally{releaseWaiters(s);if(s.dirty&&!s.conflict)s.timer=setTimeout(()=>flush(s),600);}
  }
  function field(label,control) {
    const id='soc-field-'+label.toLowerCase().replace(/[^a-z0-9]+/g,'-');
    return `<div class="soc-field"><label for="${id}">${esc(label)}</label>${control.replace(/^(<\w+)/,`$1 id="${id}"`)}</div>`;
  }
  function checkbox(id,label,checked,kind) {return `<label class="soc-check"><input type="checkbox" data-${kind}="${esc(id)}" ${checked?'checked':''}> ${esc(label)}</label>`;}
  function indicatorTokens(value) {
    return [...new Set(String(value).match(/\b(?:[a-z0-9][a-z0-9-]*\.)+example\b|\b(?:\d{1,3}\.){3}\d{1,3}\b/gi)||[])];
  }
  function indicatorActions(s,value) {
    const collected=s.state.report.iocs.toLowerCase().split(/[\s,;]+/);
    return indicatorTokens(value).map(token=>`<button class="soc-pivot" data-collect="${esc(token)}" ${collected.includes(token.toLowerCase())?'disabled':''}>${collected.includes(token.toLowerCase())?'✓ Collected':'＋ Collect'} ${esc(token)}</button>`).join('');
  }
  function evidenceActions(s,id,inspector=false) {
    const cited=s.state.report.evidence.includes(id),onTimeline=s.state.timeline.includes(id);
    return `<div class="soc-evidence-actions">${inspector?`<button data-inspector-cite="${esc(id)}" aria-pressed="${cited}">${cited?'Remove citation':'Cite evidence'}</button>`:checkbox(id,'Cite '+id+' in report',cited,'evidence')}<button ${inspector?'data-inspector-timeline':'data-add'}="${esc(id)}" ${onTimeline?'disabled':''}>${onTimeline?'✓ On timeline':id==='MAIL-01'?'Add email to timeline':'Add to timeline'}</button></div>`;
  }
  function emailView(s) {
    const e=s.scenario.email;
    return `<div class="soc-panel-heading"><div><span class="soc-room-badge">INBOX / ${esc(e.id)}</span><h3>Email evidence · ${esc(e.id)}</h3></div><span>${esc(e.time.slice(11,19))} UTC</span></div>
      <article class="soc-mail-card"><div class="soc-mail-header"><span class="soc-mail-avatar" aria-hidden="true">P</span><div><h4>${esc(e.subject)}</h4><dl><dt>From</dt><dd>${esc(e.from)}</dd><dt>To</dt><dd>${esc(e.to.join(', '))}</dd></dl></div></div><div class="soc-mail-body">${esc(e.body)}</div></article>
      <details class="soc-attachment" open><summary>Full message headers</summary><pre>${esc(e.headers)}</pre></details>
      <section class="soc-attachment"><h4>Attachment analysis · inert preview</h4><dl class="soc-attachment-grid"><div><dt>File</dt><dd>${esc(e.attachment.name)}</dd></div><div><dt>Type</dt><dd>${esc(e.attachment.mime)}</dd></div><div><dt>Size</dt><dd>${esc(e.attachment.size)}</dd></div></dl><p class="soc-inline-code">SHA-256 ${esc(e.attachment.sha256)}</p><p>${esc(e.attachment.preview)}</p></section>
      <section><h4>Collect observable indicators</h4><p>Record an observable first; decide what it means after correlating the logs. Benign indicators may appear too.</p>${indicatorActions(s,e.from+' '+e.headers+' '+e.body+' '+e.attachment.preview)}</section>
      ${evidenceActions(s,e.id)}<p class="soc-safety-note">Evidence is inert. Links and attachments cannot open a real target.</p>`;
  }
  function logsView(s) {
    const rows=search(s.scenario,s.state.query,s.state.source);
    const selected=s.scenario.logs.find(row=>row.id===s.state.selectedEvidence);
    return `<div class="soc-panel-heading"><div><span class="soc-room-badge">EVENT EXPLORER</span><h3>Simulated SIEM · ${rows.length} events</h3></div><span>UTC · ${s.scenario.logs.length} available</span></div>
      <div class="soc-source-filters" aria-label="Log source shortcuts">${['all','auth','dns','proxy','endpoint'].map(source=>`<button data-source="${source}" aria-pressed="${s.state.source===source}">${source==='all'?'All events':title(source)} <span>${s.scenario.logs.filter(r=>source==='all'||r.source===source).length}</span></button>`).join('')}</div>
      <div class="soc-filters">${field('Literal search',`<input data-field="query" maxlength="120" value="${esc(s.state.query)}" placeholder="Search an identity, host, domain or event ID">`)}${field('Source',`<select data-field="source">${['all','auth','dns','proxy','endpoint'].map(v=>`<option ${s.state.source===v?'selected':''}>${v}</option>`).join('')}</select>`)}<button data-search>Search</button><button data-clear-search>Clear</button></div>
      <div class="soc-log-layout"><div class="soc-scroll"><table><caption>Select an event to inspect it, then pivot between related evidence.</caption><thead><tr><th scope="col">Event / time</th><th scope="col">Identity / host</th><th scope="col">Evidence</th><th scope="col">Record</th></tr></thead><tbody>${rows.map(row=>`<tr ${row.id===selected?.id?'class="soc-event-selected"':''}><td><button class="soc-event-id" data-inspect="${esc(row.id)}" aria-pressed="${row.id===selected?.id}">${esc(row.id)}</button><time>${esc(row.time.slice(11,19))}</time><span class="soc-log-source">${esc(row.source)}</span></td><td><button class="soc-pivot" data-pivot-user="${esc(row.user)}" aria-label="Search all sources for ${esc(row.user)}">${esc(row.user)}</button><br><span>${esc(row.host)}</span></td><td>${esc(row.detail)}</td><td>${checkbox(row.id,'Cite '+row.id,s.state.report.evidence.includes(row.id),'evidence')}<button data-add="${row.id}" ${s.state.timeline.includes(row.id)?'disabled':''}>${s.state.timeline.includes(row.id)?'✓ On timeline':'Add to timeline'}</button></td></tr>`).join('')}</tbody></table>${!rows.length?'<div class="soc-empty-state"><h4>No matching events</h4><p>Try a broader search or another source. Search matches literal text.</p></div>':''}</div>
      <aside class="soc-inspector" aria-label="Event inspector">${selected?`<span class="soc-room-badge">SELECTED EVIDENCE</span><h4>${esc(selected.id)}</h4><dl><dt>Time</dt><dd>${esc(selected.time)}</dd><dt>Source</dt><dd>${esc(selected.source)}</dd><dt>User</dt><dd>${esc(selected.user)}</dd><dt>Host</dt><dd>${esc(selected.host)}</dd></dl><p>${esc(selected.detail)}</p><h4>Follow this entity</h4><div class="soc-evidence-actions"><button data-pivot-user="${esc(selected.user)}">Search user ${esc(selected.user)}</button><button data-pivot-host="${esc(selected.host)}">Search host ${esc(selected.host)}</button></div><h4>Record your evidence</h4>${evidenceActions(s,selected.id,true)}<h4>Observable indicators</h4>${indicatorActions(s,selected.detail)||'<p>No domain or IP is recorded in this event.</p>'}`:'<div class="soc-inspector-empty"><span aria-hidden="true">⌕</span><h4>Inspect an event</h4><p>Select an event ID to open its raw details, follow the user or host, collect indicators, and build your case.</p></div>'}</aside></div>`;
  }
  function timelineView(s) {
    return `<div class="soc-panel-heading"><div><span class="soc-room-badge">CASE RECONSTRUCTION</span><h3>Your incident timeline</h3></div><span>${s.state.timeline.length} recorded events</span></div><p>Order evidence chronologically. Adding evidence does not imply it proves compromise.</p>${s.state.timeline.length?`<ol class="soc-timeline">${s.state.timeline.map((id,i)=>{const row=id==='MAIL-01'?s.scenario.email:s.scenario.logs.find(r=>r.id===id);return `<li><time>${esc(row?.time.slice(11,19))} UTC</time><div><strong>${esc(id)}</strong><p>${esc(row?.detail || row?.subject)}</p><div class="soc-evidence-actions"><button aria-label="Move ${esc(id)} earlier" data-up="${i}" ${i===0?'disabled':''}>↑ Earlier</button><button aria-label="Move ${esc(id)} later" data-down="${i}" ${i===s.state.timeline.length-1?'disabled':''}>↓ Later</button><button data-remove="${esc(id)}">Remove ${esc(id)}</button></div></div></li>`;}).join('')}</ol>`:'<div class="soc-empty-state"><h4>Your timeline starts with evidence</h4><p>Use “Add to timeline” in Email or Logs. Compare what happened before and after each important event.</p><button data-go="logs">Investigate events</button></div>'}`;
  }
  function queryView(s) {
    const engine=window.CyberSOCQuery;
    let result=null,error='';
    if(s.state.console.lastQuery&&engine) {
      try {result=engine.run(s.scenario,s.state.console.lastQuery);}catch(e){error=e.message;}
    }
    return `<div class="soc-panel-heading"><div><span class="soc-room-badge">SYNTHETIC DATA EXPLORER</span><h3>KQL-style query editor</h3></div><span>Local dataset only · 100-row limit</span></div>
      <p>A documented training subset inspired by KQL. This is not Microsoft Sentinel or a connection to a live service. Simple literal search remains available in SIEM events.</p>
      <div class="soc-query-examples" aria-label="Beginner query examples">${(engine?.examples||[]).map((example,i)=>`<button type="button" data-query-example="${i}">${esc(example.label)}</button>`).join('')}</div>
      <form data-query-form>${field('KQL-style query',`<textarea data-query-editor maxlength="2000" rows="4" spellcheck="false">${esc(s.state.console.query)}</textarea>`)}<button class="soc-primary" type="submit">Run query</button></form>
      <details class="soc-query-help"><summary>Supported syntax and limitations</summary><pre>${esc(engine?.help||'The query engine is unavailable. Reload the current application assets.')}</pre></details>
      ${error?`<div class="soc-query-error" role="alert"><h4>Query needs attention</h4><p>${esc(error)}</p><p>Try an example or inspect the supported syntax. No query was executed on an external system.</p></div>`:result?`<section aria-label="Query output"><p class="soc-query-count" role="status">${result.rows.length} of ${result.total} matching rows${result.limited?' · output capped at 100':''}. Include id in projected columns to pivot to evidence.</p><div class="soc-scroll"><table><caption>Synthetic query results</caption><thead><tr>${result.columns.map(column=>`<th scope="col">${esc(column)}</th>`).join('')}</tr></thead><tbody>${result.rows.map(row=>`<tr>${result.columns.map(column=>`<td>${column==='id'&&evidenceById(s,row[column])?`<button data-query-evidence="${esc(row[column])}">${esc(row[column])}</button>`:esc(row[column])}</td>`).join('')}</tr>`).join('')}</tbody></table>${!result.rows.length?'<p class="soc-empty-state">No matching synthetic events. Broaden the filter or try another table.</p>':''}</div></section>`:'<p class="soc-empty-state">Choose an example or write a query, then select Run query. Queries never award XP.</p>'}`;
  }
  function evidenceById(s,id) {return id===s.scenario.email.id?s.scenario.email:s.scenario.logs.find(row=>row.id===id);}
  function reportView(s) {
    const r=s.state.report;
    const select=(name,options)=>`<select data-report="${name}"><option value="">Choose…</option>${options.map(([value,label])=>`<option value="${value}" ${r[name]===value?'selected':''}>${esc(label)}</option>`).join('')}</select>`;
    return `<h3>Incident report</h3><p>Findings are assessed by the server. Separate confirmed facts from uncertainty. Passing requires accurate scope, correlated evidence, severity and safe containment.</p>
      <nav class="soc-finding-sections" aria-label="Report sections"><button data-report-section="classification">Classify</button><button data-report-section="scope">Scope</button><button data-report-section="indicators">Indicators</button><button data-report-section="response">Response</button></nav>
      <section id="soc-report-classification"><h4>01 / Classify the incident</h4>
      ${field('Incident classification',select('classification',[['credential-phishing','Credential phishing / account takeover'],['malware','Endpoint malware'],['benign','Benign routine message']]))}
      ${field('Severity',select('severity',[['low','Low'],['medium','Medium'],['high','High'],['critical','Critical']]))}
      </section><section id="soc-report-scope"><h4>02 / Establish the affected scope</h4><p>Distinguish a recipient, a blocked visit and confirmed unauthorized access.</p>
      ${field('Confirmed affected username',`<input data-report="user" maxlength="60" value="${esc(r.user)}">`)}
      ${field('Endpoint used for credential submission',`<input data-report="endpoint" maxlength="60" value="${esc(r.endpoint)}">`)}
      </section><section id="soc-report-indicators"><h4>03 / Document your indicators</h4>
      ${field('Indicators (one per line; domain and relevant IP addresses)',`<textarea data-report="iocs" maxlength="1200">${esc(r.iocs)}</textarea>`)}
      </section><section id="soc-report-response"><h4>04 / Recommend a response</h4>
      <fieldset><legend>Recommended containment (simulated only)</legend>${s.scenario.actions.map(a=>checkbox(a.id,a.label,r.containment.includes(a.id),'containment')).join('')}</fieldset>
      <p>Cited evidence: ${esc(r.evidence.join(', ')||'None — use Email and Logs to cite records.')}</p>
      ${field('Analyst summary — evidence IDs, impact, scope, uncertainty and response',`<textarea data-report="summary" maxlength="4000" rows="6">${esc(r.summary)}</textarea>`)}
      </section><button class="soc-primary" data-submit ${s.conflict?'disabled':''}>Submit for assessment</button><p>First successful assessment awards 150 XP once. Replays and retries never duplicate it.</p>`;
  }
  function assessment(s) {
    const r=s.record.result;if(!r) return '';
    return `<section class="soc-assessment" aria-label="Last server assessment"><h3>Last server assessment · ${esc(r.score)}/100 · ${r.passed?'Passed':'Keep investigating'}</h3><p>This assesses the last submitted report; subsequent draft edits need a new submission.</p><ul>${r.checks.map(c=>`<li>${c.ok?'✓':'○'} ${esc(c.objective)} (${esc(c.ok?c.points:0)}/${esc(c.points)}) — ${esc(c.explanation)}</li>`).join('')}</ul><p>${esc(r.debrief)}</p><p>Chapter 1 reward ledger: ${esc(s.record.reward_xp)} XP total; awarded at most once.</p>${!r.passed&&s.record.reward_xp===150?'<p>A previous server-passed investigation still qualifies your chapter completion. This replay does not remove it.</p>':''}${s.record.reward_xp===150||s.record.chapter_completed_at?`<button data-complete ${s.conflict?'disabled':''}>Complete Chapter 1</button>`:''}</section>`;
  }
  function draftSignals(s) {
    const r=s.state.report;
    return [s.state.inspected.includes('MAIL-01'),!!r.classification,!!(r.user&&r.endpoint),r.evidence.some(id=>id!=='MAIL-01'),s.state.timeline.length>0,!!r.iocs.trim(),r.containment.length>0,!!r.summary.trim(),s.state.console.relationships.some(row=>row.status!=='hypothesis'),s.state.console.inspectedProcesses.length>0];
  }
  function taskRail(s) {
    const tasks=[{panel:'overview',number:'00',title:'Review the incident overview',copy:'Maya’s alert, entities and activity'},
      {panel:'email',number:'01',title:'Triage the message',copy:'Sender, authentication, links and attachment'},
      {panel:'logs',number:'02',title:'Investigate the event trail',copy:'Correlate sources; follow identities and hosts'},
      {panel:'graph',number:'02a',title:'Connect the entities',copy:'Discover relationships; record your hypotheses'},
      {panel:'processes',number:'02b',title:'Inspect endpoint processes',copy:'Check parent-child and network evidence'},
      {panel:'attack',number:'03',title:'Establish the attack path',copy:'Support or reject links using cited evidence'},
      {panel:'timeline',number:'03a',title:'Reconstruct the incident',copy:'Order events and capture observables'},
      {panel:'report',number:'04',title:'Contain and report',copy:'Document scope, severity and your response'}];
    const signals=draftSignals(s),last=s.record.result;
    return `<aside class="soc-task-rail" aria-label="Investigation tasks"><div class="soc-task-heading"><span class="soc-room-badge">YOUR MISSION</span><h3>Investigation tasks</h3><p>Keep your case in view while you work.</p></div><div class="soc-task-list">${tasks.map(task=>`<button class="soc-task" data-go="${task.panel}" aria-current="${s.state.panel===task.panel?'step':'false'}"><span class="soc-task-number">${task.number}</span><span class="soc-task-copy"><strong>${esc(task.title)}</strong><small>${esc(task.copy)}</small></span></button>`).join('')}</div>
      <section class="soc-objectives"><h4>Objective tracker</h4><p>Draft activity is not a verified answer.</p><ol class="soc-objective-list">${s.scenario.objectives.map((objective,i)=>{const passed=last?.checks[i]?.ok;return `<li data-state="${passed?'assessed':signals[i]?'draft':'pending'}"><span aria-hidden="true">${passed?'✓':signals[i]?'◐':'○'}</span><div><span class="soc-objective-title">${esc(objective)}</span><small class="soc-objective-status" data-state="${passed?'assessed':signals[i]?'draft':'pending'}">${passed?'Passed in last assessment':signals[i]?'Draft recorded':'Not started'}</small></div></li>`;}).join('')}</ol><p class="soc-toolbar-summary">${last?`${esc(last.objectives.length)}/${s.scenario.objectives.length} passed in your last assessment (v${esc(last.assessment_version||1)}).`:'No report assessed yet.'}</p></section>
      <section class="soc-mentor"><span class="soc-room-badge">MENTOR / MAYA CHEN</span><p>${esc(s.scenario.hints[Math.min(s.state.hint,s.scenario.hints.length)-1]||'Follow the evidence. A message received, a link visited and an account compromised are different findings.')}</p><button data-hint ${s.state.hint>=s.scenario.hints.length?'disabled':''}>Reveal next hint (${esc(s.state.hint)}/${s.scenario.hints.length})</button>${s.state.hint?`<details><summary>Revealed guidance</summary><ol>${s.scenario.hints.slice(0,s.state.hint).map(h=>`<li>${esc(h)}</li>`).join('')}</ol></details>`:''}</section></aside>`;
  }
  function notebook(s) {
    const r=s.state.report,tokens=r.iocs.split(/[\s,;]+/).filter(Boolean);
    return `<aside class="soc-notebook" aria-label="Analyst casebook"><div class="soc-notebook-heading"><span class="soc-room-badge">ANALYST CASEBOOK</span><h3>Build your case</h3><p>Your notes and findings stay with this account.</p></div>
      <section class="soc-case-board"><h4>Cited evidence <span>${r.evidence.length}</span></h4>${r.evidence.length?`<div class="soc-evidence-tray">${r.evidence.map(id=>`<button data-open-evidence="${esc(id)}">${esc(id)}</button>`).join('')}</div>`:'<p>Inspect a message or event and cite the evidence that supports your findings.</p>'}<h4>Timeline <span>${s.state.timeline.length}</span></h4><button data-go="timeline">Review incident timeline</button><h4>Collected indicators <span>${tokens.length}</span></h4>${tokens.length?`<ul class="soc-indicator-list">${tokens.map(token=>`<li>${esc(token)}</li>`).join('')}</ul>`:'<p>Collect observables from evidence; assess them in context.</p>'}</section>
      <section class="soc-findings-summary"><h4>Working findings</h4><dl><dt>Classification</dt><dd>${esc(r.classification||'Not recorded')}</dd><dt>Affected identity</dt><dd>${esc(r.user||'Not recorded')}</dd><dt>Endpoint</dt><dd>${esc(r.endpoint||'Not recorded')}</dd><dt>Severity</dt><dd>${esc(r.severity||'Not recorded')}</dd></dl><button data-go="report">Update report</button></section>
      ${field('Analyst notes (private to your account)',`<textarea data-field="notes" maxlength="8000" rows="8" placeholder="What happened? Which evidence supports it? What remains uncertain?">${esc(s.state.notes)}</textarea>`)}<p class="soc-safety-note">These are your draft findings. Only server assessment validates the report.</p></aside>`;
  }
  function briefingView(s) {
    const times=[s.scenario.email.time,...s.scenario.logs.map(row=>row.time)].sort();
    const windowLabel=times[0].slice(11,16)+'–'+times[times.length-1].slice(11,16)+' UTC';
    return `<div class="soc-panel-heading"><div><span class="soc-room-badge">INCIDENT NC-SOC-001</span><h3>Maya’s briefing</h3></div></div><section class="soc-alert-card"><span class="soc-room-badge">INCOMING ALERT</span><h4>Suspicious payroll message reported</h4><p>${esc(s.scenario.briefing)}</p><dl class="soc-attachment-grid"><div><dt>Evidence window</dt><dd>${esc(windowLabel)}</dd></div><div><dt>Recipients to investigate</dt><dd>${s.scenario.email.to.length} staff</dd></div><div><dt>Available evidence</dt><dd>1 message · ${s.scenario.logs.length} events</dd></div></dl></section><h4>Your investigation workflow</h4><p>Inspect the message, follow its observables through the event explorer, reconstruct what happened, and support your report with cited evidence. Keep notes of both suspicious and benign explanations.</p><ul><li>Email viewer: message headers and inert attachment analysis.</li><li>Event explorer: authentication, DNS, proxy and endpoint records.</li><li>Case timeline and notebook: your evidence and working theory.</li><li>Report: scope, severity, indicators and containment recommendations.</li></ul><div class="soc-task-actions"><button class="soc-primary" data-go="email">Begin email triage</button><button data-go="terminal">Open simulated terminal</button></div><p class="soc-safety-note">A browser-based simulation with synthetic data. No real machine, executable or external target is provisioned.</p>`;
  }
  function stageNavigation(s) {
    const stages=[['email','Triage'],['logs','Investigate'],['timeline','Reconstruct'],['report','Respond']];
    const panel={triage:'email',investigate:'logs',reconstruct:'timeline',respond:'report'}[s.state.console.stage]||'email';
    return `<nav class="soc-stage-nav soc-source-filters" aria-label="Investigation stages">${stages.map(([id,label],i)=>`${i?'<span aria-hidden="true">→</span>':''}<button data-stage="${id}" aria-pressed="${panel===id}">${esc(label)}</button>`).join('')}</nav>`;
  }
  function draw(s) {
    if(!s.root?.isConnected) return;
    const panel=s.state.panel,toolNames={overview:'Overview',briefing:'Briefing',email:'Email',logs:'SIEM events',graph:'Investigation graph',attack:'Attack path',processes:'Process tree',queries:'Queries',timeline:'Timeline',terminal:'Terminal',report:'Report'};
    s.root.innerHTML=`<section class="soc" aria-label="SOC phishing investigation"><header class="soc-room-header"><div><p class="soc-label">CYBERGUARD CHRONICLES / CHAPTER 1 / PHISHING &amp; SOCIAL ENGINEERING</p><h2>🎣 ${esc(s.scenario.title)}</h2><p>Synthetic training simulation inspired by Microsoft Sentinel. No live Microsoft integration.</p></div><div class="soc-room-meta"><span class="soc-room-badge">NEXACORP SOC</span><span>Chapter reward · 150 XP once</span><span>${esc(s.scenario.incident?.id||'NC-SOC-001')}</span></div></header>
      <div class="soc-status"><span data-status role="status" aria-live="polite">${esc(s.status)}</span><button data-retry hidden>Retry sync</button><span class="soc-case-strip">${s.state.report.evidence.length} citations · ${s.state.timeline.length} timeline events</span></div>
      ${s.conflict?'<div class="soc-conflict" role="alert"><p>Another tab or device changed this investigation. Your local draft is retained. Choose explicitly before editing or saving again.</p><button data-cloud>Use cloud version</button><button data-local>Keep my local draft over cloud</button></div>':''}
      ${stageNavigation(s)}<div class="soc-lab-grid">${taskRail(s)}<div class="soc-workbench"><nav class="soc-tool-nav" aria-label="Investigation tools">${tabs.map(t=>`<button data-tab="${t}" aria-pressed="${panel===t}">${toolNames[t]}</button>`).join('')}</nav><div class="soc-tool-body"><div class="soc-panel">${['overview','graph','attack','processes'].includes(panel)?window.CyberSOCConsole?.render(panel,s)||'<p>Reconnect and reload to access the new investigation views. Your existing evidence remains saved.</p>':panel==='queries'?queryView(s):panel==='briefing'?briefingView(s):panel==='email'?emailView(s):panel==='logs'?logsView(s):panel==='timeline'?timelineView(s):panel==='terminal'?`<div class="soc-terminal-header"><span class="soc-room-badge">READ-ONLY TOOL</span><h3>Constrained simulated terminal</h3><p>Query the same evidence set with documented commands. No host commands run.</p></div><div class="soc-terminal-body"><form data-terminal>${field('Command','<input name="command" maxlength="160" autocomplete="off" spellcheck="false" placeholder="help · email · logs auth alex · show AUTH-02">')}<button>Run simulated command</button></form><pre data-output tabindex="0">${esc(s.output||'CYBERGUARD / EVIDENCE CONSOLE\nType help to list the allowed commands.')}</pre></div>`:reportView(s)}${assessment(s)}</div>${notebook(s)}</div></div></div><footer class="soc-room-footer"><span>Drafts autosave. Server assessment verifies your findings.</span><button data-exit>Save draft and return to chapter menu</button></footer></section>`;
    bind(s);status(s,s.status);
  }
  function refreshContext(s) {
    const signals=draftSignals(s),last=s.record.result;
    s.root.querySelectorAll('.soc-objective-list li').forEach((item,i)=>{
      const passed=last?.checks[i]?.ok;item.dataset.state=passed?'assessed':signals[i]?'draft':'pending';
      const label=item.querySelector('.soc-objective-status');if(label){label.dataset.state=item.dataset.state;label.textContent=passed?'Passed in last assessment':signals[i]?'Draft recorded':'Not started';}
      item.firstElementChild.textContent=passed?'✓':signals[i]?'◐':'○';
    });
    const caseStrip=s.root.querySelector('.soc-case-strip');if(caseStrip)caseStrip.textContent=`${s.state.report.evidence.length} citations · ${s.state.timeline.length} timeline events`;
    const board=s.root.querySelector('.soc-case-board');
    if(board){const draft=document.createElement('div');draft.innerHTML=notebook(s);board.replaceWith(draft.querySelector('.soc-case-board'));}
    const summary=s.root.querySelector('.soc-findings-summary');
    if(summary){const values=[s.state.report.classification,s.state.report.user,s.state.report.endpoint,s.state.report.severity];summary.querySelectorAll('dd').forEach((el,i)=>el.textContent=values[i]||'Not recorded');}
    // Newly refreshed evidence chips use event delegation rather than rebinding all inputs.
  }
  function bind(s) {
    const root=s.root;
    const on=(selector,event,fn)=>root.querySelectorAll(selector).forEach(el=>el.addEventListener(event,()=>fn(el)));
    const markInspected=id=>{if(evidenceById(s,id)&&!s.state.inspected.includes(id))s.state.inspected.push(id);};
    const go=panel=>{s.state.panel=panel;s.state.console.stage=panelStage(panel);if(panel==='email')markInspected('MAIL-01');change(s,true);};
    const inspectEvidence=id=>{if(!evidenceById(s,id))return;markInspected(id);if(id!=='MAIL-01'){s.state.selectedEvidence=id;s.state.query='';s.state.source='all';}go(id==='MAIL-01'?'email':'logs');};
    const citeEvidence=id=>{if(!evidenceById(s,id))return;markInspected(id);if(!s.state.report.evidence.includes(id))s.state.report.evidence.push(id);change(s,true);};
    window.CyberSOCConsole?.bind(root,s,{change,go,inspectEvidence,citeEvidence});
    on('[data-tab]','click',el=>go(el.dataset.tab));
    on('[data-stage]','click',el=>go(el.dataset.stage));
    root.querySelectorAll('[data-go]').forEach(el=>{if(!el.closest('.soc-notebook'))el.addEventListener('click',()=>go(el.dataset.go));});
    on('[data-inspect]','click',el=>{s.state.selectedEvidence=el.dataset.inspect;markInspected(el.dataset.inspect);change(s,true);});
    on('[data-query-evidence]','click',el=>inspectEvidence(el.dataset.queryEvidence));
    on('[data-query-example]','click',el=>{const example=window.CyberSOCQuery?.examples[Number(el.dataset.queryExample)];if(!example)return;s.state.console.query=example.query;change(s,true);});
    on('[data-query-editor]','input',el=>{s.state.console.query=el.value;change(s);});
    root.querySelector('[data-query-form]')?.addEventListener('submit',event=>{event.preventDefault();s.state.console.lastQuery=s.state.console.query;change(s,true);});
    for(const kind of ['user','host'])on(`[data-pivot-${kind}]`,'click',el=>{s.state.query=el.dataset[kind==='user'?'pivotUser':'pivotHost'];s.state.source='all';change(s,true);});
    on('[data-source]','click',el=>{s.state.source=el.dataset.source;change(s,true);});
    on('[data-clear-search]','click',()=>{s.state.query='';s.state.source='all';change(s,true);});
    on('[data-collect]','click',el=>{const values=s.state.report.iocs.split(/[\s,;]+/).filter(Boolean);if(!values.includes(el.dataset.collect))values.push(el.dataset.collect);const next=values.join('\n');if(next.length>1200){status(s,'Indicator list is full. Edit the report before collecting more.');return;}s.state.report.iocs=next;change(s,true);});
    on('[data-inspector-cite]','click',el=>{const id=el.dataset.inspectorCite;const values=s.state.report.evidence;s.state.report.evidence=values.includes(id)?values.filter(value=>value!==id):[...values,id];if(!s.state.inspected.includes(id))s.state.inspected.push(id);change(s,true);});
    on('[data-inspector-timeline]','click',el=>{const id=el.dataset.inspectorTimeline;if(!s.state.timeline.includes(id))s.state.timeline.push(id);change(s,true);});
    root.querySelector('.soc-notebook')?.addEventListener('click',event=>{const el=event.target.closest('[data-open-evidence], [data-go]');if(!el)return;if(el.dataset.openEvidence){const id=el.dataset.openEvidence;if(id!=='MAIL-01')s.state.selectedEvidence=id;go(id==='MAIL-01'?'email':'logs');}else go(el.dataset.go);});
    on('[data-report-section]','click',el=>{const section=root.querySelector('#soc-report-'+el.dataset.reportSection);section?.scrollIntoView({block:'center',behavior:'smooth'});section?.querySelector('input,select,textarea')?.focus({preventScroll:true});});
    on('[data-field]','input',el=>{s.state[el.dataset.field]=el.value;change(s);});
    on('[data-report]','input',el=>{s.state.report[el.dataset.report]=el.value;change(s);refreshContext(s);});
    on('[data-search]','click',()=>draw(s));
    on('[data-field="source"]','change',()=>draw(s));
    for(const kind of ['evidence','containment']) on(`[data-${kind}]`,'change',el=>{
      const id=el.dataset[kind],values=s.state.report[kind];
      s.state.report[kind]=el.checked?[...new Set([...values,id])]:values.filter(v=>v!==id);
      if(kind==='evidence'&&!s.state.inspected.includes(id))s.state.inspected.push(id);
      change(s);refreshContext(s);
    });
    on('[data-add]','click',el=>{if(!s.state.timeline.includes(el.dataset.add))s.state.timeline.push(el.dataset.add);change(s);el.textContent='✓ On timeline';el.disabled=true;refreshContext(s);});
    on('[data-remove]','click',el=>{s.state.timeline=s.state.timeline.filter(id=>id!==el.dataset.remove);change(s,true);});
    for(const [attr,delta] of [['up',-1],['down',1]]) on(`[data-${attr}]`,'click',el=>{const i=Number(el.dataset[attr]);[s.state.timeline[i],s.state.timeline[i+delta]]=[s.state.timeline[i+delta],s.state.timeline[i]];change(s,true);});
    on('[data-hint]','click',()=>{s.state.hint++;change(s,true);});
    on('[data-retry]','click',()=>retrySync(s));
    on('[data-submit]','click',async el=>{el.disabled=true;await flush(s,true);if(el.isConnected)el.disabled=false;});
    on('[data-exit]','click',async()=>{await flush(s);s.options.onExit();});
    on('[data-complete]','click',()=>completeChapter(s));
    on('[data-cloud]','click',async()=>{
      try {const data=await request(s.client,undefined,s.user);s.scenario=data.scenario;s.record=data.record;s.revision=data.record.revision;s.state=normalizeState(clone(data.record.state));s.conflict=null;s.pending=null;s.dirty=false;notify(s);persistLocal(s);status(s,'Loaded cloud version');draw(s);} catch(e){status(s,e.message);}
    });
    on('[data-local]','click',async()=>{
      try {const data=await request(s.client,undefined,s.user);s.revision=data.record.revision;s.record=data.record;s.conflict=null;s.pending=null;change(s,true);await flush(s);}catch(e){status(s,e.message);}
    });
    root.querySelector('[data-terminal]')?.addEventListener('submit',event=>{
      event.preventDefault();const line=new FormData(event.currentTarget).get('command');s.output=terminal(s.scenario,line);root.querySelector('[data-output]').textContent=s.output;
      const match=/^show ([A-Z]+-\d{2})$/.exec(String(line).trim());if(match&&evidenceById(s,match[1])){markInspected(match[1]);change(s);}
    });
  }
  function emptyState() {return {version:1,panel:'briefing',selectedEvidence:null,query:'',source:'all',notes:'',hint:0,inspected:[],timeline:[],report:{classification:'',severity:'',user:'',endpoint:'',iocs:'',summary:'',evidence:[],containment:[]}};}
  async function mount(root,options) {
    const replay=options.entryIntent==='replay'&&(!active||active.user!==options.user||active.entryNonce!==options.entryNonce);
    if(active?.user===options.user&&!replay) {
      active.root=root;active.options=options;draw(active);return;
    }
    if(active) {
      // A pending write must finish before a new draft can replace its revision.
      clearTimeout(active.timer);
      if(active.saving)await new Promise(resolve=>(active.waiters ||= []).push(resolve));
      active.root=null;
    }
    root.textContent='Loading Chapter 1 investigation and cloud save…';
    const user=options.user,tab=tabId(),baseKey=`cyberguard-soc:${user}:v1`,key=`${baseKey}:${tab}`;
    try {
      let data,offline=false;
      try {data=await request(options.client,undefined,options.user);} catch(error) {
        const saved=(localRead(key)||localRead(baseKey));
        if(!saved?.scenario||!saved?.record||saved.state?.version!==1)throw error;
        data={scenario:saved.scenario,record:{...saved.record,revision:saved.revision,state:saved.state}};offline=true;
      }
      if(!root.isConnected)return;
      const s={root,options,user,client:options.client,scenario:data.scenario,record:data.record,
        revision:data.record.revision,state:normalizeState(clone(data.record.state)),generation:0,dirty:false,saving:false,
        status:'Loaded cloud save',key,baseKey,tab,entryNonce:options.entryNonce,needsRefresh:offline};
      const local=localRead(s.key)||localRead(s.baseKey);
      if(!replay&&local?.pending&&local.state?.version===1) {
        s.state=normalizeState(local.state);s.dirty=true;
        if(local.inflight?.action==='submit')s.pending=local.inflight;
        else if(local.revision!==s.revision)s.conflict={record:data.record};
        s.status=s.conflict?'Conflict: local draft retained; choose which version to keep.':'Saved on this device; cloud sync pending';
      }
      if(!replay&&local?.completion&&!s.record.chapter_completed_at)s.completionRequest=local.completion;
      active=s;
      const fresh=options.entryIntent==='start'&&!s.record.revision&&!s.dirty;
      if(replay||fresh) {
        if(replay)s.state=normalizeState(emptyState());
        s.state.panel='email';
        s.state.console.stage='triage';
        if(!s.state.inspected.includes('MAIL-01'))s.state.inspected.push('MAIL-01');
        s.pending=null;s.completionRequest=null;s.conflict=null;
        s.generation++;s.dirty=true;
        persistLocal(s);
      }
      if(!offline)notify(s);
      if(offline)s.status='Offline: restored local draft; rewards and completion await cloud confirmation.';
      else if(s.completionRequest)s.status='Chapter completion sync pending; retry when connected.';
      draw(s);
      if(s.completionRequest&&!s.conflict)await completeChapter(s);
      else if(s.dirty&&!s.conflict)await flush(s);
    } catch(error) {
      root.textContent=error.message+' Other chapters remain available.';
      const retry=document.createElement('button');retry.textContent='Retry investigation';retry.onclick=()=>mount(root,options);root.append(retry);
      const exit=document.createElement('button');exit.textContent='Return to chapter menu';exit.onclick=options.onExit;root.append(exit);
    }
  }
  window.addEventListener('online',()=>{if(active&&(active.completionRequest||active.dirty||active.needsRefresh))retrySync(active);});
  window.addEventListener('storage',event=>{
    if(active && event.key===active.baseKey && event.newValue) {
      active.conflict={};persistLocal(active,false);status(active,'Conflict: another tab changed this draft. Choose which version to keep.');draw(active);
    }
  });
  window.addEventListener('beforeunload',event=>{if(active?.dirty||active?.completionRequest){event.preventDefault();event.returnValue='';}});
  window.CyberSOC={mount,search,terminal,emptyState,
    async flush(){if(!active)return true;if(active.saving)await new Promise(resolve=>(active.waiters ||= []).push(resolve));return active.completionRequest?completeChapter(active):flush(active);},
    async loadSummary(client,user){const data=await request(client,undefined,user);return summary(data.record);},
    async loadReward(client,user) {const data=await request(client,undefined,user);return data.record.reward_xp||0;},
    reset(){if(active){clearTimeout(active.timer);active.root=null;}active=null;}
  };
})();

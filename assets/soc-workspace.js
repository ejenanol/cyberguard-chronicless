/* The browser receives evidence and assessment results, never the grading rules. */
(function () {
  'use strict';
  const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const clone = value => JSON.parse(JSON.stringify(value));
  const tabs = ['briefing','email','logs','timeline','terminal','report'];
  const title = value => value[0].toUpperCase()+value.slice(1);
  let active;
  async function request(client,body) {
    const {data:{session}} = await client.auth.getSession();
    if(!session?.access_token) throw new Error('Sign in again to save the investigation.');
    const response = await fetch('/api/soc',{
      method:body?'POST':'GET', signal:AbortSignal.timeout(10000), headers:{Authorization:`Bearer ${session.access_token}`,...(body?{'Content-Type':'application/json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{})
    });
    const data = await response.json();
    if(!response.ok) throw Object.assign(new Error(data.error || 'Investigation request failed.'),{status:response.status,record:data.record});
    return data;
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
      const snapshot=JSON.stringify({revision:s.revision,state:s.state,pending:s.dirty,inflight:s.pending||null,scenario:s.scenario,record:s.record,origin:s.tab});
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
      const {record}=await request(s.client,body);
      s.revision=record.revision;s.record=record;s.pending=null;
      s.dirty=JSON.stringify(s.state)!==JSON.stringify(body.state);
      if(!s.dirty) s.state=clone(record.state);
      s.options.onReward(record.reward_xp || 0);
      persistLocal(s);
      status(s,s.dirty?'Saved on this device; cloud sync pending':'Saved to cloud');
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
      s.saving=false;
      for(const resolve of s.waiters||[]) resolve();s.waiters=[];
      const submitButton=s.root?.querySelector('[data-submit]');if(submitButton) submitButton.disabled=!!s.conflict;
      if(s.dirty && !s.pending && !s.conflict && /^(Saved)/.test(s.status)) s.timer=setTimeout(()=>flush(s),600);
    }
  }
  function field(label,control) {
    const id='soc-field-'+label.toLowerCase().replace(/[^a-z0-9]+/g,'-');
    return `<div class="soc-field"><label for="${id}">${esc(label)}</label>${control.replace(/^(<\w+)/,`$1 id="${id}"`)}</div>`;
  }
  function checkbox(id,label,checked,kind) {return `<label class="soc-check"><input type="checkbox" data-${kind}="${esc(id)}" ${checked?'checked':''}> ${esc(label)}</label>`;}
  function emailView(s) {
    const e=s.scenario.email;
    return `<h3>Email evidence · ${esc(e.id)}</h3><p>${esc(e.time)}</p><pre>${esc(`From: ${e.from}\nTo: ${e.to.join(', ')}\nSubject: ${e.subject}\n${e.headers}\n\n${e.body}`)}</pre>
      <h3>Attachment metadata and inert preview</h3><pre>${esc(JSON.stringify(e.attachment,null,2))}</pre><p>Indicators are inert text. Nothing is fetched, opened or executed.</p>
      ${checkbox(e.id,'Cite MAIL-01 in report',s.state.report.evidence.includes(e.id),'evidence')}<button type="button" data-add="${e.id}">Add email to timeline</button>`;
  }
  function logsView(s) {
    const rows=search(s.scenario,s.state.query,s.state.source);
    return `<h3>Simulated SIEM · ${rows.length} events</h3><div class="soc-filters">${field('Literal search',`<input data-field="query" maxlength="120" value="${esc(s.state.query)}" placeholder="User, host, domain or event ID">`)}
      ${field('Source',`<select data-field="source">${['all','auth','dns','proxy','endpoint'].map(v=>`<option ${s.state.source===v?'selected':''}>${v}</option>`).join('')}</select>`)}<button data-search>Search</button></div>
      <div class="soc-scroll"><table><caption>All times UTC · Select evidence and add events to your timeline</caption><thead><tr><th scope="col">Event</th><th scope="col">Identity</th><th scope="col">Evidence</th><th scope="col">Record</th></tr></thead><tbody>${rows.map(row=>`<tr><td>${esc(row.id)}<br>${esc(row.time)}<br>${esc(row.source)}</td><td>${esc(row.user)}<br>${esc(row.host)}</td><td>${esc(row.detail)}</td><td>${checkbox(row.id,'Cite '+row.id,s.state.report.evidence.includes(row.id),'evidence')}<button data-add="${row.id}">Add to timeline</button></td></tr>`).join('')}</tbody></table></div>`;
  }
  function timelineView(s) {
    return `<h3>Your incident timeline</h3><p>Order evidence chronologically. Adding evidence does not imply it proves compromise.</p><ol>${s.state.timeline.map((id,i)=>{const row=id==='MAIL-01'?s.scenario.email:s.scenario.logs.find(r=>r.id===id);return `<li>${esc(id)} · ${esc(row?.time)} · ${esc(row?.detail || row?.subject)} <button aria-label="Move ${esc(id)} earlier" data-up="${i}" ${i===0?'disabled':''}>↑</button><button aria-label="Move ${esc(id)} later" data-down="${i}" ${i===s.state.timeline.length-1?'disabled':''}>↓</button><button data-remove="${id}">Remove ${esc(id)}</button></li>`;}).join('')}</ol>`;
  }
  function reportView(s) {
    const r=s.state.report;
    const select=(name,options)=>`<select data-report="${name}"><option value="">Choose…</option>${options.map(([value,label])=>`<option value="${value}" ${r[name]===value?'selected':''}>${esc(label)}</option>`).join('')}</select>`;
    return `<h3>Incident report</h3><p>Findings are assessed by the server. Separate confirmed facts from uncertainty. Passing requires accurate scope, correlated evidence, severity and safe containment.</p>
      ${field('Incident classification',select('classification',[['credential-phishing','Credential phishing / account takeover'],['malware','Endpoint malware'],['benign','Benign routine message']]))}
      ${field('Severity',select('severity',[['low','Low'],['medium','Medium'],['high','High'],['critical','Critical']]))}
      ${field('Confirmed affected username',`<input data-report="user" maxlength="60" value="${esc(r.user)}">`)}
      ${field('Endpoint used for credential submission',`<input data-report="endpoint" maxlength="60" value="${esc(r.endpoint)}">`)}
      ${field('Indicators (one per line; domain and relevant IP addresses)',`<textarea data-report="iocs" maxlength="1200">${esc(r.iocs)}</textarea>`)}
      <fieldset><legend>Recommended containment (simulated only)</legend>${s.scenario.actions.map(a=>checkbox(a.id,a.label,r.containment.includes(a.id),'containment')).join('')}</fieldset>
      <p>Cited evidence: ${esc(r.evidence.join(', ')||'None — use Email and Logs to cite records.')}</p>
      ${field('Analyst summary — evidence IDs, impact, scope, uncertainty and response',`<textarea data-report="summary" maxlength="4000" rows="6">${esc(r.summary)}</textarea>`)}
      <button data-submit ${s.conflict?'disabled':''}>Submit for assessment</button><p>First successful assessment awards 150 XP once. Replays and retries never duplicate it.</p>`;
  }
  function assessment(s) {
    const r=s.record.result;if(!r) return '';
    return `<section class="soc-assessment" aria-label="Last server assessment"><h3>Last server assessment · ${esc(r.score)}/100 · ${r.passed?'Passed':'Keep investigating'}</h3><p>This assesses the last submitted report; subsequent draft edits need a new submission.</p><ul>${r.checks.map(c=>`<li>${c.ok?'✓':'○'} ${esc(c.objective)} (${esc(c.ok?c.points:0)}/${esc(c.points)}) — ${esc(c.explanation)}</li>`).join('')}</ul><p>${esc(r.debrief)}</p><p>Simulation reward ledger: ${esc(s.record.reward_xp)} XP total.</p>${r.passed?'<button data-complete>Continue chapter</button>':''}<button data-replay>Replay investigation (no additional XP)</button></section>`;
  }
  function draw(s) {
    if(!s.root?.isConnected) return;
    const panel=s.state.panel;
    s.root.innerHTML=`<section class="soc" aria-label="SOC phishing investigation"><h2>🎣 ${esc(s.scenario.title)}</h2><p class="soc-label">CHAPTER 1 · SIMULATED SOC · NO REAL TARGETS</p>
      <div class="soc-status"><span data-status role="status" aria-live="polite">${esc(s.status)}</span> <button data-retry hidden>Retry sync</button></div>
      ${s.conflict?'<div class="soc-conflict" role="alert"><p>Another tab or device changed this investigation. Your local draft is retained. Choose explicitly before editing or saving again.</p><button data-cloud>Use cloud version</button><button data-local>Keep my local draft over cloud</button></div>':''}
      <nav aria-label="Investigation tools">${tabs.map(t=>`<button data-tab="${t}" aria-pressed="${panel===t}">${title(t)}</button>`).join('')}</nav>
      <div class="soc-panel">${panel==='briefing'?`<h3>Maya’s briefing</h3><p>${esc(s.scenario.briefing)}</p><ol>${s.scenario.objectives.map(o=>`<li>${esc(o)}</li>`).join('')}</ol><p>Assessed objectives: ${esc(s.record.result?.objectives.length||0)}/8. Draft activity is saved separately from server-validated completion.</p><p>Cadets: begin with Email, then search the Logs for the domain you find. Experienced agents: correlate the identity and endpoint trails before containing.</p>`:panel==='email'?emailView(s):panel==='logs'?logsView(s):panel==='timeline'?timelineView(s):panel==='terminal'?`<h3>Constrained simulated terminal</h3><p>Read-only synthetic dataset; type help for commands.</p><form data-terminal>${field('Command', '<input name="command" maxlength="160" autocomplete="off" spellcheck="false">')}<button>Run simulated command</button></form><pre data-output tabindex="0">${esc(s.output||'Type help. No host commands are available.')}</pre>`:reportView(s)}</div>
      <div class="soc-notes">${field('Analyst notes (private to your account)',`<textarea data-field="notes" maxlength="8000" rows="4">${esc(s.state.notes)}</textarea>`)}<button data-hint ${s.state.hint>=s.scenario.hints.length?'disabled':''}>Reveal next hint (${esc(s.state.hint)}/${s.scenario.hints.length})</button><ol>${s.scenario.hints.slice(0,s.state.hint).map(h=>`<li>${esc(h)}</li>`).join('')}</ol></div>
      ${assessment(s)}<button data-exit>Save draft and return to chapter menu</button></section>`;
    bind(s);status(s,s.status);
  }
  function bind(s) {
    const root=s.root;
    const on=(selector,event,fn)=>root.querySelectorAll(selector).forEach(el=>el.addEventListener(event,()=>fn(el)));
    on('[data-tab]','click',el=>{s.state.panel=el.dataset.tab;if(s.state.panel==='email'&&!s.state.inspected.includes('MAIL-01'))s.state.inspected.push('MAIL-01');change(s,true);});
    on('[data-field]','input',el=>{s.state[el.dataset.field]=el.value;change(s);});
    on('[data-report]','input',el=>{s.state.report[el.dataset.report]=el.value;change(s);});
    on('[data-search]','click',()=>draw(s));
    on('[data-field="source"]','change',()=>draw(s));
    for(const kind of ['evidence','containment']) on(`[data-${kind}]`,'change',el=>{
      const id=el.dataset[kind],values=s.state.report[kind];
      s.state.report[kind]=el.checked?[...new Set([...values,id])]:values.filter(v=>v!==id);
      if(kind==='evidence'&&!s.state.inspected.includes(id))s.state.inspected.push(id);
      change(s);
    });
    on('[data-add]','click',el=>{if(!s.state.timeline.includes(el.dataset.add))s.state.timeline.push(el.dataset.add);change(s);el.textContent='Added to timeline';});
    on('[data-remove]','click',el=>{s.state.timeline=s.state.timeline.filter(id=>id!==el.dataset.remove);change(s,true);});
    for(const [attr,delta] of [['up',-1],['down',1]]) on(`[data-${attr}]`,'click',el=>{const i=Number(el.dataset[attr]);[s.state.timeline[i],s.state.timeline[i+delta]]=[s.state.timeline[i+delta],s.state.timeline[i]];change(s,true);});
    on('[data-hint]','click',()=>{s.state.hint++;change(s,true);});
    on('[data-retry]','click',()=>flush(s));
    on('[data-submit]','click',async el=>{el.disabled=true;await flush(s,true);if(el.isConnected)el.disabled=false;});
    on('[data-exit]','click',async()=>{await flush(s);s.options.onExit();});
    on('[data-complete]','click',()=>s.options.onComplete());
    on('[data-replay]','click',()=>{s.state=emptyState();change(s,true);});
    on('[data-cloud]','click',async()=>{
      try {const data=await request(s.client);s.record=data.record;s.revision=data.record.revision;s.state=clone(data.record.state);s.conflict=null;s.pending=null;s.dirty=false;s.options.onReward(data.record.reward_xp||0);persistLocal(s);status(s,'Loaded cloud version');draw(s);} catch(e){status(s,e.message);}
    });
    on('[data-local]','click',async()=>{
      try {const data=await request(s.client);s.revision=data.record.revision;s.record=data.record;s.conflict=null;s.pending=null;change(s,true);await flush(s);}catch(e){status(s,e.message);}
    });
    root.querySelector('[data-terminal]')?.addEventListener('submit',event=>{
      event.preventDefault();const line=new FormData(event.currentTarget).get('command');s.output=terminal(s.scenario,line);root.querySelector('[data-output]').textContent=s.output;
    });
  }
  function emptyState() {return {version:1,panel:'briefing',query:'',source:'all',notes:'',hint:0,inspected:[],timeline:[],report:{classification:'',severity:'',user:'',endpoint:'',iocs:'',summary:'',evidence:[],containment:[]}};}
  async function mount(root,options) {
    if(active?.user===options.user) {active.root=root;active.options=options;draw(active);return;}
    if(active) {clearTimeout(active.timer);active.root=null;}
    root.textContent='Loading investigation and cloud save…';
    const user=options.user,tab=tabId(),baseKey=`cyberguard-soc:${user}:v1`,key=`${baseKey}:${tab}`;
    try {
      let data,offline=false;
      try {data=await request(options.client);} catch(error) {
        const saved=(localRead(key)||localRead(baseKey));
        if(!saved?.scenario || !saved?.record || saved.state?.version!==1) throw error;
        data={scenario:saved.scenario,record:{...saved.record,revision:saved.revision,state:saved.state}};offline=true;
      }
      
      if(!root.isConnected) return;
      const s={root,options,user,client:options.client,scenario:data.scenario,record:data.record,revision:data.record.revision,state:clone(data.record.state),generation:0,dirty:false,saving:false,status:'Loaded cloud save',key,baseKey,tab};
      const local=localRead(s.key)||localRead(s.baseKey);
      if(local?.pending && local.state?.version===1) {
        s.state=local.state;s.dirty=true;
        if(local.inflight?.action==='submit') {s.pending=local.inflight;}
        else if(local.revision!==s.revision) {s.conflict={record:data.record};}
        s.status=s.conflict?'Conflict: local draft retained; choose which version to keep.':'Saved on this device; cloud sync pending';
      }
      active=s;options.onReward(s.record.reward_xp||0);if(offline)s.status='Offline: restored local draft; retry cloud sync when connected.';draw(s);
      if(s.dirty&&!s.conflict) await flush(s);
    } catch(error) {
      root.textContent=error.message+' Other missions remain available.';
      const retry=document.createElement('button');retry.textContent='Retry investigation';retry.onclick=()=>mount(root,options);root.append(retry);
      const exit=document.createElement('button');exit.textContent='Return to chapter menu';exit.onclick=options.onExit;root.append(exit);
    }
  }
  window.addEventListener('online',()=>{if(active?.dirty)flush(active);});
  window.addEventListener('storage',event=>{
    if(active && event.key===active.baseKey && event.newValue) {
      active.conflict={};persistLocal(active,false);status(active,'Conflict: another tab changed this draft. Choose which version to keep.');draw(active);
    }
  });
  window.addEventListener('beforeunload',event=>{if(active?.dirty){event.preventDefault();event.returnValue='';}});
  window.CyberSOC={mount,search,terminal,emptyState,
    async flush(){if(!active) return true;if(active.saving)await new Promise(resolve=>(active.waiters ||= []).push(resolve));return flush(active);},
    async loadReward(client,user) {const data=await request(client);return data.record.reward_xp||0;},
    reset(){if(active){clearTimeout(active.timer);active.root=null;}active=null;}
  };
})();

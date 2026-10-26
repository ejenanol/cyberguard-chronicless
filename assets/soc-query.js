/* A deliberately limited, local KQL-style parser for synthetic training records. */
(function (root) {
  'use strict';
  const baseColumns = ['id', 'time', 'source', 'user', 'host', 'detail'];
  const processColumns = ['processId', 'pid', 'parentPid', 'name', 'commandLine', 'filePath', 'sha256', 'signature'];
  const emailColumns = ['from', 'to', 'subject', 'headers', 'body', 'attachmentName', 'attachmentMime', 'attachmentSha256'];
  const definitions = [
    {name:'SecurityEvents', source:null, columns:[...baseColumns,...processColumns]},
    {name:'EmailEvents', source:'email', columns:[...baseColumns,...emailColumns]},
    {name:'SigninLogs', source:'auth', columns:baseColumns},
    {name:'DnsEvents', source:'dns', columns:baseColumns},
    {name:'ProxyEvents', source:'proxy', columns:baseColumns},
    {name:'DeviceEvents', source:'endpoint', columns:[...baseColumns,...processColumns]}
  ];
  const examples = [
    {label:'Start with all events', query:'SecurityEvents | sort by time asc | take 20'},
    {label:'Follow an identity', query:'SigninLogs | where user == "alex" | project id, time, user, host, detail | sort by time asc'},
    {label:'Find a domain in web activity', query:'ProxyEvents | where detail contains "payroll-review.example" | project id, time, user, detail'},
    {label:'Compare email authentication', query:'EmailEvents | where headers contains "spf=fail" | project id, time, from, subject, headers'},
    {label:'Inspect endpoint process telemetry', query:'DeviceEvents | where host == "NC-WS-014" | project id, time, processId, pid, parentPid, name, detail | sort by time asc'}
  ];
  const help = [
    'Synthetic training data only. This is a KQL-style subset, not Microsoft KQL or a live Sentinel connection.',
    'Tables: SecurityEvents (all logs), EmailEvents, SigninLogs, DnsEvents, ProxyEvents, DeviceEvents.',
    'Basic columns: id, time (UTC), source, user, host, detail.',
    'DeviceEvents and SecurityEvents also allow processId, pid, parentPid, name, commandLine, filePath, sha256, signature. Missing telemetry is an empty cell, not proof of absence.',
    'EmailEvents also allows from, to, subject, headers, body, attachmentName, attachmentMime, attachmentSha256.',
    'Syntax: Table | where column == "text" | where column contains "text" | project id, time, detail | sort by time asc | take 20',
    'where supports == and != with quoted text or integer literals; >, >=, < and <= with integer literals; contains, startswith and has with quoted text. has matches one word (letters, digits or underscore).',
    'Use another where clause to combine filters. Table/column/operator names are case-insensitive. == and != compare text exactly; contains, startswith and has ignore case.',
    'Single or double quotes are accepted. Inside a quoted value, escape its quote or a backslash with a backslash. Pipes inside quotes are literal text.',
    'project accepts a comma-separated list of allowed columns. Later operators can use only projected columns. sort by defaults to desc; asc is available. take accepts 1–100.',
    'Limits: 2,000 characters, 12 operators and 100 returned rows. Results use only the supplied synthetic records. No joins, functions, expressions, comments, regex, SQL, JavaScript, shell commands or external requests.'
  ].join('\n');
  function fail(message) {
    const error = new Error(message);
    error.name = 'QueryError';
    throw error;
  }
  function splitPipeline(query) {
    if(typeof query !== 'string') fail('Enter a query as text.');
    if(query.length > 2000) fail('Query is too long. Use at most 2,000 characters.');
    if(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(query)) fail('Control characters are not supported in queries.');
    if(!query.trim()) fail('Choose a synthetic table to start, for example SecurityEvents | take 20.');
    const parts=[];
    let current='', quote=null, escaped=false;
    for(const char of query) {
      if(quote) {
        current+=char;
        if(escaped) escaped=false;
        else if(char==='\\') escaped=true;
        else if(char===quote) quote=null;
      } else if(char==='"'||char==="'") {quote=char;current+=char;}
      else if(char==='|') {parts.push(current.trim());current='';}
      else current+=char;
    }
    if(quote) fail('Unclosed quoted value. Close the matching single or double quote.');
    parts.push(current.trim());
    if(parts.some(part=>!part)) fail('An empty pipeline step was found. Put a supported operator after each |.');
    if(parts.length>13) fail('Too many pipeline steps. Use at most 12 operators.');
    return parts;
  }
  function literal(input) {
    if(/^\-?(?:0|[1-9][0-9]*)$/.test(input)) {
      const number=Number(input);
      if(!Number.isSafeInteger(number)) fail('Integer literals must be safe whole numbers.');
      return number;
    }
    const quote=input[0];
    if(quote!=='"'&&quote!=="'") fail('Filter values must be quoted text or integer literals.');
    let value='';
    for(let i=1;i<input.length;i++) {
      const char=input[i];
      if(char==='\n'||char==='\r') fail('Quoted values must stay on one line.');
      if(char===quote) {
        if(i!==input.length-1) fail('Unexpected text after the quoted value. Combine filters using another | where clause.');
        return value;
      }
      if(char==='\\') {
        const next=input[++i];
        if(next!==quote&&next!=='\\') fail('Only the matching quote and backslash can be escaped inside a value.');
        value+=next;
      } else value+=char;
    }
    fail('Unclosed quoted value.');
  }
  function resolveColumn(name, available) {
    const canonical=available.find(column=>column.toLowerCase()===name.toLowerCase());
    if(!canonical) fail('Unknown or unavailable column "'+name+'". Available columns: '+available.join(', ')+'.');
    return canonical;
  }
  function scalar(value) {
    return ['string','number','boolean'].includes(typeof value) ? value : '';
  }
  function sourceRows(scenario, definition) {
    if(!scenario||typeof scenario!=='object'||!Array.isArray(scenario.logs)) fail('The synthetic training dataset is unavailable. Reconnect and reopen the investigation.');
    if(scenario.logs.length>5000) fail('This local training query tool supports at most 5,000 source records.');
    if(definition.source==='email') {
      const email=scenario.email;
      if(!email||typeof email!=='object') return [];
      const attachment=email.attachment||{};
      const to=Array.isArray(email.to)?email.to.filter(value=>typeof value==='string').join(', '):'';
      return [{id:scalar(email.id),time:scalar(email.time),source:'email',user:'',host:'',
        detail:[email.subject,email.from,to,email.headers,email.body,attachment.preview].map(scalar).join('\n'),
        from:scalar(email.from),to,subject:scalar(email.subject),headers:scalar(email.headers),body:scalar(email.body),
        attachmentName:scalar(attachment.name),attachmentMime:scalar(attachment.mime),attachmentSha256:scalar(attachment.sha256)}];
    }
    return scenario.logs.filter(row=>row&&typeof row==='object'&&(!definition.source||row.source===definition.source))
      .map(row=>Object.fromEntries(definition.columns.map(column=>[column,Object.prototype.hasOwnProperty.call(row,column)?scalar(row[column]):''])));
  }
  function run(scenario, query) {
    const pipeline=splitPipeline(query);
    const definition=definitions.find(table=>table.name.toLowerCase()===pipeline[0].toLowerCase());
    if(!definition) fail('Unknown table "'+pipeline[0]+'". Choose '+definitions.map(table=>table.name).join(', ')+'.');
    let rows=sourceRows(scenario,definition), available=[...definition.columns], columns=[...baseColumns];
    for(const step of pipeline.slice(1)) {
      let match=/^where\s+([a-z][a-z0-9_]*)\s*(==|!=|>=|<=|>|<|contains\b|has\b|startswith\b)\s*(.+)$/i.exec(step);
      if(match) {
        const field=resolveColumn(match[1],available),operator=match[2].toLowerCase(),value=literal(match[3].trim());
        if(['contains','has','startswith'].includes(operator)&&typeof value!=='string') fail(operator+' requires a quoted text value.');
        if(['>','>=','<','<='].includes(operator)&&typeof value!=='number') fail('Ordered comparisons support integer values only. Sort the UTC time column to reconstruct time order.');
        if(operator==='has'&&!/^[a-z0-9_]+$/i.test(value)) fail('has expects one word made of letters, digits or underscore. Use contains for a phrase.');
        rows=rows.filter(row=>{
          const actual=row[field];
          if(operator==='==') return actual===value;
          if(operator==='!=') return actual!==value;
          if(['>','>=','<','<='].includes(operator)) {
            if(typeof actual!=='number') return false;
            if(operator==='>') return actual>value;
            if(operator==='>=') return actual>=value;
            if(operator==='<') return actual<value;
            return actual<=value;
          }
          const text=String(actual).toLowerCase(),term=value.toLowerCase();
          if(operator==='contains') return text.includes(term);
          if(operator==='startswith') return text.startsWith(term);
          return text.split(/[^a-z0-9_]+/).includes(term);
        });
        continue;
      }
      match=/^project\s+(.+)$/i.exec(step);
      if(match) {
        const names=match[1].split(',').map(name=>name.trim());
        if(names.some(name=>!/^[a-z][a-z0-9_]*$/i.test(name))) fail('project expects a comma-separated list of column names, for example project id, time, detail.');
        columns=names.map(name=>resolveColumn(name,available));
        if(new Set(columns).size!==columns.length) fail('project contains a duplicate column. List each column once.');
        available=[...columns];
        continue;
      }
      match=/^sort\s+by\s+([a-z][a-z0-9_]*)(?:\s+(asc|desc))?$/i.exec(step);
      if(match) {
        const field=resolveColumn(match[1],available),direction=match[2]?.toLowerCase()==='asc'?1:-1;
        rows=[...rows].sort((left,right)=>{
          const a=left[field],b=right[field];
          // Missing telemetry sorts last in either direction. Equal values keep source order.
          if(a===''&&b!=='') return 1;
          if(b===''&&a!=='') return -1;
          return (a<b?-1:a>b?1:0)*direction;
        });
        continue;
      }
      match=/^take\s+([0-9]+)$/i.exec(step);
      if(match) {
        const count=Number(match[1]);
        if(!Number.isSafeInteger(count)||count<1||count>100) fail('take must be a whole number from 1 to 100.');
        rows=rows.slice(0,count);
        continue;
      }
      fail('Unsupported pipeline step "'+step.slice(0,100)+'". Use where, project, sort by or take; see the supported syntax.');
    }
    const total=rows.length;
    return {table:definition.name,columns,rows:rows.slice(0,100).map(row=>Object.fromEntries(columns.map(column=>[column,row[column]]))),total,limited:total>100};
  }
  const api=Object.freeze({run,help,examples:Object.freeze(examples.map(example=>Object.freeze(example))),tables:Object.freeze(definitions.map(table=>table.name))});
  if(root) root.CyberSOCQuery=api;
  if(typeof module!=='undefined'&&module.exports) module.exports=api;
})(typeof window!=='undefined'?window:typeof globalThis!=='undefined'?globalThis:null);

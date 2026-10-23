const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function handler(file, context = {}) {
  const source = fs.readFileSync(path.join(__dirname, '../api', file), 'utf8')
    .replace(/^import .*;\n/, '').replace('export default async function handler', 'async function handler');
  const sandbox = vm.createContext({process:{env:{}},console:{error(){}},...context});
  vm.runInContext(source, sandbox);
  return sandbox.handler;
}
function response() {
  return {statusCode:200, status(code){this.statusCode=code;return this;},json(body){this.body=body;return this;}};
}
test('hint rejects absent, null and non-string titles without throwing', async()=>{
  const hint=handler('hint.js');
  for(const body of [undefined,null,{}, {title:42}, {title:'  '}]) {
    const res=response();await hint({method:'POST',body},res);assert.equal(res.statusCode,400);
  }
});
test('hint works without an Anthropic key and makes no external request', async()=>{
  const hint=handler('hint.js',{fetch(){assert.fail('Unexpected API call');}});
  const res=response();await hint({method:'POST',body:{title:'Phishing'}},res);
  assert.equal(res.statusCode,200);assert.match(res.body.hint,/Think carefully/);
});
test('hint reports upstream failure rather than claiming success', async()=>{
  const hint=handler('hint.js',{process:{env:{ANTHROPIC_API_KEY:'test-only'}},fetch:async()=>({ok:false})});
  const res=response();await hint({method:'POST',body:{title:'Phishing'}},res);
  assert.equal(res.statusCode,502);assert.match(res.body.hint,/Think carefully/);
});
test('username underscores are escaped for literal case-insensitive lookup', async()=>{
  let pattern;
  const lookup=handler('resolve-username.js',{
    process:{env:{SUPABASE_URL:'https://example.supabase.co',SUPABASE_SECRET_KEY:'test-only'}},
    createClient:()=>({from:()=>({select:()=>({ilike:(column,value)=>{
      pattern=value;return {maybeSingle:async()=>({data:null,error:null})};
    }})})})
  });
  const res=response();await lookup({method:'POST',body:{action:'check',username:' Agent_1 '}},res);
  assert.equal(pattern,'agent\\_1');assert.equal(res.body.available,true);
});
test('feedback reports resolved database errors as failures', async()=>{
  const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
  const source=html.slice(html.indexOf('const saveFeedback ='),html.indexOf('const getLeaderboard ='));
  for(const error of [null,{code:'42501'}]) {
    const context=vm.createContext({sb:{from:()=>({insert:async()=>({error})})}});
    vm.runInContext(source+'globalThis.save = saveFeedback;',context);
    assert.equal(await context.save(5,'Useful game',100),!error);
  }
});

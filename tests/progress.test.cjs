const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(require('node:path').join(__dirname, '../index.html'), 'utf8');
const source = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1]).sort((a,b)=>b.length-a.length)[0].split('// ─── START THE APP')[0];
function setup({ storage=new Map(), database=new Map(), fail=false, delay }={}) {
  const writes=[];
  const client={ auth: {
    onAuthStateChange() {},
    getSession: async()=>({data:{session:{user:{id:'agent-1',email:'agent@example.com',user_metadata:{username:'agent'}}}}})
  }, from: ()=>({
    upsert: async row=>{
      if(delay) await delay();
      writes.push(JSON.parse(JSON.stringify(row)));
      if(fail) return {error:{code:'offline'}};
      database.set(row.user_id,JSON.parse(JSON.stringify(row)));
      return {error:null};
    },
    select: ()=>({eq: (field,id)=>({maybeSingle:async()=>({data:database.get(id)||null,error:fail?{code:'offline'}:null})})})
  }) };
  const app={innerHTML:''};
  const context=vm.createContext({
    window:{location:{hash:''},addEventListener(){}}, URLSearchParams,
    supabase:{createClient:()=>client}, console:{log(){},warn(){},error(){}},
    localStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)},
    document:{getElementById:id=>id==='app'?app:null},setTimeout,clearTimeout,setInterval,clearInterval
  });
  vm.runInContext(source,context);
  vm.runInContext(`globalThis.state=ST; globalThis.game=GD; globalThis.persist=saveProgress;
    globalThis.flush=()=>progressQueue; globalThis.draw=render; render=()=>saveProgress();
    ST.authUser={id:'agent-1'}; ST.authEmail='agent@example.com'; ST.username='agent';
    ST.profile='pro'; ST.playerName='Agent'; ST.screen='challenge';`,context);
  return {context,ST:context.state,writes,database,storage,app};
}
test('mission result survives reload and cannot award XP twice',async()=>{
  const s=setup();
  s.ST.chapIdx=s.context.game.findIndex(c=>c.challenges.some((ch,i)=>ch.explanations && i<c.challenges.length-1));
  s.ST.chalIdx=s.context.game[s.ST.chapIdx].challenges.findIndex((ch,i)=>ch.explanations && i<s.context.game[s.ST.chapIdx].challenges.length-1);
  const mission=s.ST.chalIdx;
  s.ST.selOpt=s.context.game[s.ST.chapIdx].challenges[mission].correct;
  s.context.window.submitMCQ();
  await s.context.flush();
  const xp=s.ST.xp;
  s.context.window.submitMCQ();
  assert.equal(s.ST.xp,xp);
  const next=setup(s);
  await next.context.initializeAuth();
  assert.equal(next.ST.screen,'welcome_back');
  next.context.window.continueProgress();
  assert.equal(next.ST.screen,'result');
  assert.equal(next.ST.xp,xp);
  assert.ok(next.ST.result);
  await next.context.window.nextChal();
  await next.context.flush();
  assert.equal(next.database.get('agent-1').chal_idx,mission+1);
  assert.equal(next.database.get('agent-1').checkpoint.screen,'challenge');
});
test('classification missions save their awarded XP and result',async()=>{
  const s=setup();
  const chapter=s.context.game.findIndex(c=>c.challenges.some(ch=>ch.items));
  s.ST.chapIdx=chapter;
  s.ST.chalIdx=s.context.game[chapter].challenges.findIndex(ch=>ch.items);
  const challenge=s.context.game[chapter].challenges[s.ST.chalIdx];
  s.ST.classifyAnswers=Object.fromEntries(challenge.items.map(i=>[i.id,i.correct]));
  s.context.window.submitClassify();
  await s.context.flush();
  assert.equal(s.database.get('agent-1').xp,challenge.xp);
  assert.equal(s.database.get('agent-1').checkpoint.screen,'result');
});
test('chapter completion persists codex and unlocked chapters before reload',async()=>{
  const s=setup();
  s.ST.chalIdx=s.context.game[0].challenges.length-1;
  s.ST.result={ok:true,earned:100,expl:'done'};s.ST.screen='result';
  s.ST.playerName=null;
  await s.context.window.nextChal();
  await s.context.flush();
  const row=s.database.get('agent-1');
  assert.ok(row.done_chaps.includes(1));
  assert.ok(row.codex.length);
  assert.equal(row.checkpoint.screen,'chap_end');
});
test('partial answers and chapter story resume at the saved screen',async()=>{
  const s=setup();
  s.ST.screen='story';await s.context.persist();
  let next=setup(s);await next.context.initializeAuth();next.context.window.continueProgress();
  assert.equal(next.ST.screen,'story');
  next.context.window.advScene();
  next.ST.selOpt=0;next.context.window.addSpot('test-spot');
  await next.context.flush();
  const restored=setup(next);await restored.context.initializeAuth();restored.context.window.continueProgress();
  assert.equal(restored.ST.screen,'challenge');
  assert.equal(restored.ST.selOpt,0);
  assert.ok(restored.ST.foundSpots.has('test-spot'));
});
test('offline checkpoint survives reload and syncs when saving succeeds',async()=>{
  const s=setup({fail:true});s.ST.xp=100;await s.context.persist();
  assert.match(s.ST.saveStatus,/sync pending/);
  const next=setup({storage:s.storage,database:s.database});
  await next.context.initializeAuth();next.context.window.continueProgress();await next.context.flush();
  assert.equal(next.ST.xp,100);
  assert.equal(next.database.get('agent-1').xp,100);
  assert.equal(next.ST.saveStatus,'Progress saved');
});
test('queued saves freeze snapshots and preserve write order',async()=>{
  let release;const blocked=new Promise(resolve=>{release=resolve;});
  const s=setup({delay:()=>blocked});
  s.ST.xp=100;s.context.persist();s.ST.xp=200;s.context.persist();release();
  await s.context.flush();
  assert.deepEqual(s.writes.map(r=>r.xp),[100,200]);
  assert.equal(s.database.get('agent-1').xp,200);
});
test('start fresh persists reset instead of resurrecting old progress',async()=>{
  const s=setup();s.ST.xp=300;await s.context.persist();
  s.context.window.startFresh();await s.context.flush();
  assert.equal(s.database.get('agent-1').xp,0);
  assert.equal(s.database.get('agent-1').profile,null);
});
test('checkpoints are isolated by authenticated user',async()=>{
  const s=setup();await s.context.persist();
  s.ST.authUser={id:'agent-2'};s.ST.username='agent2';s.ST.xp=900;await s.context.persist();
  assert.equal(JSON.parse(s.storage.get('cyberguard-progress:agent-1')).xp,0);
  assert.equal(JSON.parse(s.storage.get('cyberguard-progress:agent-2')).xp,900);
});
test('real render saves answer changes and displays save status',async()=>{
  const s=setup();s.ST.screen='title';s.context.draw();await s.context.flush();
  assert.match(s.app.innerHTML,/save-status/);
  assert.equal(s.database.get('agent-1').checkpoint.screen,'title');
});
test('legacy saves resume at their mission without resetting XP',async()=>{
  const s=setup();await s.context.persist();
  const row=s.database.get('agent-1');delete row.checkpoint;row.xp=250;row.chal_idx=1;
  s.storage.clear();
  const next=setup(s);await next.context.initializeAuth();next.context.window.continueProgress();
  assert.equal(next.ST.screen,'challenge');assert.equal(next.ST.chalIdx,1);assert.equal(next.ST.xp,250);
});
test('failed reads do not silently start a new game',async()=>{
  const s=setup({fail:true});await s.context.initializeAuth();await s.context.flush();
  assert.equal(s.ST.screen,'login');assert.equal(s.writes.length,0);
});
test('SOC append preserves legacy indices, completed chapters and all other missions',async()=>{
  const s=setup();
  assert.deepEqual(Array.from(s.context.game[0].challenges,c=>c.type),['email_spot','classify','mcq','soc_investigation']);
  assert.equal(s.context.game.length,19);
  await s.context.persist();const row=s.database.get('agent-1');
  row.done_chaps=[1];row.xp=275;row.chal_idx=2;row.checkpoint={screen:'chap_end'};s.storage.clear();
  const next=setup(s);await next.context.initializeAuth();next.context.window.continueProgress();
  assert.equal(next.ST.screen,'chap_end');assert.equal(next.ST.chalIdx,2);assert.ok(next.ST.doneChaps.includes(1));assert.equal(next.ST.xp,275);
});
test('simulation bonus projects into existing XP without duplicating legacy stored XP',async()=>{
  const s=setup();s.ST.socReward=150;s.ST.xp=425;await s.context.persist();
  assert.equal(s.database.get('agent-1').xp,275);
  const next=setup(s);next.context.window.CyberSOC={loadReward:async()=>150};
  await next.context.initializeAuth();next.context.window.continueProgress();await next.context.flush();
  assert.equal(next.ST.xp,425);assert.equal(next.ST.socReward,150);assert.equal(next.database.get('agent-1').xp,275);
  next.context.window.startFresh();await next.context.flush();
  assert.equal(next.ST.xp,150);assert.equal(next.database.get('agent-1').xp,0);
});

// Isolated browser fixture: real API handler, grader and SQL; fake test-only identity.
// This file is NOT imported by the production development server or Vercel handlers.
const http=require('node:http');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const {createHash}=require('node:crypto');
const {serve}=require('../../scripts/dev.cjs');
const root=path.join(__dirname,'../..');
(async()=>{
  const {PGlite}=await import('@electric-sql/pglite');const db=new PGlite();
  const A='11111111-1111-4111-8111-111111111111',B='22222222-2222-4222-8222-222222222222';
  await db.exec(`create role anon;create role authenticated;create role service_role bypassrls;create schema auth;create table auth.users(id uuid primary key);create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;insert into auth.users values('${A}'),('${B}');`);
  await db.exec("create table public.user_progress(user_id uuid primary key references auth.users(id), xp integer default 0, done_chaps jsonb default '[]'::jsonb);");
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20261023220000_soc_phishing_investigation.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20261024010000_integrate_chapter_one.sql'),'utf8'));
  const client={auth:{getUser:async token=>({data:{user:token==='test-A'?{id:A}:token==='test-B'?{id:B}:null}})},from:()=>({select:()=>({filters:{},eq(k,v){this.filters[k]=v;return this;},async maybeSingle(){return {data:(await db.query('select * from soc_investigations where user_id=$1 and scenario_id=$2',[this.filters.user_id,this.filters.scenario_id])).rows[0]||null};}})}),rpc:async(name,p)=>({data:name==='complete_soc_chapter'?(await db.query('select complete_soc_chapter($1,$2,$3) as value',[p.p_user,p.p_scenario,p.p_revision])).rows[0].value:(await db.query('select write_soc_investigation($1,$2,$3,$4,$5,$6,$7) as value',[p.p_user,p.p_scenario,p.p_revision,JSON.stringify(p.p_state),p.p_result?JSON.stringify(p.p_result):null,p.p_request,p.p_hash])).rows[0].value})};
  const lib=await import('../../api/_lib/soc.js');
  const source=fs.readFileSync(path.join(root,'api/soc.js'),'utf8').replace(/^import .*;\n/gm,'').replace('export default async function handler','async function handler');
  const context=vm.createContext({...lib,createHash,createClient:()=>client,Buffer,process:{env:{SUPABASE_URL:'https://fixture.invalid',SUPABASE_SECRET_KEY:'fixture-only'}},console,Date,Map});vm.runInContext(source,context);
  const server=http.createServer(async(req,res)=>{
    if(req.url==='/__test/reset'&&req.method==='POST'){await db.exec('truncate soc_submission_receipts,soc_investigations');vm.runInContext('buckets.clear()',context);res.end('reset');return;}
    if(req.url==='/__test/seed-soc'&&req.method==='POST'){
      try{
        let text='';for await(const chunk of req){text+=chunk;if(text.length>64000)throw new Error('Too large');}
        const seed=JSON.parse(text||'{}'),user=seed.user_id||A;
        if(![A,B].includes(user)||![0,150].includes(seed.reward_xp||0)||!Number.isSafeInteger(seed.revision??1))throw new Error('Invalid test seed');
        const state=lib.validateState(seed.state||{}),completed=seed.chapter_completed_at===true?new Date().toISOString():seed.chapter_completed_at||null;
        await db.query('insert into soc_investigations(user_id,scenario_id,revision,state,result,reward_xp,chapter_completed_at) values($1,$2,$3,$4,$5,$6,$7) on conflict(user_id,scenario_id) do update set revision=excluded.revision,state=excluded.state,result=excluded.result,reward_xp=excluded.reward_xp,chapter_completed_at=excluded.chapter_completed_at',
          [user,lib.scenarioId,seed.revision??1,JSON.stringify(state),seed.result?JSON.stringify(seed.result):null,seed.reward_xp||0,completed]);res.end('seeded');
      }catch{res.statusCode=400;res.end('Invalid test seed');}return;
    }
    if(req.url==='/__test/unthrottle'&&req.method==='POST'){await db.exec("update soc_investigations set last_submitted_at=now()-interval '10 seconds'");res.end('ok');return;}
    await serve(req,res,async route=>route==='soc'?context.handler:(await import(path.join(root,'api',route+'.js'))).default);
  });
  server.listen(3100,'127.0.0.1',()=>console.log('Isolated browser fixture ready'));
})().catch(error=>{console.error(error);process.exitCode=1;});

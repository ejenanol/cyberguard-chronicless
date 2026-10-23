// Isolated browser fixture: real API handler, grader and SQL; fake test-only identity.
// This file is NOT imported by the production development server or Vercel handlers.
const http=require('node:http');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const {createHash}=require('node:crypto');
const {serve}=require('../../scripts/dev.cjs');
const root=path.join(__dirname,'../..');
(async()=>{
  const {PGlite}=await import('@electric-sql/pglite');const db=new PGlite();
  const A='11111111-1111-4111-8111-111111111111',B='22222222-2222-4222-8222-222222222222';
  await db.exec(`create role anon;create role authenticated;create role service_role bypassrls;create schema auth;create table auth.users(id uuid primary key);create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;insert into auth.users values('${A}'),('${B}');`);
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20261023220000_soc_phishing_investigation.sql'),'utf8'));
  const client={auth:{getUser:async token=>({data:{user:token==='test-A'?{id:A}:token==='test-B'?{id:B}:null}})},from:()=>({select:()=>({filters:{},eq(k,v){this.filters[k]=v;return this;},async maybeSingle(){return {data:(await db.query('select * from soc_investigations where user_id=$1 and scenario_id=$2',[this.filters.user_id,this.filters.scenario_id])).rows[0]||null};}})}),rpc:async(name,p)=>({data:(await db.query('select write_soc_investigation($1,$2,$3,$4,$5,$6,$7) as value',[p.p_user,p.p_scenario,p.p_revision,JSON.stringify(p.p_state),p.p_result?JSON.stringify(p.p_result):null,p.p_request,p.p_hash])).rows[0].value})};
  const lib=await import('../../api/_lib/soc.js');
  const source=fs.readFileSync(path.join(root,'api/soc.js'),'utf8').replace(/^import .*;\n/gm,'').replace('export default async function handler','async function handler');
  const context=vm.createContext({...lib,createHash,createClient:()=>client,Buffer,process:{env:{SUPABASE_URL:'https://fixture.invalid',SUPABASE_SECRET_KEY:'fixture-only'}},console,Date,Map});vm.runInContext(source,context);
  const server=http.createServer(async(req,res)=>{
    if(req.url==='/__test/reset'&&req.method==='POST'){await db.exec('truncate soc_submission_receipts,soc_investigations');res.end('reset');return;}
    if(req.url==='/__test/unthrottle'&&req.method==='POST'){await db.exec("update soc_investigations set last_submitted_at=now()-interval '10 seconds'");res.end('ok');return;}
    await serve(req,res,async route=>route==='soc'?context.handler:(await import(path.join(root,'api',route+'.js'))).default);
  });
  server.listen(3100,'127.0.0.1',()=>console.log('Isolated browser fixture ready'));
})().catch(error=>{console.error(error);process.exitCode=1;});

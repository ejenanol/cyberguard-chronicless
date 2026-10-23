const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';
test('migration: transactions, stale writes, RLS and exactly-once reward ledger',async()=>{
  const {PGlite}=await import('@electric-sql/pglite');const db=new PGlite();
  try{
    await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
      create schema auth;create table auth.users(id uuid primary key);
      create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
      grant usage on schema auth to authenticated;grant execute on function auth.uid() to authenticated;
      insert into auth.users values('${A}'),('${B}');`);
    await db.exec(fs.readFileSync(path.join(__dirname,'../supabase/migrations/20261023220000_soc_phishing_investigation.sql'),'utf8'));
    const write=async(user,revision,request,result=null,hash='hash',state={version:1})=>(await db.query('select public.write_soc_investigation($1,$2,$3,$4,$5,$6,$7) as data',[user,'phishing-soc-v1',revision,JSON.stringify(state),result?JSON.stringify(result):null,request,hash])).rows[0].data;
    const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
    let saved=await write(A,0,id(1));assert.equal(saved.record.revision,1);
    const stale=await write(A,0,id(2));assert.equal(stale.conflict,true);assert.equal(stale.record.revision,1);
    let passed=await write(A,1,id(3),{passed:true,score:100});assert.equal(passed.record.reward_xp,150);assert.equal(passed.record.revision,2);
    const duplicate=await write(A,1,id(3),{passed:true,score:100});assert.equal(duplicate.duplicate,true);assert.equal(duplicate.record.revision,2);assert.equal(duplicate.record.reward_xp,150);
    assert.equal((await write(A,2,id(3),{passed:true},'changed')).reused,true);
    assert.equal((await write(A,2,id(4),{passed:true})).throttled,true);
    await db.exec(`update public.soc_investigations set last_submitted_at=now()-interval '10 seconds';`);
    passed=await write(A,2,id(5),{passed:true,score:100});assert.equal(passed.record.reward_xp,150);
    await write(B,0,id(6),null,'other',{notes:'B private'});
    await db.exec(`set role authenticated; set request.jwt.claim.sub='${A}';`);
    const own=await db.query('select user_id from public.soc_investigations');assert.deepEqual(own.rows.map(r=>r.user_id),[A]);
    await assert.rejects(db.exec(`update public.soc_investigations set reward_xp=150 where user_id='${B}'`),/permission denied/);
    await assert.rejects(write(B,1,id(7),{passed:true}),/permission denied/);
    await assert.rejects(db.query('select * from public.soc_submission_receipts'),/permission denied/);
    await db.exec('reset role; set role anon;');
    await assert.rejects(db.query('select * from public.soc_investigations'),/permission denied/);
  }finally{await db.close();}
});

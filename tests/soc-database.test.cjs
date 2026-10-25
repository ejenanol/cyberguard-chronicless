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

test('chapter migration preserves historical XP/completion; completion requires a server pass and is idempotent',async()=>{
  const {PGlite}=await import('@electric-sql/pglite');const db=new PGlite();
  const C='33333333-3333-4333-8333-333333333333',D='44444444-4444-4444-8444-444444444444';
  try{
    await db.exec(`create role anon;create role authenticated;create role service_role bypassrls;
      create schema auth;create table auth.users(id uuid primary key);
      create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
      grant usage on schema auth to authenticated;grant execute on function auth.uid() to authenticated;
      insert into auth.users values('${A}'),('${B}'),('${C}'),('${D}');
      create table public.user_progress(user_id uuid primary key references auth.users(id),xp integer,done_chaps jsonb,checkpoint jsonb);
      insert into public.user_progress values
        ('${A}',275,'[1,2]','{"screen":"chap_end"}'),
        ('${B}',100,'[]','{"screen":"challenge","selOpt":1}'),
        ('${C}',0,'[1]','{"screen":"title"}'),
        ('${D}',75,'[]','{"screen":"result"}');`);
    await db.exec(fs.readFileSync(path.join(__dirname,'../supabase/migrations/20261023220000_soc_phishing_investigation.sql'),'utf8'));
    const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
    const write=async(user,revision,n,result=null,state={version:1})=>(await db.query('select public.write_soc_investigation($1,$2,$3,$4,$5,$6,$7) as data',[user,'phishing-soc-v1',revision,JSON.stringify(state),result?JSON.stringify(result):null,id(n),'hash-'+n])).rows[0].data;
    await write(A,0,1,{passed:true,score:80},{version:1,panel:'logs',notes:'Existing saved investigation',timeline:['MAIL-01']});
    await write(D,0,2,{passed:true,score:80},{version:1,panel:'report',notes:'Previously passed under original rules'});
    await db.exec(`update soc_investigations set result='{"passed":false,"score":0}' where user_id='${D}';`);
    const before=(await db.query('select * from user_progress order by user_id')).rows;
    await db.exec(fs.readFileSync(path.join(__dirname,'../supabase/migrations/20261024010000_integrate_chapter_one.sql'),'utf8'));
    assert.deepEqual((await db.query('select * from user_progress order by user_id')).rows,before,'no historical XP, unlock or checkpoint changes');
    const a=(await db.query('select * from soc_investigations where user_id=$1',[A])).rows[0];
    assert.ok(a.chapter_completed_at);assert.equal(a.reward_xp,150);assert.equal(a.revision,1);assert.equal(a.state.notes,'Existing saved investigation');assert.equal(a.result.score,80);
    const c=(await db.query('select * from soc_investigations where user_id=$1',[C])).rows[0];
    assert.ok(c.chapter_completed_at);assert.equal(c.reward_xp,0,'grandfathering never grants XP');
    const finish=async(user,revision)=>(await db.query('select public.complete_soc_chapter($1,$2,$3) as data',[user,'phishing-soc-v1',revision])).rows[0].data;
    assert.equal((await finish(B,0)).not_passed,true,'no record cannot complete');
    await write(B,0,3,null,{version:1,panel:'report'});assert.equal((await finish(B,1)).not_passed,true,'draft/click-through cannot complete');
    assert.equal((await finish(D,0)).conflict,true,'stale completion cannot overwrite a draft');
    const completed=await finish(D,1);assert.ok(completed.record.chapter_completed_at);assert.equal(completed.record.reward_xp,150);assert.equal(completed.record.revision,2);
    const duplicate=await finish(D,1);assert.equal(duplicate.duplicate,true);assert.equal(duplicate.record.revision,2);assert.equal(duplicate.record.chapter_completed_at,completed.record.chapter_completed_at);
    await db.exec("update soc_investigations set last_submitted_at=now()-interval '10 seconds' where user_id='"+D+"';");
    const replay=await write(D,2,4,{passed:false,score:0},{version:1,panel:'email'});assert.equal(replay.record.reward_xp,150);assert.equal(replay.record.chapter_completed_at,completed.record.chapter_completed_at);
    assert.equal((await finish(D,0)).duplicate,true,'later replay cannot revoke completion');
    await db.exec(`set role authenticated;set request.jwt.claim.sub='${B}';`);
    const scoped=await db.query('select user_id from soc_investigations');assert.deepEqual(scoped.rows.map(r=>r.user_id),[B]);
    await assert.rejects(finish(A,1),/permission denied/);
    await assert.rejects(db.exec(`update soc_investigations set chapter_completed_at=now() where user_id='${B}'`),/permission denied/);
    await db.exec('reset role;set role anon;');await assert.rejects(finish(D,3),/permission denied/);
  }finally{await db.close();}
});

test('chapter backfill tolerates ownerless, orphan and duplicate legacy progress without changing source saves',async()=>{
  const {PGlite}=await import('@electric-sql/pglite');const db=new PGlite();
  const orphan='33333333-3333-4333-8333-333333333333';
  try{
    await db.exec(`create role anon;create role authenticated;create role service_role bypassrls;
      create schema auth;create table auth.users(id uuid primary key);
      create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
      insert into auth.users values('${A}'),('${B}');
      -- Older deployments may have neither a required owner nor unique/FK constraints.
      -- SQL arrays also occur in legacy schemas; the main fixture covers JSON arrays.
      create table public.user_progress(id integer primary key,user_id uuid,xp integer,done_chaps integer[],checkpoint jsonb);
      insert into public.user_progress values
        (1,null,275,array[1],'{"notes":"ownerless save"}'),
        (2,'${orphan}',425,array[1,2],'{"notes":"deleted account save"}'),
        (3,'${A}',100,array[1],'{"notes":"first historical save"}'),
        (4,'${A}',275,array[1,2],'{"notes":"second historical save"}'),
        (5,'${B}',75,array[2],'{"notes":"another chapter only"}'),
        (6,null,0,null,'{}');`);
    await db.exec(fs.readFileSync(path.join(__dirname,'../supabase/migrations/20261023220000_soc_phishing_investigation.sql'),'utf8'));
    const before=(await db.query('select * from user_progress order by id')).rows;
    await db.exec(fs.readFileSync(path.join(__dirname,'../supabase/migrations/20261024010000_integrate_chapter_one.sql'),'utf8'));
    assert.deepEqual((await db.query('select * from user_progress order by id')).rows,before,'even unlinked legacy rows remain untouched');
    const receipts=(await db.query('select * from soc_investigations')).rows;
    assert.equal(receipts.length,1,'only the real completed account gets one receipt');
    assert.equal(receipts[0].user_id,A);assert.ok(receipts[0].chapter_completed_at);
    assert.equal(receipts[0].reward_xp,0);assert.equal(receipts[0].revision,0);
    assert.deepEqual(receipts[0].state,{});assert.equal(receipts[0].result,null);
  }finally{await db.close();}
});

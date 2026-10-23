// Browser tests only. Never loaded by production HTML without Playwright interception.
window.supabase={createClient:()=>{
  const id=localStorage.getItem('test-identity')||'11111111-1111-4111-8111-111111111111';
  const user={id,email:'agent@example.test',user_metadata:{username:'agent'}};
  const session=()=>localStorage.getItem('test-signed-out')?null:{user,access_token:id.startsWith('111')?'test-A':'test-B'};
  const key='test-game:'+id;
  if(!localStorage.getItem(key))localStorage.setItem(key,JSON.stringify({user_id:id,username:'agent',email:user.email,profile:'pro',xp:275,done_chaps:[],codex:[],player_name:'Agent',chap_idx:0,chal_idx:3,checkpoint:{screen:'challenge'},updated_at:'2026-10-22T00:00:00Z'}));
  return {auth:{getSession:async()=>({data:{session:session()}}),onAuthStateChange(){},signOut:async()=>{localStorage.setItem('test-signed-out','1');return {error:null};},signInWithPassword:async()=>{localStorage.removeItem('test-signed-out');return {data:{user,session:session()},error:null};}},from:table=>{
    const result=()=>({data:table==='user_progress'?JSON.parse(localStorage.getItem(key)):table==='player_count'?{count:1}:[],error:null});
    const chain={select(){return this;},eq(){return this;},order(){return this;},limit(){return this;},maybeSingle:async()=>result(),then(resolve){return Promise.resolve(resolve(result()));},upsert:async row=>{if(table==='user_progress')localStorage.setItem(key,JSON.stringify(row));return {error:null};},update(){return this;},insert:async()=>({error:null})};return chain;
  }};
}};

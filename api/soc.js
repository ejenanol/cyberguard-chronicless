import { createClient } from '@supabase/supabase-js';
import { createHash } from 'node:crypto';
import { scenario, scenarioId, validateState, grade } from './_lib/soc.js';

// Best-effort warm-instance limiter, plus transactional submission throttling in SQL.
const buckets=new Map();
function allowed(user) {
  const now=Date.now();
  if(buckets.size>=2000) {
    for(const [key,b] of buckets) if(now>b.reset) buckets.delete(key);
    if(buckets.size>=2000 && !buckets.has(user)) return false;
  }
  const b=buckets.get(user);
  if(!b || now>b.reset) {buckets.set(user,{count:1,reset:now+60000});return true;}
  return ++b.count<=90;
}
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(!['GET','POST'].includes(req.method)) {res.setHeader('Allow','GET, POST');return res.status(405).json({error:'Method not allowed.'});}
  const token=/^Bearer (\S+)$/i.exec(req.headers.authorization || '')?.[1];
  if(!token) return res.status(401).json({error:'Sign in to open the investigation.'});
  if(!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) return res.status(503).json({error:'Investigation service is not configured. Other chapters are still available.'});
  const address=String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  if(!allowed('ip:'+address)) {res.setHeader('Retry-After','60');return res.status(429).json({error:'Too many requests. Wait a minute and retry.'});}
  try {
    const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SECRET_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data:auth,error:authError}=await sb.auth.getUser(token);
    if(authError || !auth?.user) return res.status(401).json({error:'Session expired. Sign in again.'});
    const user=auth.user.id;
    if(!allowed(user)) return res.status(429).json({error:'Too many requests. Wait a minute and retry.'});
    if(req.method==='GET') {
      const {data,error}=await sb.from('soc_investigations').select('*').eq('user_id',user).eq('scenario_id',scenarioId).maybeSingle();
      if(error) throw error;
      return res.status(200).json({scenario,record:data || {revision:0,state:validateState({}),result:null,reward_xp:0}});
    }
    if(Buffer.byteLength(JSON.stringify(req.body ?? {}))>64000) return res.status(413).json({error:'Workspace is too large.'});
    const body=req.body;
    if(!body || !['save','submit'].includes(body.action) || !Number.isSafeInteger(body.revision) || body.revision<0 || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.requestId || '')) return res.status(400).json({error:'Invalid investigation request.'});
    let state;
    try {state=validateState(body.state);} catch {return res.status(400).json({error:'Invalid workspace fields or selections.'});}
    const result=body.action==='submit'?grade(state):null;
    const hash=createHash('sha256').update(JSON.stringify({action:body.action,state})).digest('hex');
    const {data,error}=await sb.rpc('write_soc_investigation',{
      p_user:user,p_scenario:scenarioId,p_revision:body.revision,p_state:state,
      p_result:result,p_request:body.requestId,p_hash:hash
    });
    if(error) throw error;
    if(data.conflict) return res.status(409).json({error:'This investigation changed in another tab or device. Choose which draft to keep.',record:data.record});
    if(data.reused) return res.status(409).json({error:'Request ID was reused with different content. Reload the cloud draft.'});
    if(data.throttled) return res.status(429).json({error:'Wait five seconds before another assessment.'});
    return res.status(200).json(data);
  } catch(error) {
    console.error('SOC service failed:',{code:error?.code || 'unavailable'});
    return res.status(503).json({error:'Investigation storage is unavailable. Your local draft is retained; retry after the service or migration is ready.'});
  }
}

-- Additive: does not modify auth, user_progress, existing rewards or RLS.
create table public.soc_investigations (
  user_id uuid not null references auth.users(id) on delete cascade,
  scenario_id text not null check (scenario_id = 'phishing-soc-v1'),
  revision bigint not null default 0 check (revision >= 0),
  state jsonb not null default '{}'::jsonb,
  result jsonb,
  reward_xp integer not null default 0 check (reward_xp in (0,150)),
  last_submitted_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key (user_id,scenario_id)
);
create table public.soc_submission_receipts (
  user_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  payload_hash text not null,
  primary key (user_id,request_id)
);
alter table public.soc_investigations enable row level security;
alter table public.soc_submission_receipts enable row level security;
create policy "Read own investigation" on public.soc_investigations
  for select to authenticated using ((select auth.uid())=user_id);
-- No browser writes: authenticated API validates every state and assessment.
revoke all on public.soc_investigations from anon,authenticated;
grant select on public.soc_investigations to authenticated;
revoke all on public.soc_submission_receipts from anon,authenticated;
grant all on public.soc_investigations,public.soc_submission_receipts to service_role;

create function public.write_soc_investigation(
  p_user uuid,p_scenario text,p_revision bigint,p_state jsonb,
  p_result jsonb,p_request uuid,p_hash text
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  current_row public.soc_investigations;
  previous_hash text;
begin
  if p_scenario <> 'phishing-soc-v1' then raise exception 'Unknown scenario'; end if;
  insert into public.soc_investigations(user_id,scenario_id)
    values(p_user,p_scenario) on conflict do nothing;
  select * into current_row from public.soc_investigations
    where user_id=p_user and scenario_id=p_scenario for update;
  select payload_hash into previous_hash from public.soc_submission_receipts
    where user_id=p_user and request_id=p_request;
  if found then
    if previous_hash <> p_hash then return jsonb_build_object('reused',true); end if;
    return jsonb_build_object('record',to_jsonb(current_row),'duplicate',true);
  end if;
  if current_row.revision <> p_revision then
    return jsonb_build_object('conflict',true,'record',to_jsonb(current_row));
  end if;
  if p_result is not null and current_row.last_submitted_at > clock_timestamp()-interval '5 seconds' then
    return jsonb_build_object('throttled',true);
  end if;
  update public.soc_investigations set
    state=p_state, revision=revision+1, updated_at=clock_timestamp(),
    result=case when p_result is null then result else p_result end,
    reward_xp=case when (p_result->>'passed')::boolean is true then 150 else reward_xp end,
    last_submitted_at=case when p_result is null then last_submitted_at else clock_timestamp() end
    where user_id=p_user and scenario_id=p_scenario returning * into current_row;
  -- Only submission receipts need indefinite retention. Saves remain CAS operations.
  if p_result is not null then
    insert into public.soc_submission_receipts(user_id,request_id,payload_hash) values(p_user,p_request,p_hash);
  end if;
  return jsonb_build_object('record',to_jsonb(current_row));
end;
$$;
revoke all on function public.write_soc_investigation(uuid,text,bigint,jsonb,jsonb,uuid,text) from public,anon,authenticated;
grant execute on function public.write_soc_investigation(uuid,text,bigint,jsonb,jsonb,uuid,text) to service_role;

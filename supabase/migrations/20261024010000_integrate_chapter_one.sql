-- Apply once after review. Transactional; no existing XP, saves or rewards are changed.
begin;

alter table public.soc_investigations add column chapter_completed_at timestamptz;

-- Freeze historical chapter completion as a server-owned receipt. Do not infer
-- historical quiz XP: it exists only inside the player's aggregate base XP.
-- to_jsonb works with both JSON and SQL-array representations of done_chaps.
insert into public.soc_investigations(user_id, scenario_id, chapter_completed_at)
select progress.user_id, 'phishing-soc-v1', transaction_timestamp()
from public.user_progress as progress
where coalesce(to_jsonb(progress)->'done_chaps', '[]'::jsonb) @> '[1]'::jsonb
on conflict (user_id, scenario_id) do update
  set chapter_completed_at=coalesce(public.soc_investigations.chapter_completed_at, excluded.chapter_completed_at);

-- Assessment/reward stays in write_soc_investigation. Completion acknowledges
-- its monotonic 150-XP proof and never awards XP or trusts a browser's result.
create function public.complete_soc_chapter(p_user uuid, p_scenario text, p_revision bigint)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  current_row public.soc_investigations;
begin
  if p_scenario <> 'phishing-soc-v1' then raise exception 'Unknown scenario'; end if;
  select * into current_row from public.soc_investigations
    where user_id=p_user and scenario_id=p_scenario for update;
  if not found then return jsonb_build_object('not_passed',true); end if;
  -- A receipt is monotonic and idempotent, even after an uncertain response,
  -- a new request ID, or a later failed replay assessment.
  if current_row.chapter_completed_at is not null then
    return jsonb_build_object('record',to_jsonb(current_row),'duplicate',true);
  end if;
  if current_row.reward_xp <> 150 then return jsonb_build_object('not_passed',true); end if;
  if current_row.revision <> p_revision then
    return jsonb_build_object('conflict',true,'record',to_jsonb(current_row));
  end if;
  update public.soc_investigations set
    chapter_completed_at=clock_timestamp(), revision=revision+1, updated_at=clock_timestamp()
    where user_id=p_user and scenario_id=p_scenario returning * into current_row;
  return jsonb_build_object('record',to_jsonb(current_row));
end;
$$;
revoke all on function public.complete_soc_chapter(uuid,text,bigint) from public,anon,authenticated;
grant execute on function public.complete_soc_chapter(uuid,text,bigint) to service_role;

commit;

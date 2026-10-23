alter table public.user_progress add column if not exists checkpoint jsonb;
comment on column public.user_progress.checkpoint is 'Game screen, mission result and in-progress answers for resume; owned by user_id under existing RLS.';

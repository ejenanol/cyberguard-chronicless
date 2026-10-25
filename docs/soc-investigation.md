# Chapter 1: SOC phishing investigation

> Historical design note: the Chapter 1 entry and reward flow are superseded by [the connected Chapter 1 integration](chapter-one-integration.md).
## Scope and compatibility

This extends CyberGuard Chronicles in its existing HTML/JavaScript, Vercel and Supabase stack. Maya Chen briefs a synthetic NexaCorp payroll incident. The terminal, email and SIEM are inert views of one server-supplied dataset. No external targets, paid AI, containers or laboratory infrastructure are involved.

The original three Chapter 1 missions stay at indices 0–2, with their content and XP unchanged. The investigation is appended at index 3 for 150 one-time XP. New playthroughs finish it before the existing chapter-completion screen, codex and badges. Existing saved mission indices and checkpoints resume unchanged; a player finishing the old last mission advances into the new investigation. Previously completed chapters remain completed and other chapters remain unlocked. Those players may replay Chapter 1 and earn the new investigation's reward once; their previous XP and badges are retained. No historical chapter completion is revoked.

The original chapter stories, characters, agent profiles, other 18 chapters, authentication and recovery remain in place. There is no framework migration. Practical investigation depth follows the general pattern of briefing → evidence correlation → response → debrief, with original content and existing CyberGuard colors and game progression.

## Assessment and rewards

`api/_lib/soc.js` contains the synthetic evidence and private grading rules. Only the evidence, instructions and deterministic hints are returned before assessment. The browser neither receives the answer key nor supplies its own trusted score. `api/soc.js` validates the Supabase bearer session using `auth.getUser`, ignores learner-supplied identity/score/reward values and scopes every read/write to that verified user.

A passing report needs at least 80/100 **and** correct classification, affected identity/endpoint, correlated evidence, safe containment and a supported high-severity report. Points also assess email inspection, indicators and a chronological timeline. The report cites evidence IDs; free-form prose is checked for minimum substance and citations, not semantically understood. The debrief explains both correct and missing findings after assessment. Hints are progressive, free, deterministic and do not require an API key.

The SQL transaction locks the learner's investigation, compares revisions, records submission request IDs and awards a ledger total of 150 XP at most once. Failed assessments and replays cannot subtract an existing award. Identical submission retries are idempotent; reusing a request ID with altered content fails. A five-second database assessment throttle and a best-effort per-instance API limiter reduce brute-force submissions. The warm-instance limiter is not a distributed global quota.

Simulation rewards live in `soc_investigations.reward_xp`, not in the legacy client-written `user_progress.xp`. The upgraded client projects this bonus into the existing XP/rank/badge/leaderboard displays and subtracts it before legacy progress writes. Reload reads the ledger again. This avoids stale legacy saves destroying or duplicating simulation rewards and preserves all existing base XP. Start Fresh clears the existing game progress as before but retains an already-earned simulation ledger reward. Old clients display only base XP; upgrading restores the bonus. Existing quiz XP and the public leaderboard retain their previous trust model; hardening them is separate work.

## Progress, offline and concurrency

The simulation persists panel, filters, notes, inspected/cited evidence, timeline, hints and report fields separately from the existing game checkpoint. Cloud writes use a compare-and-swap revision and are serialized within a workspace. A changed draft during an in-flight save is sent in a subsequent write. Local storage is scoped by authenticated user, keeps separate per-tab drafts across refresh, and includes inert evidence for offline reloads. It never stores a service credential or an extra auth token.

Cloud success, local-only/pending, offline restore, failed sync and conflicts are distinct visible states. Uncertain submissions retain the exact request ID and payload for retry. Cross-device stale writes return 409 rather than overwriting; cross-tab storage changes raise a conflict. Users explicitly choose the latest cloud state or overwrite it with their retained local draft. Unsaved changes trigger the browser's leave warning. Local drafts cannot move across devices until cloud sync succeeds. Two devices can each read their own cloud state, but must resolve conflicts when editing concurrently.

The original non-simulation progress queue is retained. Its legacy timestamp conflict model is not upgraded to CAS by this change. This isolation prevents a new simulation migration from breaking other chapters, but simultaneous edits to **legacy missions** remain a known limitation.

## Setup and release (requires review)

1. Use Node 24 (the local adapter uses `--use-env-proxy`); run `npm ci`. The lockfile is now included.
2. Configure `SUPABASE_URL` and `SUPABASE_SECRET_KEY` in the Vercel server environment. Keep the secret out of the repository and browser. The project must match the existing browser Supabase URL in `index.html`.
3. After reviewing the SQL and approving release, apply `supabase/migrations/20261023220000_soc_phishing_investigation.sql` through your normal migration process. It adds two tables and one service-only RPC. It does not modify existing tables, users, policies or data. The older checkpoint migration assumes `public.user_progress` already exists; this repository does not include the full original schema.
4. Start local development with `npm run dev` (default port 3000). The adapter serves only index.html, browser assets and the three public API routes; private server source is not served.
5. Vercel uses the existing `api/` convention. `vercel.json` publishes only the HTML, browser assets and three API functions, and disables automatic deployments of `feat/phishing-soc-investigation`. Server helpers and non-public project files are not static build targets. Verify those paths return 404 in staging.
6. No `ANTHROPIC_API_KEY` is required. The old hint route retains its existing no-key fallback for legacy missions.

The migration is **not** applied to the live database by this PR. Without it, the SOC workspace reports storage unavailable and offers retry/return to the chapter menu; the other chapters remain usable. Do not merge or deploy until the user approves. A deployment may occur automatically when a PR is merged into main; review Vercel project settings before merging.

## Security boundaries

Both new tables enable RLS. Authenticated users can select only their own investigation; anonymous access and browser writes are denied. Receipt access and the write RPC are service-only. The API authenticates before using the server credential. Tests run the real migration against disposable PostgreSQL (PGlite), including cross-user denial and revoked grants. They do not prove the existing hosted project's policies are correct: full schema/policy definitions were not provided by the repository or exposed by the available REST access.

All untrusted UI text is escaped, or written via textContent/input values. Search is literal string matching, not SQL or regex execution. The terminal has a closed command grammar and never uses eval, a shell, server commands or a real network. Input size and selection limits apply server-side. The SDK's auth storage and the existing app error rendering remain inherited components; no service-role credential is sent to the browser. Shared computers retain user-scoped local drafts; clear browser site data when appropriate.

## Verification

- `npm test`: existing auth/recovery/progress regressions plus API grading/input isolation, terminal/search injection and real SQL transaction/RLS tests.
- `npm run test:e2e`: Chromium against the actual app and API handler/grader with the real migration in a disposable PGlite database. Supabase identity and legacy progress are test fixtures; **these are not live Supabase authentication tests**. Set `CHROMIUM_PATH` if Chromium is elsewhere.
- Browser coverage: complete investigation, inert note injection, checkpoint refresh, one-time XP, replay submission, chapter codex/rewards, offline save/retry and offline reload, uncertain submission retry with newer local edits, logout/login, independent-device resume, cross-user isolation, device/tab stale-write resolution, separate tab draft recovery, terminal injection and mobile layout.
- Live verification still required after approved migration: valid-session API access, real refresh/logout/login and second-device saves, cross-user RLS with real users, legacy auth recovery links and Vercel private-source denial. Use authorized test accounts and avoid changing production player data.

## Prioritized follow-ups

1. Export/version the original Supabase schema, grants and RLS; add staging deployment checks and distributed API quotas.
2. Move legacy mission writes and leaderboard scores behind authoritative revision-aware validation, preserving old saves.
3. Extend the same evidence/report pattern into incident response and threat hunting, then IAM, cloud security and vulnerability remediation. Keep each scenario versioned and each reward uniquely identified.
4. If isolated VM labs become necessary, propose lifecycle cleanup, tenant isolation, egress restrictions, abuse controls and explicit cost approval separately. Do not provision them as part of this static simulation.

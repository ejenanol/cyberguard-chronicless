# CyberGuard Chronicles

Cybersecurity learning RPG with 19 chapters, agent profiles, XP, badges and Supabase accounts/progress. Chapter 1 now follows one connected SOC phishing investigation through Triage → Investigate → Reconstruct → Respond, entered from its normal Start/Resume/Replay card.

```sh
npm ci
npm run dev
npm test
npm run test:e2e
```

Use Node 24. Configure `SUPABASE_URL` and `SUPABASE_SECRET_KEY` on the server only. No Anthropic key is required. Browser tests use isolated identity/progress fixtures and a disposable PostgreSQL database; see [simulation setup, compatibility, security and verification](docs/soc-investigation.md) before applying the additive migration or releasing.

See [Chapter 1 integration, reward rules and save compatibility](docs/chapter-one-integration.md) for the staged completion-receipt migration and release checklist. Apply production changes only after PR approval.

The [Sentinel-inspired investigation console](docs/sentinel-workspace.md) adds progressive entity/attack graphs, supported endpoint process inspection and a bounded KQL-style editor to the same Chapter 1 case. Its optional save extension needs no database migration and preserves the once-only 150-XP reward.

# CyberGuard Chronicles

Cybersecurity learning RPG with 19 chapters, agent profiles, XP, badges and Supabase accounts/progress. Chapter 1 now adds a practical SOC phishing investigation after its original missions.

```sh
npm ci
npm run dev
npm test
npm run test:e2e
```

Use Node 24. Configure `SUPABASE_URL` and `SUPABASE_SECRET_KEY` on the server only. No Anthropic key is required. Browser tests use isolated identity/progress fixtures and a disposable PostgreSQL database; see [simulation setup, compatibility, security and verification](docs/soc-investigation.md) before applying the additive migration or releasing.

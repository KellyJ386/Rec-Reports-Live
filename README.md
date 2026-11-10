# Rec Reports

An operations platform for recreation facilities: communications, tasks, checklists, incidents, and the facility and staff schedules, built for multi-facility organizations.

Status: Phase 1 (platform foundation) in progress. See [docs/ROADMAP.md](docs/ROADMAP.md).

Start with [CLAUDE.md](CLAUDE.md), then [docs/PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Getting started

Requires Node 22 (see `.nvmrc`) and npm.

```bash
npm ci
cp .env.example .env.local   # then fill in the Supabase keys
npm run dev                  # http://localhost:3000
```

| Command                               | What it does                                                    |
| ------------------------------------- | --------------------------------------------------------------- |
| `npm run lint` / `typecheck` / `test` | ESLint (includes the domain boundary rule), TypeScript, Vitest  |
| `npm run build`                       | Production build                                                |
| `npm run format` / `format:check`     | Prettier                                                        |
| `npm run db:test:local`               | Run migrations and pgTAP tests on a plain local Postgres        |

The database uses the Supabase CLI: `supabase start` for the local stack and `supabase test db` for the pgTAP tests (CI runs the latter). Config is in `supabase/config.toml`. Code layout and the domain boundary rule are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Never commit `.env*` files or real keys.

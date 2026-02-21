# Thief Watcher (Next.js)

Professional blockchain incident-response webapp for tracing wallet theft flows, monitoring suspect activity, and generating CEX escalation bundles.

## Stack
- Next.js 15 (App Router, TypeScript)
- Dynamic API routes for chain tracing and OSINT enrichment
- Client-side command center UI + interactive trace graph canvas
- JSZip for one-click evidence bundle downloads

## Core Features
- Live watch state for suspect wallet (nonce, MATIC, USDC, USDC.e)
- Event stream with filters (`severity`, `direction`, `token`, `search`)
- Intel tagging system (default + custom tags)
- Address profiler (balances, transfer counterparties, Polymarket hinting)
- Multi-hop trace graph builder with CEX/DEX/mixer/bridge exposure summary
- Recovery playbook generation
- Webhook alert routing for warning/critical/error events
- CEX escalation packet generator with downloadable ZIP:
  - `packet.json`
  - `trace_edges.csv`
  - `addresses.csv`
  - `timeline.csv`
  - `cex_request_template.md`

## Local Run
```bash
cd /Users/kevinlin/Downloads/thief_watcher
npm install
npm run dev
```

Open: `http://127.0.0.1:3000`

## Production Build
```bash
npm run build
npm run start
```

## API Surface
- `GET /api/status`
- `GET /api/health`
- `GET /api/events?limit=200&severity=critical&direction=out&token=USDC&q=0xabc`
- `GET /api/tags?q=relay&type=bridge`
- `POST /api/tags`
- `GET|POST /api/profile`
- `POST /api/trace`
- `GET /api/playbook`
- `GET /api/state`
- `POST /api/control/start`
- `POST /api/control/stop`
- `POST /api/control/tick`
- `POST /api/webhook`
- `POST /api/escalation-packet`

## Vercel Deploy (CLI)
```bash
vercel whoami
vercel link
vercel deploy
vercel deploy --prod
```

## Notes
- This repository is now fully Next.js/TypeScript (legacy Python watcher files removed).
- Runtime state is stored in `.tw_data` locally.
- Durable persistence is supported via Upstash Redis:
  - `UPSTASH_REDIS_REST_URL`
  - `UPSTASH_REDIS_REST_TOKEN`
  - optional: `THIEF_WATCHER_REDIS_PREFIX` (default: `thief_watcher`)
- Without Redis env vars, local JSON file fallback is used.
- Heavy endpoints (`/api/profile`, `/api/trace`, `/api/escalation-packet`) are configured for longer execution windows.

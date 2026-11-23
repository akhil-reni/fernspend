# Fernspend

Expense management for growing teams: receipt capture, approval routing and signed webhooks.

Runs on Cloudflare Workers with D1.

```bash
npm install
npx wrangler d1 execute fernspend-db --local --file=schema.sql
npm run dev
```

Secrets (`wrangler secret put`): `SESSION_SECRET`, `WEBHOOK_SIGNING_KEY` (PKCS#8 PEM), `FLAG_CONTRACT`.

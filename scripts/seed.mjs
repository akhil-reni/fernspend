// Generates seed.local.sql from .lab/secrets.env. Usage: node scripts/seed.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, randomUUID } from 'node:crypto';

const env = Object.fromEntries(
  readFileSync('.lab/secrets.env', 'utf8').split('\n').filter(Boolean).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);
const b64u = (b) => b.toString('base64url');
const hash = (pw) => { const salt = randomBytes(16); return `pbkdf2$100000$${b64u(salt)}$${b64u(pbkdf2Sync(pw, salt, 100000, 32, 'sha256'))}`; };
const q = (s) => (s === null ? 'NULL' : `'${String(s).replace(/'/g, "''")}'`);

const org = env.ACME_ORG_ID;
const people = [
  [env.ACME_OWNER_ID, 'ingrid.halvorsen@halvorsen-freight.com', 'Ingrid Halvorsen', 'owner', env.ACME_OWNER_PW],
  [randomUUID(), 'marcus.oyelaran@halvorsen-freight.com', 'Marcus Oyelaran', 'admin', randomBytes(18).toString('hex')],
  [randomUUID(), 'sofie.lindqvist@halvorsen-freight.com', 'Sofie Lindqvist', 'member', randomBytes(18).toString('hex')],
  [randomUUID(), 'tomas.reyes@halvorsen-freight.com', 'Tomás Reyes', 'member', randomBytes(18).toString('hex')],
];
const out = [];
out.push('DELETE FROM webhook_deliveries; DELETE FROM webhooks; DELETE FROM integration_secrets; DELETE FROM expenses; DELETE FROM memberships; DELETE FROM orgs; DELETE FROM users;');
out.push(`INSERT INTO orgs (id, name, slug, plan, seats, sso_domain, sso_provider, created_at) VALUES (${q(org)}, 'Halvorsen Freight', 'halvorsen-freight', 'enterprise', 1500, 'halvorsen-freight.com', 'okta', '2024-02-11 09:14:00');`);
for (const [id, email, name, role, pw] of people) {
  out.push(`INSERT INTO users (id, email, name, password_hash, created_at) VALUES (${q(id)}, ${q(email)}, ${q(name)}, ${q(hash(pw))}, '2024-02-11 09:20:00');`);
  out.push(`INSERT INTO memberships (user_id, org_id, role, created_at) VALUES (${q(id)}, ${q(org)}, ${q(role)}, '2024-02-11 09:20:00');`);
}
const merchants = [['Maersk Line', 'Freight', 1284000], ['Shell Fleet', 'Fuel', 48211], ['Scandic Hotels', 'Lodging', 31900], ['SAS Scandinavian', 'Travel', 112450], ['Circle K', 'Fuel', 9120], ['Hertz', 'Ground transport', 27640], ['Espresso House', 'Meals', 1890], ['Samsara', 'Software', 249900]];
for (let i = 0; i < 40; i++) {
  const [m, c, a] = merchants[i % merchants.length];
  const who = people[1 + (i % 3)][0];
  const d = new Date(Date.UTC(2026, 10, 20) - i * 2 * 86400000).toISOString().slice(0, 10);
  const st = ['approved', 'pending', 'reimbursed', 'approved', 'rejected'][i % 5];
  out.push(`INSERT INTO expenses (id, org_id, user_id, merchant, category, amount_cents, status, spent_at) VALUES (${q(randomUUID())}, ${q(org)}, ${q(who)}, ${q(m)}, ${q(c)}, ${a + i * 37}, ${q(st)}, ${q(d)});`);
}
out.push(`INSERT INTO integration_secrets (id, org_id, provider, label, value) VALUES (${q(randomUUID())}, NULL, 'stripe', 'Platform payouts (restricted key)', ${q(env.FLAG_SQLI)});`);
out.push(`INSERT INTO integration_secrets (id, org_id, provider, label, value) VALUES (${q(randomUUID())}, ${q(org)}, 'netsuite', 'ERP sync token', ${q('ns_' + randomBytes(24).toString('hex'))});`);
out.push(`INSERT INTO integration_secrets (id, org_id, provider, label, value) VALUES (${q(randomUUID())}, NULL, 'postmark', 'Transactional email', ${q('pm_' + randomBytes(20).toString('hex'))});`);
writeFileSync('seed.local.sql', out.join('\n') + '\n');
console.log('wrote seed.local.sql');

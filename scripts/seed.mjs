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
out.push('DELETE FROM api_tokens; DELETE FROM reports; DELETE FROM invites; DELETE FROM comments; DELETE FROM receipts; DELETE FROM wallets; DELETE FROM webhook_deliveries; DELETE FROM webhooks; DELETE FROM integration_secrets; DELETE FROM expenses; DELETE FROM memberships; DELETE FROM orgs; DELETE FROM users;');
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
// ---- additional tenants
const addOrg = (id, name, slug, plan, seats, notes, created) =>
  out.push(`INSERT INTO orgs (id, name, slug, plan, seats, internal_notes, created_at) VALUES (${q(id)}, ${q(name)}, ${q(slug)}, ${q(plan)}, ${seats}, ${q(notes)}, ${q(created)});`);
const addUser = (id, email, name, pw, org, role) => {
  out.push(`INSERT INTO users (id, email, name, password_hash, created_at) VALUES (${q(id)}, ${q(email)}, ${q(name)}, ${q(hash(pw))}, '2024-06-01 10:00:00');`);
  out.push(`INSERT INTO memberships (user_id, org_id, role, created_at) VALUES (${q(id)}, ${q(org)}, ${q(role)}, '2024-06-01 10:00:00');`);
  out.push(`INSERT INTO wallets (user_id, balance_cents) VALUES (${q(id)}, 0);`);
};
const addExp = (org, user, merchant, cat, cents, status, date, note = null) =>
  out.push(`INSERT INTO expenses (id, org_id, user_id, merchant, category, amount_cents, status, spent_at, note) VALUES (${q(randomUUID())}, ${q(org)}, ${q(user)}, ${q(merchant)}, ${q(cat)}, ${cents}, ${q(status)}, ${q(date)}, ${q(note)});`);
for (const [id] of people) out.push(`INSERT INTO wallets (user_id, balance_cents) VALUES (${q(id)}, 0);`);

// Brightwater Labs: CFO account (password reset target)
const bw = randomUUID(), bwCfo = randomUUID(), bwEng = randomUUID();
addOrg(bw, 'Brightwater Labs', 'brightwater-labs', 'growth', 40, null, '2024-05-02 08:00:00');
addUser(bwCfo, 'helena.marsh@brightwaterlabs.io', 'Helena Marsh', randomBytes(18).toString('hex'), bw, 'owner');
addUser(bwEng, 'devon.park@brightwaterlabs.io', 'Devon Park', randomBytes(18).toString('hex'), bw, 'member');
addExp(bw, bwCfo, 'Wilson Sonsini', 'Legal', 1850000, 'approved', '2026-11-04', `Series B closing — wire ref ${env.FLAG_RESET}`);
addExp(bw, bwEng, 'AWS', 'Software', 412300, 'pending', '2026-11-08');
addExp(bw, bwEng, 'Lyft', 'Ground transport', 3410, 'approved', '2026-11-10');

// Tessellate: ops user with a weak password
const ts = randomUUID(), tsOps = randomUUID();
addOrg(ts, 'Tessellate', 'tessellate', 'starter', 5, null, '2025-01-14 12:00:00');
addUser(tsOps, 'ops@tessellate.dev', 'Tessellate Ops', 'Tessellate2025!', ts, 'owner');
addExp(ts, tsOps, 'Hetzner', 'Software', 8900, 'approved', '2026-11-01', `Prod box — root recovery code ${env.FLAG_BRUTE}`);
addExp(ts, tsOps, 'WeWork', 'Office', 45000, 'pending', '2026-11-03');

// Meridian Health: shared board report + internal notes
const md = randomUUID(), mdOwner = randomUUID();
addOrg(md, 'Meridian Health', 'meridian-health', 'enterprise', 600, `Escalation contact for renewal — ref ${env.FLAG_ADMIN}`, '2024-03-20 15:00:00');
addUser(mdOwner, 'r.okafor@meridianhealth.org', 'Rachel Okafor', randomBytes(18).toString('hex'), md, 'owner');
addExp(md, mdOwner, 'Epic Systems', 'Software', 9800000, 'approved', '2026-10-15');
addExp(md, mdOwner, 'Hilton Chicago', 'Lodging', 128000, 'reimbursed', '2026-10-21');
out.push(`INSERT INTO reports (id, org_id, title, period_from, period_to, created_by, share_sig, created_at) VALUES (1, ${q(halvorsenOrg())}, 'Q3 fleet spend', '2026-07-01', '2026-09-30', ${q(env.ACME_OWNER_ID)}, NULL, '2026-10-02 09:00:00');`);
out.push(`INSERT INTO reports (id, org_id, title, period_from, period_to, created_by, share_sig, created_at) VALUES (2, ${q(md)}, ${q('Board pack — ' + env.FLAG_SHARE)}, '2026-10-01', '2026-10-31', ${q(mdOwner)}, ${q(randomBytes(16).toString('hex'))}, '2026-11-02 18:00:00');`);
out.push(`INSERT INTO reports (id, org_id, title, period_from, period_to, created_by, share_sig, created_at) VALUES (3, ${q(bw)}, 'October close', '2026-10-01', '2026-10-31', ${q(bwCfo)}, NULL, '2026-11-01 11:00:00');`);

// Receipts (low sequential ids) attached to Halvorsen expenses
const svg = (lines) => Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="360" height="${60 + lines.length * 22}"><rect width="100%" height="100%" fill="#fff"/>${lines.map((l, i) => `<text x="20" y="${40 + i * 22}" font-family="monospace" font-size="14">${l}</text>`).join('')}</svg>`).toString('base64');
const halExp = randomUUID();
out.push(`INSERT INTO expenses (id, org_id, user_id, merchant, category, amount_cents, status, spent_at) VALUES (${q(halExp)}, ${q(halvorsenOrg())}, ${q(env.ACME_OWNER_ID)}, 'Nordea Corporate Card', 'Bank fees', 250000, 'approved', '2026-11-12');`);
const rc = [['receipt-scandic.svg', ['SCANDIC HOTELS OSLO', 'Room 412  2 nights', 'TOTAL NOK 3,190.00']],
            ['nordea-card-statement.svg', ['NORDEA CORPORATE CARD', 'Card ending 4471', `Statement ref ${env.FLAG_RECEIPT}`]],
            ['receipt-circlek.svg', ['CIRCLE K DRAMMEN', 'Diesel 82.4 L', 'TOTAL NOK 1,612.00']]];
rc.forEach(([name, lines], i) => out.push(`INSERT INTO receipts (id, expense_id, org_id, filename, content_type, data_b64, size) VALUES (${i + 1}, ${q(halExp)}, ${q(halvorsenOrg())}, ${q(name)}, 'image/svg+xml', ${q(svg(lines))}, ${Buffer.from(svg(lines), 'base64').length});`));
out.push(`UPDATE sqlite_sequence SET seq = 1000 WHERE name = 'receipts';`);
out.push(`INSERT INTO sqlite_sequence (name, seq) SELECT 'receipts', 1000 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'receipts');`);
out.push(`UPDATE sqlite_sequence SET seq = 40 WHERE name = 'reports';`);
out.push(`INSERT INTO sqlite_sequence (name, seq) SELECT 'reports', 40 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'reports');`);
function halvorsenOrg() { return org; }

writeFileSync('seed.local.sql', out.join('\n') + '\n');
console.log('wrote seed.local.sql');

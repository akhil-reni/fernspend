import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { AppBindings, OrgRow, UserRow } from './types';
import { hashPassword, verifyPassword, uuid, sha256Hex } from './lib/crypto';
import { publicJwks, signSession, signWebhook, verifyToken } from './lib/jwt';
import { assertPublicDestination, deliver, EgressPolicyError } from './lib/egress';

const app = new Hono<AppBindings>();
const COOKIE = 'fs_session';

app.use('*', async (c, next) => {
  await next();
  c.header('x-content-type-options', 'nosniff');
  c.header('referrer-policy', 'strict-origin-when-cross-origin');
  c.header('x-frame-options', 'DENY');
});

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: 'internal_error', message: 'Something went wrong. Please try again.' }, 500);
});

const bad = (c: any, message: string, status = 400) => c.json({ error: 'bad_request', message }, status);

/* ------------------------------------------------------------------ meta */

app.get('/api/v1/health', (c) => c.json({ status: 'ok', version: '2.14.0' }));
app.get('/.well-known/jwks.json', async (c) => c.json(await publicJwks(c.env)));
app.get('/api/v1/integrations/signing-key.pem', (c) =>
  c.body(c.env.WEBHOOK_PUBLIC_KEY, 200, { 'content-type': 'application/x-pem-file' }),
);

/* ------------------------------------------------------------------ auth */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function issue(c: any, user: UserRow, orgId: string, role: string) {
  const token = await signSession(c.env, { sub: user.id, org: orgId, role, email: user.email });
  setCookie(c, COOKIE, token, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 60 * 60 * 8 });
  return token;
}

const SAMPLE = [
  ['Delta Air Lines', 'Travel', 48230],
  ['Marriott Downtown', 'Lodging', 61400],
  ['Uber', 'Ground transport', 2875],
  ['Blue Bottle Coffee', 'Meals', 1460],
  ['Figma', 'Software', 4500],
  ['Staples', 'Office supplies', 8999],
  ['Sweetgreen', 'Meals', 3120],
];

app.post('/api/v1/auth/signup', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const email = String(body.email ?? '').trim().toLowerCase();
  const name = String(body.name ?? '').trim().slice(0, 80);
  const company = String(body.company ?? '').trim().slice(0, 80) || `${name || 'My'}'s team`;
  const password = String(body.password ?? '');
  if (!EMAIL_RE.test(email)) return bad(c, 'Enter a valid work email.');
  if (!name) return bad(c, 'Enter your name.');
  if (password.length < 10) return bad(c, 'Password must be at least 10 characters.');

  const sso = await c.env.DB.prepare('SELECT id FROM orgs WHERE sso_domain = ?').bind(email.split('@')[1]).first();
  if (sso) return bad(c, 'Your company uses single sign-on. Use "Sign in with SSO" instead.', 409);
  if (await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first())
    return bad(c, 'An account with this email already exists.', 409);

  const userId = uuid();
  const orgId = uuid();
  const slug = `${company.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'team'}-${orgId.slice(0, 6)}`;
  const stmts = [
    c.env.DB.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').bind(userId, email, name, await hashPassword(password)),
    c.env.DB.prepare("INSERT INTO orgs (id, name, slug, plan, seats) VALUES (?, ?, ?, 'starter', 5)").bind(orgId, company, slug),
    c.env.DB.prepare("INSERT INTO memberships (user_id, org_id, role) VALUES (?, ?, 'owner')").bind(userId, orgId),
  ];
  SAMPLE.forEach(([merchant, category, cents], i) => {
    const d = new Date(Date.now() - (i * 3 + 1) * 86400000).toISOString().slice(0, 10);
    const status = i % 3 === 0 ? 'approved' : i % 3 === 1 ? 'pending' : 'reimbursed';
    stmts.push(
      c.env.DB.prepare('INSERT INTO expenses (id, org_id, user_id, merchant, category, amount_cents, status, spent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(uuid(), orgId, userId, merchant, category, cents, status, d),
    );
  });
  await c.env.DB.batch(stmts);
  const user = (await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first()) as UserRow;
  await issue(c, user, orgId, 'owner');
  return c.json({ ok: true }, 201);
});

app.post('/api/v1/auth/login', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const email = String(body.email ?? '').trim().toLowerCase();
  const password = String(body.password ?? '');
  const user = (await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first()) as UserRow | null;
  const ok = user ? await verifyPassword(password, user.password_hash) : await hashPassword(password).then(() => false);
  if (!user || !ok) return c.json({ error: 'invalid_credentials', message: 'Incorrect email or password.' }, 401);
  const m = (await c.env.DB.prepare('SELECT org_id, role FROM memberships WHERE user_id = ? ORDER BY created_at LIMIT 1').bind(user.id).first()) as
    | { org_id: string; role: string }
    | null;
  if (!m) return c.json({ error: 'no_workspace', message: 'Your account is not attached to a workspace.' }, 403);
  await issue(c, user, m.org_id, m.role);
  return c.json({ ok: true });
});

app.post('/api/v1/auth/logout', (c) => {
  deleteCookie(c, COOKIE, { path: '/' });
  return c.json({ ok: true });
});

app.post('/api/v1/auth/sso/discover', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const email = String(body.email ?? '').trim().toLowerCase();
  const domain = email.includes('@') ? email.split('@')[1] : email;
  const org = (await c.env.DB.prepare('SELECT id, name, sso_provider FROM orgs WHERE sso_domain = ?').bind(domain).first()) as
    | Pick<OrgRow, 'id' | 'name' | 'sso_provider'>
    | null;
  if (!org) return c.json({ sso: false });
  return c.json({
    sso: true,
    organization: { id: org.id, name: org.name },
    provider: org.sso_provider,
    authorize_url: `/auth/sso/start?organization=${org.id}`,
  });
});

app.get('/auth/sso/start', (c) => {
  const q = new URLSearchParams({ error: 'temporarily_unavailable', organization: c.req.query('organization') ?? '' });
  return c.redirect(`/login?${q}`, 302);
});

/* -------------------------------------------------------------- session */

const authed = new Hono<AppBindings>();

authed.use('*', async (c, next) => {
  const header = c.req.header('authorization');
  const token = header?.startsWith('Bearer ') ? header.slice(7) : getCookie(c, COOKIE);
  const claims = token ? await verifyToken(c.env, token) : null;
  if (!claims) return c.json({ error: 'unauthorized', message: 'Please sign in.' }, 401);
  const user = (await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(claims.sub).first()) as UserRow | null;
  if (!user) return c.json({ error: 'unauthorized', message: 'Please sign in.' }, 401);
  c.set('session', claims);
  c.set('user', user);
  await next();
});

const isManager = (role: string) => role === 'owner' || role === 'admin';

authed.get('/me', async (c) => {
  const s = c.get('session');
  const u = c.get('user');
  const org = (await c.env.DB.prepare('SELECT id, name, slug, plan, seats FROM orgs WHERE id = ?').bind(s.org).first()) as OrgRow | null;
  if (!org) return c.json({ error: 'not_found', message: 'Workspace not found.' }, 404);
  return c.json({ user: { id: u.id, email: u.email, name: u.name }, organization: org, role: s.role });
});

/* expenses */

const SORTABLE = new Set(['spent_at', 'merchant', 'category', 'amount_cents', 'status', 'created_at']);

authed.get('/expenses', async (c) => {
  const s = c.get('session');
  const q = (c.req.query('q') ?? '').slice(0, 100);
  const status = c.req.query('status') ?? '';
  const page = Math.max(1, Math.min(500, parseInt(c.req.query('page') ?? '1', 10) || 1));
  const size = 25;

  const sort = c.req.query('sort') ?? 'spent_at:desc';
  const sep = sort.indexOf(':');
  let column = sep === -1 ? sort : sort.slice(0, sep);
  let direction = sep === -1 ? 'desc' : sort.slice(sep + 1);
  if (!SORTABLE.has(column)) column = 'spent_at';
  if (!/^(asc|desc)/i.test(direction)) direction = 'desc';

  const where = ['e.org_id = ?'];
  const binds: unknown[] = [s.org];
  if (q) {
    where.push('(e.merchant LIKE ? OR e.category LIKE ? OR e.note LIKE ?)');
    binds.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (['pending', 'approved', 'rejected', 'reimbursed'].includes(status)) {
    where.push('e.status = ?');
    binds.push(status);
  }

  const sql = `SELECT e.id, e.merchant, e.category, e.amount_cents, e.currency, e.status, e.note, e.spent_at, u.name AS submitted_by
    FROM expenses e JOIN users u ON u.id = e.user_id
    WHERE ${where.join(' AND ')}
    ORDER BY ${column} ${direction}
    LIMIT ${size} OFFSET ${(page - 1) * size}`;

  const [rows, total] = await Promise.all([
    c.env.DB.prepare(sql).bind(...binds).all(),
    c.env.DB.prepare(`SELECT COUNT(*) AS n, COALESCE(SUM(amount_cents),0) AS cents FROM expenses e WHERE ${where.join(' AND ')}`).bind(...binds).first<{ n: number; cents: number }>(),
  ]);
  return c.json({ data: rows.results, page, page_size: size, total: total?.n ?? 0, total_cents: total?.cents ?? 0 });
});

authed.post('/expenses', async (c) => {
  const s = c.get('session');
  const body = await c.req.json().catch(() => ({}));
  const merchant = String(body.merchant ?? '').trim().slice(0, 120);
  const category = String(body.category ?? 'Other').trim().slice(0, 60);
  const note = String(body.note ?? '').trim().slice(0, 500) || null;
  const amount = Math.round(Number(body.amount) * 100);
  const spentAt = /^\d{4}-\d{2}-\d{2}$/.test(String(body.spent_at)) ? String(body.spent_at) : new Date().toISOString().slice(0, 10);
  if (!merchant) return bad(c, 'Merchant is required.');
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) return bad(c, 'Enter a valid amount.');
  const id = uuid();
  await c.env.DB.prepare('INSERT INTO expenses (id, org_id, user_id, merchant, category, amount_cents, note, spent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, s.org, s.sub, merchant, category, amount, note, spentAt)
    .run();
  c.executionCtx.waitUntil(fanout(c, s.org, 'expense.created', { id, merchant, category, amount_cents: amount, spent_at: spentAt }));
  return c.json({ id }, 201);
});

authed.patch('/expenses/:id', async (c) => {
  const s = c.get('session');
  if (!isManager(s.role)) return c.json({ error: 'forbidden', message: 'Only workspace admins can review expenses.' }, 403);
  const body = await c.req.json().catch(() => ({}));
  const status = String(body.status ?? '');
  if (!['approved', 'rejected', 'reimbursed'].includes(status)) return bad(c, 'Invalid status.');
  const r = await c.env.DB.prepare('UPDATE expenses SET status = ? WHERE id = ? AND org_id = ?').bind(status, c.req.param('id'), s.org).run();
  if (!r.meta.changes) return c.json({ error: 'not_found', message: 'Expense not found.' }, 404);
  c.executionCtx.waitUntil(fanout(c, s.org, `expense.${status}`, { id: c.req.param('id'), status }));
  return c.json({ ok: true });
});

/* organization */

authed.get('/org/members', async (c) => {
  const s = c.get('session');
  const rows = await c.env.DB.prepare(
    'SELECT u.name, u.email, m.role, m.created_at FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? ORDER BY m.created_at',
  ).bind(s.org).all();
  return c.json({ data: rows.results });
});

authed.patch('/org', async (c) => {
  const s = c.get('session');
  if (s.role !== 'owner') return c.json({ error: 'forbidden', message: 'Only the workspace owner can change settings.' }, 403);
  const body = await c.req.json().catch(() => ({}));
  const name = String(body.name ?? '').trim().slice(0, 80);
  if (!name) return bad(c, 'Name is required.');
  await c.env.DB.prepare('UPDATE orgs SET name = ? WHERE id = ?').bind(name, s.org).run();
  return c.json({ ok: true });
});

authed.get('/org/billing', async (c) => {
  const s = c.get('session');
  if (s.role !== 'owner') return c.json({ error: 'forbidden', message: 'Billing is visible to the workspace owner only.' }, 403);
  const org = (await c.env.DB.prepare('SELECT plan, seats FROM orgs WHERE id = ?').bind(s.org).first()) as OrgRow | null;
  if (!org) return c.json({ error: 'not_found' }, 404);
  const used = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM memberships WHERE org_id = ?').bind(s.org).first<{ n: number }>();
  const base = { plan: org.plan, seats: org.seats, seats_used: used?.n ?? 0 };
  if (org.plan !== 'enterprise') return c.json({ ...base, price_per_seat_cents: 800, interval: 'month' });
  return c.json({
    ...base,
    interval: 'year',
    contract: { reference: c.env.FLAG_CONTRACT, renews_on: '2027-03-31', account_manager: 'Priya Natarajan' },
  });
});

/* webhooks (enterprise) */

async function requireEnterpriseOwner(c: any) {
  const s = c.get('session');
  if (s.role !== 'owner') return c.json({ error: 'forbidden', message: 'Only the workspace owner can manage webhooks.' }, 403);
  const org = await c.env.DB.prepare('SELECT plan FROM orgs WHERE id = ?').bind(s.org).first();
  if (org?.plan !== 'enterprise') return c.json({ error: 'plan_required', message: 'Webhooks are available on the Enterprise plan.' }, 402);
  return null;
}

authed.get('/webhooks', async (c) => {
  const deny = await requireEnterpriseOwner(c);
  if (deny) return deny;
  const rows = await c.env.DB.prepare('SELECT id, url, events, active, created_at FROM webhooks WHERE org_id = ? ORDER BY created_at DESC').bind(c.get('session').org).all();
  return c.json({ data: rows.results });
});

authed.post('/webhooks', async (c) => {
  const deny = await requireEnterpriseOwner(c);
  if (deny) return deny;
  const body = await c.req.json().catch(() => ({}));
  try {
    await assertPublicDestination(String(body.url ?? ''));
  } catch (e) {
    if (e instanceof EgressPolicyError) return bad(c, e.message);
    throw e;
  }
  const id = uuid();
  await c.env.DB.prepare('INSERT INTO webhooks (id, org_id, url, events) VALUES (?, ?, ?, ?)')
    .bind(id, c.get('session').org, String(body.url), 'expense.*')
    .run();
  return c.json({ id }, 201);
});

authed.delete('/webhooks/:id', async (c) => {
  const deny = await requireEnterpriseOwner(c);
  if (deny) return deny;
  await c.env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND org_id = ?').bind(c.req.param('id'), c.get('session').org).run();
  return c.json({ ok: true });
});

authed.post('/webhooks/:id/test', async (c) => {
  const deny = await requireEnterpriseOwner(c);
  if (deny) return deny;
  const hook = await c.env.DB.prepare('SELECT * FROM webhooks WHERE id = ? AND org_id = ?').bind(c.req.param('id'), c.get('session').org).first<any>();
  if (!hook) return c.json({ error: 'not_found' }, 404);
  const result = await send(c, hook, 'ping', { zen: 'Keep receipts. Keep calm.' });
  return c.json(result);
});

authed.get('/webhooks/:id/deliveries', async (c) => {
  const deny = await requireEnterpriseOwner(c);
  if (deny) return deny;
  const rows = await c.env.DB.prepare(
    `SELECT d.id, d.event, d.status_code, d.duration_ms, d.error, d.created_at FROM webhook_deliveries d
     JOIN webhooks w ON w.id = d.webhook_id WHERE w.id = ? AND w.org_id = ? ORDER BY d.created_at DESC LIMIT 20`,
  ).bind(c.req.param('id'), c.get('session').org).all();
  return c.json({ data: rows.results });
});

async function send(c: any, hook: any, event: string, data: unknown) {
  const payload = JSON.stringify({ id: uuid(), event, created_at: new Date().toISOString(), data });
  const signature = await signWebhook(c.env, { iat: Math.floor(Date.now() / 1000), body_sha256: await sha256Hex(payload) });
  let status: number | null = null;
  let error: string | null = null;
  let duration = 0;
  try {
    const r = await deliver(hook.url, {
      headers: { 'content-type': 'application/json', 'user-agent': 'Fernspend-Webhooks/2.14', 'fernspend-signature': signature },
      body: payload,
    });
    status = r.status;
    duration = r.durationMs;
  } catch (e) {
    error = e instanceof EgressPolicyError ? e.message : 'Delivery failed';
  }
  await c.env.DB.prepare('INSERT INTO webhook_deliveries (id, webhook_id, event, status_code, error, duration_ms) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(uuid(), hook.id, event, status, error, duration)
    .run();
  return { delivered: status !== null && status < 300, status_code: status, error, duration_ms: duration };
}

async function fanout(c: any, orgId: string, event: string, data: unknown) {
  const hooks = await c.env.DB.prepare('SELECT * FROM webhooks WHERE org_id = ? AND active = 1').bind(orgId).all();
  await Promise.all((hooks.results ?? []).map((h: any) => send(c, h, event, data).catch(() => null)));
}

app.route('/api/v1', authed);

app.all('/api/*', (c) => c.json({ error: 'not_found', message: 'No such endpoint.' }, 404));
app.all('*', async (c) => {
  const res = await c.env.ASSETS.fetch(c.req.raw);
  return new Response(res.body, res);
});

export default app;

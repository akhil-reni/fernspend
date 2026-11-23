import type { Hono } from 'hono';
import type { AppBindings } from '../types';
import { hashPassword, sha256Hex, uuid, b64urlEncode } from '../lib/crypto';
import { signSession } from '../lib/jwt';
import { setCookie } from 'hono/cookie';

type App = Hono<AppBindings>;
const bad = (c: any, message: string, status = 400) => c.json({ error: 'bad_request', message }, status);
const forbidden = (c: any, message: string) => c.json({ error: 'forbidden', message }, 403);
const notFound = (c: any, message = 'Not found.') => c.json({ error: 'not_found', message }, 404);
const isManager = (role: string) => role === 'owner' || role === 'admin';
const ROLES = ['owner', 'admin', 'member'];

const RECEIPT_EXT = ['png', 'jpg', 'jpeg', 'gif', 'pdf', 'heic', 'webp'];

function toB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export function registerPublicRoutes(app: App) {
  app.get('/api/v1/public/reports/:id', async (c) => {
    const sig = c.req.query('sig') ?? '';
    const r = await c.env.DB.prepare(
      'SELECT r.*, o.name AS org_name, u.email AS created_by_email, u.name AS created_by_name FROM reports r JOIN orgs o ON o.id = r.org_id JOIN users u ON u.id = r.created_by WHERE r.id = ?',
    ).bind(c.req.param('id')).first<any>();
    if (!r || !r.share_sig || !r.share_sig.startsWith(sig)) return notFound(c, 'This report link is invalid or has been revoked.');
    const rows = await c.env.DB.prepare(
      `SELECT e.spent_at, e.merchant, e.category, e.amount_cents, e.status, u.name AS submitted_by FROM expenses e JOIN users u ON u.id = e.user_id
       WHERE e.org_id = ? AND e.spent_at BETWEEN ? AND ? ORDER BY e.spent_at`,
    ).bind(r.org_id, r.period_from, r.period_to).all();
    return c.json({ report: r, expenses: rows.results });
  });

  app.get('/api/v1/invites/:token', async (c) => {
    const inv = await c.env.DB.prepare(
      'SELECT i.email, i.role, i.accepted, o.name AS org_name, u.name AS invited_by FROM invites i JOIN orgs o ON o.id = i.org_id JOIN users u ON u.id = i.invited_by WHERE i.token = ?',
    ).bind(c.req.param('token')).first();
    if (!inv) return notFound(c, 'This invitation is invalid.');
    return c.json(inv);
  });
}

export function registerWorkspaceRoutes(authed: App) {
  /* ---------------------------------------------------------- expenses */

  authed.get('/expenses/export.csv', async (c) => {
    const s = c.get('session');
    const rows = await c.env.DB.prepare(
      'SELECT e.spent_at, e.merchant, e.category, e.amount_cents, e.currency, e.status, e.note, u.name AS submitted_by FROM expenses e JOIN users u ON u.id = e.user_id WHERE e.org_id = ? ORDER BY e.spent_at DESC',
    ).bind(s.org).all<any>();
    const q = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const lines = [['Date', 'Merchant', 'Category', 'Amount', 'Currency', 'Status', 'Note', 'Submitted by'].join(',')];
    for (const r of rows.results) lines.push([r.spent_at, r.merchant, r.category, (r.amount_cents / 100).toFixed(2), r.currency, r.status, r.note, r.submitted_by].map(q).join(','));
    return c.body(lines.join('\r\n'), 200, { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': 'attachment; filename="expenses.csv"' });
  });

  authed.post('/expenses/bulk', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can review expenses.');
    const body = await c.req.json().catch(() => ({}));
    const ids: string[] = Array.isArray(body.ids) ? body.ids.slice(0, 100).map(String) : [];
    const status = String(body.status ?? '');
    if (!['approved', 'rejected'].includes(status) || ids.length === 0) return bad(c, 'Select expenses and a status.');
    const res = await c.env.DB.batch(ids.map((id) => c.env.DB.prepare("UPDATE expenses SET status = ? WHERE id = ? AND org_id = ? AND status = 'pending'").bind(status, id, s.org)));
    return c.json({ updated: res.reduce((n, r) => n + (r.meta.changes ?? 0), 0) });
  });

  authed.get('/expenses/:id', async (c) => {
    const e = await c.env.DB.prepare(
      'SELECT e.*, u.name AS submitted_by, u.email AS submitted_by_email FROM expenses e JOIN users u ON u.id = e.user_id WHERE e.id = ?',
    ).bind(c.req.param('id')).first();
    if (!e) return notFound(c, 'Expense not found.');
    const receipts = await c.env.DB.prepare('SELECT id, filename, content_type, size, created_at FROM receipts WHERE expense_id = ?').bind(c.req.param('id')).all();
    return c.json({ ...e, receipts: receipts.results });
  });

  authed.patch('/expenses/:id/details', async (c) => {
    const s = c.get('session');
    const e = await c.env.DB.prepare('SELECT * FROM expenses WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).first<any>();
    if (!e) return notFound(c, 'Expense not found.');
    if (e.user_id !== s.sub) return forbidden(c, 'You can only edit expenses you submitted.');
    const body = await c.req.json().catch(() => ({}));
    const merchant = body.merchant !== undefined ? String(body.merchant).trim().slice(0, 120) : e.merchant;
    const note = body.note !== undefined ? String(body.note).trim().slice(0, 500) : e.note;
    const amount = body.amount !== undefined ? Math.round(parseFloat(body.amount) * 100) : e.amount_cents;
    if (!merchant || !Number.isFinite(amount)) return bad(c, 'Check the merchant and amount.');
    await c.env.DB.prepare('UPDATE expenses SET merchant = ?, note = ?, amount_cents = ? WHERE id = ?').bind(merchant, note, amount, e.id).run();
    return c.json({ ok: true });
  });

  authed.post('/expenses/:id/reimburse', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can issue reimbursements.');
    const e = await c.env.DB.prepare('SELECT * FROM expenses WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).first<any>();
    if (!e) return notFound(c, 'Expense not found.');
    if (e.status !== 'approved') return bad(c, 'Only approved expenses can be reimbursed.', 409);
    const payee = await c.env.DB.prepare('SELECT name FROM users WHERE id = ?').bind(e.user_id).first<{ name: string }>();
    await c.env.DB.prepare('INSERT INTO comments (id, expense_id, user_id, body) VALUES (?, ?, ?, ?)')
      .bind(uuid(), e.id, s.sub, `Reimbursement of ${(e.amount_cents / 100).toFixed(2)} ${e.currency} issued to ${payee?.name ?? 'submitter'}.`)
      .run();
    await c.env.DB.prepare('INSERT INTO wallets (user_id, balance_cents) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET balance_cents = balance_cents + excluded.balance_cents')
      .bind(e.user_id, e.amount_cents)
      .run();
    await c.env.DB.prepare("UPDATE expenses SET status = 'reimbursed' WHERE id = ?").bind(e.id).run();
    return c.json({ ok: true, credited_cents: e.amount_cents });
  });

  /* receipts */

  authed.post('/expenses/:id/receipts', async (c) => {
    const s = c.get('session');
    const e = await c.env.DB.prepare('SELECT id FROM expenses WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).first();
    if (!e) return notFound(c, 'Expense not found.');
    const form = await c.req.formData().catch(() => null);
    const file = form?.get('file');
    if (!file || typeof file === 'string') return bad(c, 'Attach a receipt file.');
    const ext = (file.name.split('.').pop() ?? '').toLowerCase();
    if (!RECEIPT_EXT.includes(ext)) return bad(c, 'Receipts must be an image or PDF.');
    if (file.size > 512 * 1024) return bad(c, 'Receipts must be smaller than 512 KB.');
    const r = await c.env.DB.prepare('INSERT INTO receipts (expense_id, org_id, filename, content_type, data_b64, size) VALUES (?, ?, ?, ?, ?, ?) RETURNING id')
      .bind(c.req.param('id'), s.org, file.name.slice(0, 120), file.type || 'application/octet-stream', toB64(await file.arrayBuffer()), file.size)
      .first<{ id: number }>();
    return c.json({ id: r?.id }, 201);
  });

  authed.get('/receipts/:id', async (c) => {
    const r = await c.env.DB.prepare('SELECT * FROM receipts WHERE id = ?').bind(c.req.param('id')).first<any>();
    if (!r) return notFound(c, 'Receipt not found.');
    const bin = atob(r.data_b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Response(bytes, {
      headers: { 'content-type': r.content_type, 'content-disposition': `inline; filename="${r.filename.replace(/"/g, '')}"`, 'x-expense-id': r.expense_id },
    });
  });

  /* comments */

  authed.get('/expenses/:id/comments', async (c) => {
    const rows = await c.env.DB.prepare(
      'SELECT cm.id, cm.body, cm.created_at, u.name AS author, u.email AS author_email FROM comments cm JOIN users u ON u.id = cm.user_id WHERE cm.expense_id = ? ORDER BY cm.created_at',
    ).bind(c.req.param('id')).all();
    return c.json({ data: rows.results });
  });

  authed.post('/expenses/:id/comments', async (c) => {
    const s = c.get('session');
    const e = await c.env.DB.prepare('SELECT id FROM expenses WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).first();
    if (!e) return notFound(c, 'Expense not found.');
    const body = await c.req.json().catch(() => ({}));
    const text = String(body.body ?? '').trim().slice(0, 2000);
    if (!text) return bad(c, 'Write a comment first.');
    const id = uuid();
    await c.env.DB.prepare('INSERT INTO comments (id, expense_id, user_id, body) VALUES (?, ?, ?, ?)').bind(id, c.req.param('id'), s.sub, text).run();
    return c.json({ id }, 201);
  });

  /* people search for @mentions */

  authed.get('/users/search', async (c) => {
    const q = (c.req.query('q') ?? '').trim();
    if (q.length < 2) return c.json({ data: [] });
    const rows = await c.env.DB.prepare(
      `SELECT u.id, u.name, u.email, m.org_id FROM users u JOIN memberships m ON m.user_id = u.id
       WHERE u.name LIKE ? OR u.email LIKE ? ORDER BY u.name LIMIT 10`,
    ).bind(`${q}%`, `${q}%`).all();
    return c.json({ data: rows.results });
  });

  /* ------------------------------------------------------------- members */

  authed.patch('/org/members/:userId', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can change roles.');
    const body = await c.req.json().catch(() => ({}));
    const role = String(body.role ?? '');
    if (!ROLES.includes(role)) return bad(c, 'Invalid role.');
    const target = await c.env.DB.prepare('SELECT role FROM memberships WHERE user_id = ? AND org_id = ?').bind(c.req.param('userId'), s.org).first<{ role: string }>();
    if (!target) return notFound(c, 'Member not found.');
    if (target.role === 'owner') return forbidden(c, 'The workspace owner’s role cannot be changed.');
    await c.env.DB.prepare('UPDATE memberships SET role = ? WHERE user_id = ? AND org_id = ?').bind(role, c.req.param('userId'), s.org).run();
    return c.json({ ok: true });
  });

  authed.delete('/org/members/:userId', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can remove members.');
    const target = await c.env.DB.prepare('SELECT role FROM memberships WHERE user_id = ? AND org_id = ?').bind(c.req.param('userId'), s.org).first<{ role: string }>();
    if (!target) return notFound(c, 'Member not found.');
    if (target.role === 'owner') return forbidden(c, 'The workspace owner cannot be removed.');
    await c.env.DB.prepare('DELETE FROM memberships WHERE user_id = ? AND org_id = ?').bind(c.req.param('userId'), s.org).run();
    return c.json({ ok: true });
  });

  authed.patch('/org/security', async (c) => {
    const s = c.get('session');
    if (s.role !== 'owner') return forbidden(c, 'Only the workspace owner can change security settings.');
    const body = await c.req.json().catch(() => ({}));
    const domain = String(body.invite_domain ?? '').trim().toLowerCase().replace(/^@/, '') || null;
    await c.env.DB.prepare('UPDATE orgs SET invite_domain = ? WHERE id = ?').bind(domain, s.org).run();
    return c.json({ ok: true });
  });

  authed.get('/org/security', async (c) => {
    const s = c.get('session');
    const o = await c.env.DB.prepare('SELECT invite_domain FROM orgs WHERE id = ?').bind(s.org).first();
    return c.json(o ?? {});
  });

  /* ------------------------------------------------------------- invites */

  authed.get('/org/invites', async (c) => {
    const s = c.get('session');
    const rows = await c.env.DB.prepare(
      'SELECT i.token, i.email, i.role, i.accepted, i.created_at, u.name AS invited_by FROM invites i JOIN users u ON u.id = i.invited_by WHERE i.org_id = ? ORDER BY i.created_at DESC',
    ).bind(s.org).all();
    return c.json({ data: rows.results });
  });

  authed.post('/org/invites', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can invite people.');
    const body = await c.req.json().catch(() => ({}));
    const email = String(body.email ?? '').trim().toLowerCase();
    const role = ['admin', 'member'].includes(body.role) ? body.role : 'member';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad(c, 'Enter a valid email.');
    const org = await c.env.DB.prepare('SELECT invite_domain FROM orgs WHERE id = ?').bind(s.org).first<{ invite_domain: string | null }>();
    if (org?.invite_domain && !email.endsWith(org.invite_domain)) return bad(c, `Invites are restricted to @${org.invite_domain} addresses.`);
    const token = b64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
    await c.env.DB.prepare('INSERT INTO invites (token, org_id, email, role, invited_by) VALUES (?, ?, ?, ?, ?)').bind(token, s.org, email, role, s.sub).run();
    return c.json({ token, link: `/invite?token=${token}` }, 201);
  });

  const acceptInvite = async (c: any, token: string, requestedRole?: string) => {
    const s = c.get('session');
    const inv = await c.env.DB.prepare('SELECT * FROM invites WHERE token = ? AND accepted = 0').bind(token).first();
    if (!inv) return null;
    const role = requestedRole && ROLES.includes(requestedRole) ? requestedRole : inv.role;
    await c.env.DB.batch([
      c.env.DB.prepare('INSERT OR IGNORE INTO memberships (user_id, org_id, role) VALUES (?, ?, ?)').bind(s.sub, inv.org_id, role),
      c.env.DB.prepare('UPDATE invites SET accepted = 1 WHERE token = ?').bind(token),
    ]);
    const user = c.get('user');
    const jwt = await signSession(c.env, { sub: user.id, org: inv.org_id, role, email: user.email });
    setCookie(c, 'fs_session', jwt, { httpOnly: true, secure: true, sameSite: 'None', path: '/', maxAge: 60 * 60 * 8 });
    return { org_id: inv.org_id, role };
  };

  authed.post('/invites/accept', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const r = await acceptInvite(c, String(body.token ?? ''), body.role);
    if (!r) return bad(c, 'This invitation is invalid or was already used.');
    return c.json({ ok: true, ...r });
  });

  authed.get('/invites/:token/accept', async (c) => {
    const r = await acceptInvite(c, c.req.param('token'));
    return c.redirect(r ? '/app' : '/invite?error=invalid', 302);
  });

  /* ------------------------------------------------------ workspace switch */

  authed.get('/me/workspaces', async (c) => {
    const rows = await c.env.DB.prepare('SELECT o.id, o.name, m.role FROM memberships m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = ?').bind(c.get('session').sub).all();
    return c.json({ data: rows.results });
  });

  authed.post('/me/workspaces/switch', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const m = await c.env.DB.prepare('SELECT org_id, role FROM memberships WHERE user_id = ? AND org_id = ?').bind(c.get('session').sub, String(body.org ?? '')).first<any>();
    if (!m) return forbidden(c, 'You are not a member of that workspace.');
    const user = c.get('user');
    const jwt = await signSession(c.env, { sub: user.id, org: m.org_id, role: m.role, email: user.email });
    setCookie(c, 'fs_session', jwt, { httpOnly: true, secure: true, sameSite: 'None', path: '/', maxAge: 60 * 60 * 8 });
    return c.json({ ok: true });
  });

  /* -------------------------------------------------------------- account */

  authed.patch('/me', async (c) => {
    const s = c.get('session');
    const body = await c.req.json().catch(() => ({}));
    const name = body.name !== undefined ? String(body.name).trim().slice(0, 80) : c.get('user').name;
    const email = body.email !== undefined ? String(body.email).trim().toLowerCase() : c.get('user').email;
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad(c, 'Check your name and email.');
    const clash = await c.env.DB.prepare('SELECT id FROM users WHERE email = ? AND id != ?').bind(email, s.sub).first();
    if (clash) return bad(c, 'That email is already in use.', 409);
    await c.env.DB.prepare('UPDATE users SET name = ?, email = ? WHERE id = ?').bind(name, email, s.sub).run();
    return c.json({ ok: true });
  });

  authed.post('/me/password', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const pw = String(body.new_password ?? '');
    if (pw.length < 10) return bad(c, 'Password must be at least 10 characters.');
    await c.env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await hashPassword(pw), c.get('session').sub).run();
    return c.json({ ok: true });
  });

  /* tokens */

  authed.get('/org/tokens', async (c) => {
    const rows = await c.env.DB.prepare(
      'SELECT t.id, t.name, t.scope, t.prefix, t.role, t.last_used_at, t.created_at, u.name AS owner, u.email AS owner_email FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.org_id = ? ORDER BY t.created_at DESC',
    ).bind(c.get('session').org).all();
    return c.json({ data: rows.results });
  });

  authed.post('/me/tokens', async (c) => {
    const s = c.get('session');
    if (s.scope) return forbidden(c, 'API tokens cannot create other tokens.');
    const body = await c.req.json().catch(() => ({}));
    const name = String(body.name ?? '').trim().slice(0, 60) || 'Untitled token';
    const scope = body.scope === 'write' ? 'write' : 'read';
    const secret = `fsp_${b64urlEncode(crypto.getRandomValues(new Uint8Array(24)))}`;
    const id = uuid();
    await c.env.DB.prepare('INSERT INTO api_tokens (id, user_id, org_id, role, name, scope, token_hash, prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, s.sub, s.org, s.role, name, scope, await sha256Hex(secret), secret.slice(0, 10))
      .run();
    return c.json({ id, token: secret, scope }, 201);
  });

  authed.delete('/me/tokens/:id', async (c) => {
    await c.env.DB.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').bind(c.req.param('id'), c.get('session').sub).run();
    return c.json({ ok: true });
  });

  /* -------------------------------------------------------------- reports */

  authed.get('/reports', async (c) => {
    const rows = await c.env.DB.prepare(
      'SELECT r.id, r.title, r.period_from, r.period_to, r.share_sig IS NOT NULL AS shared, r.created_at, u.name AS created_by FROM reports r JOIN users u ON u.id = r.created_by WHERE r.org_id = ? ORDER BY r.id DESC',
    ).bind(c.get('session').org).all();
    return c.json({ data: rows.results });
  });

  authed.post('/reports', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can create reports.');
    const body = await c.req.json().catch(() => ({}));
    const title = String(body.title ?? '').trim().slice(0, 120);
    const from = String(body.period_from ?? ''), to = String(body.period_to ?? '');
    if (!title || !/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to)) return bad(c, 'Enter a title and a valid period.');
    const r = await c.env.DB.prepare('INSERT INTO reports (org_id, title, period_from, period_to, created_by) VALUES (?, ?, ?, ?, ?) RETURNING id')
      .bind(s.org, title, from, to, s.sub)
      .first<{ id: number }>();
    return c.json({ id: r?.id }, 201);
  });

  authed.get('/reports/:id', async (c) => {
    const s = c.get('session');
    const r = await c.env.DB.prepare('SELECT * FROM reports WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).first<any>();
    if (!r) return notFound(c, 'Report not found.');
    const rows = await c.env.DB.prepare(
      `SELECT e.spent_at, e.merchant, e.category, e.amount_cents, e.status, u.name AS submitted_by FROM expenses e JOIN users u ON u.id = e.user_id
       WHERE e.org_id = ? AND e.spent_at BETWEEN ? AND ? ORDER BY e.spent_at`,
    ).bind(s.org, r.period_from, r.period_to).all();
    return c.json({ report: r, expenses: rows.results });
  });

  authed.post('/reports/:id/share', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can share reports.');
    const r = await c.env.DB.prepare('SELECT id FROM reports WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).first();
    if (!r) return notFound(c, 'Report not found.');
    const sig = (await sha256Hex(`${c.req.param('id')}.${uuid()}`)).slice(0, 32);
    await c.env.DB.prepare('UPDATE reports SET share_sig = ? WHERE id = ?').bind(sig, c.req.param('id')).run();
    return c.json({ url: `/r?id=${c.req.param('id')}&sig=${sig}` });
  });

  authed.delete('/reports/:id/share', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Only workspace admins can manage sharing.');
    await c.env.DB.prepare('UPDATE reports SET share_sig = NULL WHERE id = ? AND org_id = ?').bind(c.req.param('id'), s.org).run();
    return c.json({ ok: true });
  });

  /* ---------------------------------------------------------- admin console */

  authed.get('/admin/orgs', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Administrator access required.');
    const rows = await c.env.DB.prepare(
      'SELECT o.id, o.name, o.slug, o.plan, o.seats, o.sso_domain, o.internal_notes, o.created_at, (SELECT COUNT(*) FROM memberships m WHERE m.org_id = o.id) AS members FROM orgs o ORDER BY o.created_at LIMIT 200',
    ).all();
    return c.json({ data: rows.results });
  });

  authed.get('/admin/users', async (c) => {
    const s = c.get('session');
    if (!isManager(s.role)) return forbidden(c, 'Administrator access required.');
    const rows = await c.env.DB.prepare('SELECT u.id, u.name, u.email, u.created_at FROM users u ORDER BY u.created_at LIMIT 200').all();
    return c.json({ data: rows.results });
  });
}

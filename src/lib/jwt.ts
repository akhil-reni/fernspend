import type { Env } from '../types';
import {
  b64urlDecode,
  b64urlDecodeBytes,
  b64urlEncode,
  hmacSha256,
  importRsaPrivate,
  importRsaPublic,
  timingSafeEqual,
} from './crypto';

export interface KeyEntry {
  kid: string;
  alg: 'HS256' | 'RS256';
  use: 'session' | 'webhook';
  material: string;
  publish: boolean;
}

/**
 * Central key store. Session tokens and outbound webhook signatures share the
 * same JOSE plumbing so that rotation is handled in one place.
 */
export function keyring(env: Env): Record<string, KeyEntry> {
  return {
    [env.SESSION_KID]: { kid: env.SESSION_KID, alg: 'HS256', use: 'session', material: env.SESSION_SECRET, publish: false },
    [env.WEBHOOK_KID]: { kid: env.WEBHOOK_KID, alg: 'RS256', use: 'webhook', material: env.WEBHOOK_PUBLIC_KEY, publish: true },
  };
}

const enc = new TextEncoder();

export async function signSession(env: Env, claims: Record<string, unknown>, ttlSeconds = 60 * 60 * 8): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT', kid: env.SESSION_KID };
  const payload = { iss: 'https://app.fernspend.io', iat: now, exp: now + ttlSeconds, ...claims };
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
  const sig = await hmacSha256(env.SESSION_SECRET, signingInput);
  return `${signingInput}.${b64urlEncode(sig)}`;
}

export async function signWebhook(env: Env, claims: Record<string, unknown>): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid: env.WEBHOOK_KID };
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(claims))}`;
  const key = await importRsaPrivate(env.WEBHOOK_SIGNING_KEY);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(signingInput));
  return `${signingInput}.${b64urlEncode(sig)}`;
}

export interface SessionClaims {
  sub: string;
  org: string;
  role: 'owner' | 'admin' | 'member';
  email?: string;
  exp: number;
  [k: string]: unknown;
}

export async function verifyToken(env: Env, token: string): Promise<SessionClaims | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  let header: { alg?: string; kid?: string };
  let payload: SessionClaims;
  try {
    header = JSON.parse(b64urlDecode(h));
    payload = JSON.parse(b64urlDecode(p));
  } catch {
    return null;
  }

  const entry = header.kid ? keyring(env)[header.kid] : undefined;
  if (!entry) return null;

  const signingInput = `${h}.${p}`;
  let sig: Uint8Array;
  try {
    sig = b64urlDecodeBytes(s);
  } catch {
    return null;
  }

  let valid = false;
  switch (header.alg) {
    case 'HS256': {
      const expected = new Uint8Array(await hmacSha256(entry.material, signingInput));
      valid = timingSafeEqual(expected, sig);
      break;
    }
    case 'RS256': {
      try {
        const key = await importRsaPublic(entry.material);
        valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, enc.encode(signingInput));
      } catch {
        valid = false;
      }
      break;
    }
    default:
      valid = false;
  }
  if (!valid) return null;
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) return null;
  if (!payload.sub || !payload.org) return null;
  return payload;
}

export async function publicJwks(env: Env) {
  const keys = [];
  for (const entry of Object.values(keyring(env))) {
    if (!entry.publish) continue;
    const key = await importRsaPublic(entry.material);
    const jwk = (await crypto.subtle.exportKey('jwk', key)) as JsonWebKey;
    keys.push({ kty: jwk.kty, kid: entry.kid, use: 'sig', alg: entry.alg, n: jwk.n, e: jwk.e });
  }
  return { keys };
}

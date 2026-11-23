import type { Env } from '../types';

export class EgressPolicyError extends Error {}

const BLOCKED_V4: Array<[number, number]> = [
  [0x00000000, 8], // 0.0.0.0/8
  [0x0a000000, 8], // 10.0.0.0/8
  [0x64400000, 10], // 100.64.0.0/10
  [0x7f000000, 8], // 127.0.0.0/8
  [0xa9fe0000, 16], // 169.254.0.0/16
  [0xac100000, 12], // 172.16.0.0/12
  [0xc0000000, 24], // 192.0.0.0/24
  [0xc0a80000, 16], // 192.168.0.0/16
  [0xc6120000, 15], // 198.18.0.0/15
  [0xe0000000, 4], // 224.0.0.0/4
  [0xf0000000, 4], // 240.0.0.0/4
];

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipv4ToInt(ip: string): number | null {
  const m = IPV4_RE.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function isBlockedIPv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return true;
  return BLOCKED_V4.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) >>> 0 === base;
  });
}

const BLOCKED_NAMES = [/^localhost$/i, /\.localhost$/i, /\.local$/i, /\.internal$/i, /\.lan$/i, /^metadata$/i];

export async function resolveA(hostname: string): Promise<string[]> {
  if (IPV4_RE.test(hostname)) return [hostname];
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
    headers: { accept: 'application/dns-json' },
    cf: { cacheTtl: 0 },
  } as RequestInit);
  if (!res.ok) return [];
  const body = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
  return (body.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
}

/** Validates a customer-supplied destination before we send anything to it. */
export async function assertPublicDestination(raw: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new EgressPolicyError('Destination URL is not valid');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new EgressPolicyError('Only http(s) destinations are supported');
  if (url.username || url.password) throw new EgressPolicyError('Credentials in URLs are not supported');
  if (url.port && !['80', '443', '8080', '8443'].includes(url.port)) throw new EgressPolicyError('Destination port is not allowed');

  const host = url.hostname;
  if (host.startsWith('[')) throw new EgressPolicyError('IPv6 destinations are not supported yet');
  if (BLOCKED_NAMES.some((re) => re.test(host))) throw new EgressPolicyError('Destination host is not allowed');

  const addrs = await resolveA(host);
  if (addrs.length === 0) throw new EgressPolicyError('Destination host could not be resolved');
  if (addrs.some(isBlockedIPv4)) throw new EgressPolicyError('Destination resolves to a non-public address');
  return url;
}

export interface DeliveryResult {
  status: number;
  contentType: string | null;
  body: string;
  durationMs: number;
  finalUrl: string;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export async function deliver(
  destination: string,
  init: { headers: Record<string, string>; body: string },
): Promise<DeliveryResult> {
  const started = Date.now();
  let url = await assertPublicDestination(destination);
  let method = 'POST';
  let body: string | undefined = init.body;

  for (let hop = 0; hop < 3; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    let res: Response;
    try {
      res = await fetch(url.toString(), { method, headers: init.headers, body, signal: controller.signal, redirect: 'manual' });
    } finally {
      clearTimeout(timer);
    }
    const location = res.headers.get('location');
    if (REDIRECTS.has(res.status) && location) {
      url = await assertPublicDestination(new URL(location, url).toString());
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
        method = 'GET';
        body = undefined;
      }
      continue;
    }
    const text = await res.text();
    return {
      status: res.status,
      contentType: res.headers.get('content-type'),
      body: text.slice(0, 512),
      durationMs: Date.now() - started,
      finalUrl: url.toString(),
    };
  }
  throw new EgressPolicyError('Too many redirects');
}

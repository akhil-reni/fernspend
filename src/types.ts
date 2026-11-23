import type { SessionClaims } from './lib/jwt';

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  APP_NAME: string;
  SESSION_KID: string;
  SESSION_SECRET: string;
  WEBHOOK_KID: string;
  WEBHOOK_PUBLIC_KEY: string;
  WEBHOOK_SIGNING_KEY: string;
  FLAG_CONTRACT: string;
}

export interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  created_at: string;
}

export interface OrgRow {
  id: string;
  name: string;
  slug: string;
  plan: string;
  seats: number;
  sso_domain: string | null;
  sso_provider: string | null;
  created_at: string;
}

export type AppBindings = {
  Bindings: Env;
  Variables: { session: SessionClaims; user: UserRow };
};

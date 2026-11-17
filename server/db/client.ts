/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Single Reusable Server-Side Supabase Client
 * Ensures all backend modules share one centralized database client instance
 * configured strictly from server-only environment variables.
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { getServerDbConfig } from './config.ts';

export class DatabaseNotConfiguredError extends Error {
  public readonly statusCode = 503;

  constructor(message = 'Centralized database service is not configured on the server.') {
    super(message);
    this.name = 'DatabaseNotConfiguredError';
  }
}

let cachedServerClient: SupabaseClient | null = null;
let cachedSignature = '';

/**
 * Returns the single reusable server-side Supabase client singleton,
 * or null if server-only DB environment variables are not configured.
 */
export function getServerSupabase(): SupabaseClient | null {
  const cfg = getServerDbConfig();
  if (!cfg.isConfigured) {
    cachedServerClient = null;
    cachedSignature = '';
    return null;
  }

  const nextSignature = `${cfg.projectFingerprint}:${cfg.authMode}:${cfg.supabaseKey.length}`;
  if (cachedServerClient && cachedSignature === nextSignature) {
    return cachedServerClient;
  }

  try {
    cachedServerClient = createClient(cfg.supabaseUrl, cfg.supabaseKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
      global: {
        headers: {
          'x-ensec-client': 'ensec-erp-server',
        },
      },
    });
    cachedSignature = nextSignature;
    return cachedServerClient;
  } catch (err) {
    console.error('[DB Client] Failed to initialize server database client:', sanitizeDatabaseError(err));
    cachedServerClient = null;
    cachedSignature = '';
    return null;
  }
}

/**
 * Returns the active Supabase server client or throws a sanitized 503 error.
 */
export function requireServerSupabase(): SupabaseClient {
  const client = getServerSupabase();
  if (!client) {
    throw new DatabaseNotConfiguredError();
  }
  return client;
}

/**
 * Clears the cached server client instance so subsequent calls re-read server env config.
 */
export function resetServerSupabaseClient(): void {
  cachedServerClient = null;
  cachedSignature = '';
}

/**
 * Redacts URLs, JWTs, API keys, and Postgres connection strings before logging or responding.
 */
export function sanitizeDatabaseError(error: unknown): string {
  const raw =
    typeof error === 'string'
      ? error
      : error && typeof error === 'object' && 'message' in error
        ? String((error as { message?: unknown }).message || 'Database operation failed')
        : 'Database operation failed';

  return raw
    .replace(/postgres(?:ql)?:\/\/[^\s'"]+/gi, '[REDACTED_CONNECTION_URI]')
    .replace(/https?:\/\/[a-z0-9.-]+\.supabase\.co[^\s'"]*/gi, '[REDACTED_SUPABASE_URL]')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_JWT]')
    .replace(/sb_(?:secret|publishable)_[A-Za-z0-9_-]+/g, '[REDACTED_API_KEY]')
    .trim();
}

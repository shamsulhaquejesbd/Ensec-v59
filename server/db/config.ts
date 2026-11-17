/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Server-Side Database Configuration
 * All database credentials and session secrets are loaded strictly from
 * server-only environment variables. Zero hardcoded credentials or client-exposed
 * fallback secrets are permitted.
 */

import crypto from 'crypto';

export type ServerDbAuthMode = 'service_role' | 'anon_env' | 'unconfigured';

export interface ServerDatabaseConfig {
  readonly supabaseUrl: string;
  readonly supabaseKey: string;
  readonly authMode: ServerDbAuthMode;
  readonly isConfigured: boolean;
  readonly projectFingerprint: string | null;
  readonly sessionSecret: string;
  readonly hasExplicitSessionSecret: boolean;
}

export interface PublicSafeDatabaseSummary {
  configured: boolean;
  hasUrl: boolean;
  hasServiceRoleKey: boolean;
  authMode: ServerDbAuthMode;
  sessionSecretConfigured: boolean;
  projectFingerprint: string | null;
}

// Per-process ephemeral fallback secret when ERP_SESSION_SECRET is not set in dev.
// Never derived from SUPABASE_URL or hardcoded constants.
let ephemeralProcessSessionSecret: string | null = null;
let warnedMissingSessionSecret = false;
let warnedLegacyAnonKey = false;

function isValidHttpUrl(raw: string): boolean {
  if (!raw) return false;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function computeProjectFingerprint(url: string): string | null {
  if (!url) return null;
  return crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex').slice(0, 12);
}

export function getServerDbConfig(): ServerDatabaseConfig {
  const rawUrl = (process.env.SUPABASE_URL || '').trim();
  const validUrl = isValidHttpUrl(rawUrl) ? rawUrl : '';

  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  const anonEnvKey = (process.env.SUPABASE_ANON_KEY || '').trim();

  let supabaseKey = '';
  let authMode: ServerDbAuthMode = 'unconfigured';

  if (validUrl && serviceRoleKey) {
    supabaseKey = serviceRoleKey;
    authMode = 'service_role';
  } else if (validUrl && anonEnvKey) {
    supabaseKey = anonEnvKey;
    authMode = 'anon_env';
    if (!warnedLegacyAnonKey) {
      warnedLegacyAnonKey = true;
      console.warn(
        '[DB Config] SUPABASE_SERVICE_ROLE_KEY is not set; using server-only SUPABASE_ANON_KEY. Configure SUPABASE_SERVICE_ROLE_KEY for full backend privileges and strict RLS enforcement.'
      );
    }
  }

  const explicitSessionSecret = (process.env.ERP_SESSION_SECRET || '').trim();
  if (!explicitSessionSecret && !ephemeralProcessSessionSecret) {
    ephemeralProcessSessionSecret = crypto.randomBytes(32).toString('hex');
    if (!warnedMissingSessionSecret) {
      warnedMissingSessionSecret = true;
      console.warn(
        '[Security] ERP_SESSION_SECRET is not set. Using an ephemeral per-process session secret; set ERP_SESSION_SECRET in server environment variables for persistent sessions.'
      );
    }
  }

  const sessionSecret = explicitSessionSecret || (ephemeralProcessSessionSecret as string);

  return {
    supabaseUrl: validUrl,
    supabaseKey,
    authMode,
    isConfigured: Boolean(validUrl && supabaseKey),
    projectFingerprint: validUrl ? computeProjectFingerprint(validUrl) : null,
    sessionSecret,
    hasExplicitSessionSecret: Boolean(explicitSessionSecret),
  };
}

export function getPublicSafeDatabaseSummary(): PublicSafeDatabaseSummary {
  const cfg = getServerDbConfig();
  return {
    configured: cfg.isConfigured,
    hasUrl: Boolean(cfg.supabaseUrl),
    hasServiceRoleKey: cfg.authMode === 'service_role',
    authMode: cfg.authMode,
    sessionSecretConfigured: cfg.hasExplicitSessionSecret,
    projectFingerprint: cfg.projectFingerprint,
  };
}

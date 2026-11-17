import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import type express from 'express';
import { getServerDbConfig, getServerSupabase, recordDbAuditEvent } from '../db/index.ts';
import { getDefaultPermissionsForRole, resolveUserPermissions, type Role } from '../../src/types/erp.ts';

export const SESSION_COOKIE_NAME = 'ensec_erp_session';
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const BCRYPT_SALT_ROUNDS = 10;

export interface AuthenticatedErpUser {
  id: string;
  userId: string;
  name: string;
  email: string;
  phone?: string;
  role: string;
  designation?: string;
  department?: string;
  region?: string;
  area?: string;
  territory?: string;
  isSalesman?: boolean;
  salesmanCode?: string;
  monthlySalesTargetBDT?: number;
  status: string;
  avatar?: string;
  permissions: any;
  createdAt?: string;
}

interface ActiveSessionRecord {
  user: AuthenticatedErpUser;
  createdAt: number;
  expiresAt: number;
}

const erpActiveSessions = new Map<string, ActiveSessionRecord>();
const revokedSessionTokens = new Set<string>();
const serverUsersCache = new Map<string, AuthenticatedErpUser & { _passwordHash?: string }>();

const DEFAULT_ROOT_PASSWORD_HASH = bcrypt.hashSync('ensec2026', BCRYPT_SALT_ROUNDS);

export function getDefaultRootAdminRecord(): AuthenticatedErpUser & { _passwordHash: string } {
  return {
    id: 'u-admin-root',
    userId: 'ADMIN',
    name: 'Super Admin',
    email: 'admin@ensecbd.com',
    phone: '',
    role: 'Super Admin',
    designation: 'Managing Director / System Administrator',
    department: 'Management',
    status: 'Active',
    permissions: getDefaultPermissionsForRole('Super Admin'),
    _passwordHash: DEFAULT_ROOT_PASSWORD_HASH,
  };
}

export function isBcryptHash(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return /^\$2[aby]\$\d{2}\$/.test(value);
}

export async function hashPassword(plainPassword: string): Promise<string> {
  return bcrypt.hash(String(plainPassword), BCRYPT_SALT_ROUNDS);
}

export function sanitizeUserForClient<T extends Record<string, any> | null | undefined>(
  user: T
): Omit<NonNullable<T>, 'password' | 'password_hash' | 'passwordHash' | '_passwordHash'> | null {
  if (!user || typeof user !== 'object') return null;
  const {
    password: _p,
    password_hash: _ph,
    passwordHash: _phCamel,
    _passwordHash: _internalPh,
    ...safe
  } = user as Record<string, any>;
  return safe as any;
}

export function mapSupabaseUserRowSafe(row: any): AuthenticatedErpUser {
  let parsedPermissions = row.permissions;
  if (typeof parsedPermissions === 'string') {
    try {
      parsedPermissions = JSON.parse(parsedPermissions);
    } catch {
      parsedPermissions = null;
    }
  }
  const role = (row.role as Role) || 'Field Force';
  const status =
    row.status === 'Inactive'
      ? 'Inactive'
      : row.status === 'Blocked'
      ? 'Blocked'
      : 'Active';

  return {
    id: row.uid ? String(row.uid) : `u-sb-${row.id}`,
    userId:
      row.user_id ||
      row.uid ||
      (row.email ? String(row.email).split('@')[0].toUpperCase() : `EMP-${row.id}`),
    name: row.name || 'Staff User',
    email: row.email || '',
    phone: row.phone || '',
    role,
    designation: row.designation || '',
    department: row.department || '',
    region: row.region || '',
    area: row.area || '',
    territory: row.territory || '',
    isSalesman: row.is_salesman,
    salesmanCode: row.salesman_code || row.salesmancode || undefined,
    monthlySalesTargetBDT: row.monthly_target_bdt || row.monthlysalestargetbdt,
    status,
    avatar: row.avatar || undefined,
    permissions: resolveUserPermissions({
      role,
      permissions: parsedPermissions,
    }),
    createdAt: row.created_at || undefined,
  };
}

export function indexUserInAuthCache(user: any, passwordHash?: string) {
  if (!user || typeof user !== 'object') return;
  const safe = sanitizeUserForClient(user) as AuthenticatedErpUser | null;
  if (!safe) return;
  const existingHash =
    (safe.id && serverUsersCache.get(String(safe.id).toLowerCase())?._passwordHash) ||
    (safe.userId && serverUsersCache.get(String(safe.userId).toLowerCase())?._passwordHash) ||
    (safe.email && serverUsersCache.get(String(safe.email).toLowerCase())?._passwordHash) ||
    undefined;
  const resolvedHash = passwordHash || existingHash;
  const entry = {
    ...safe,
    ...(resolvedHash ? { _passwordHash: resolvedHash } : {}),
  };
  if (safe.id) serverUsersCache.set(String(safe.id).toLowerCase(), entry);
  if (safe.userId) serverUsersCache.set(String(safe.userId).toLowerCase(), entry);
  if (safe.salesmanCode) serverUsersCache.set(String(safe.salesmanCode).toLowerCase(), entry);
  if (safe.email) serverUsersCache.set(String(safe.email).toLowerCase(), entry);
}

export function clearAuthCacheForTest() {
  serverUsersCache.clear();
  erpActiveSessions.clear();
  revokedSessionTokens.clear();
}

export function getCachedServerUsers(): AuthenticatedErpUser[] {
  const unique = new Map<string, AuthenticatedErpUser>();
  for (const u of serverUsersCache.values()) {
    const key = String(u.id || u.userId || u.email).toLowerCase();
    if (!unique.has(key)) {
      const sanitized = sanitizeUserForClient(u);
      if (sanitized) unique.set(key, sanitized);
    }
  }
  return Array.from(unique.values());
}

export function parseCookies(cookieHeader?: string): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx <= 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      try {
        result[key] = decodeURIComponent(val);
      } catch {
        result[key] = val;
      }
    }
  }
  return result;
}

export function extractSessionToken(req: express.Request): string {
  const cookies = parseCookies(req.headers.cookie);
  const cookieToken = cookies[SESSION_COOKIE_NAME] || '';
  const authHeader = String(req.headers['authorization'] || '').trim();
  const bearerToken = authHeader.toLowerCase().startsWith('bearer ')
    ? authHeader.slice(7).trim()
    : '';
  const headerToken = String(req.headers['x-erp-session-token'] || '').trim();
  return String(cookieToken || headerToken || bearerToken || '').trim();
}

function isRequestSecure(req: express.Request): boolean {
  const xfProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
  return Boolean(req.secure || xfProto === 'https');
}

export function setSessionCookie(
  res: express.Response,
  req: express.Request,
  token: string,
  ttlMs: number = SESSION_TTL_MS
) {
  const maxAgeSeconds = Math.max(1, Math.floor(ttlMs / 1000));
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (isRequestSecure(req)) {
    parts.push('Secure');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(res: express.Response, req: express.Request) {
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (isRequestSecure(req)) {
    parts.push('Secure');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function signErpSessionToken(user: AuthenticatedErpUser, ttlMs: number = SESSION_TTL_MS): string {
  const secret = getServerDbConfig().sessionSecret;
  const now = Date.now();
  const payload = {
    uid: String(user.id),
    code: String(user.userId || ''),
    email: String(user.email || ''),
    iat: now,
    exp: now + ttlMs,
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

export function verifyErpSessionToken(
  token?: string | null
): { uid: string; code: string; email: string; exp: number } | null {
  if (!token || revokedSessionTokens.has(token)) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const secret = getServerDbConfig().sessionSecret;
  const expectedSig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  try {
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!parsed || !parsed.uid || (parsed.exp && Date.now() > Number(parsed.exp))) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function createSessionForUser(
  user: AuthenticatedErpUser,
  previousTokenToRotate?: string | null,
  ttlMs: number = SESSION_TTL_MS
): { token: string; expiresAt: number } {
  // Session fixation protection: revoke any prior token presented during login
  if (previousTokenToRotate) {
    revokeSessionToken(previousTokenToRotate);
  }
  const safeUser = sanitizeUserForClient(user) as AuthenticatedErpUser;
  const token = signErpSessionToken(safeUser, ttlMs);
  const now = Date.now();
  const expiresAt = now + ttlMs;
  erpActiveSessions.set(token, {
    user: safeUser,
    createdAt: now,
    expiresAt,
  });
  return { token, expiresAt };
}

export function revokeSessionToken(token?: string | null) {
  if (!token) return;
  erpActiveSessions.delete(token);
  revokedSessionTokens.add(token);
}

export async function findRawUserRecordByIdentifier(
  identifier: string
): Promise<{
  rawRow: any | null;
  user: AuthenticatedErpUser | null;
  storedPassword: string | null;
}> {
  const cleanId = String(identifier || '').trim();
  const cleanIdLower = cleanId.toLowerCase();
  if (!cleanId) {
    return { rawRow: null, user: null, storedPassword: null };
  }

  const db = getServerSupabase();
  if (db) {
    try {
      // Query users safely by user_id, email, uid, phone, or salesman_code
      const { data: rows, error } = await db.from('users').select('*');
      if (!error && Array.isArray(rows)) {
        const cleanDigits = cleanIdLower.replace(/[^0-9]/g, '');
        const hit = rows.find((r: any) => {
          const rUid = String(r.uid || '').trim().toLowerCase();
          const rUserId = String(r.user_id || '').trim().toLowerCase();
          const rEmail = String(r.email || '').trim().toLowerCase();
          const rPhone = String(r.phone || '').replace(/[^0-9]/g, '');
          const rSalesmanCode = String(r.salesman_code || r.salesmancode || '').trim().toLowerCase();
          return (
            rUserId === cleanIdLower ||
            rEmail === cleanIdLower ||
            rUid === cleanIdLower ||
            rSalesmanCode === cleanIdLower ||
            (cleanDigits.length >= 6 && rPhone === cleanDigits)
          );
        });
        if (hit) {
          const mapped = mapSupabaseUserRowSafe(hit);
          indexUserInAuthCache(mapped);
          return {
            rawRow: hit,
            user: mapped,
            storedPassword:
              hit.password !== undefined && hit.password !== null && String(hit.password) !== ''
                ? String(hit.password)
                : null,
          };
        }
        // Database responded and has rows, user genuinely not found
        if (rows.length > 0) {
          return { rawRow: null, user: null, storedPassword: null };
        }
      }
    } catch {
      // Fallback below only if DB unavailable or unseeded
    }
  }

  // Fallback to server cache (used in test/offline mode without Supabase .env)
  const cached = serverUsersCache.get(cleanIdLower);
  if (cached) {
    return {
      rawRow: null,
      user: sanitizeUserForClient(cached) as AuthenticatedErpUser,
      storedPassword: cached._passwordHash || null,
    };
  }

  // Emergency root ADMIN fallback ONLY when directory is completely unseeded (zero users)
  if (
    serverUsersCache.size === 0 &&
    (cleanIdLower === 'admin' || cleanIdLower === 'admin@ensecbd.com')
  ) {
    const rootAdmin = getDefaultRootAdminRecord();
    indexUserInAuthCache(rootAdmin, rootAdmin._passwordHash);
    return {
      rawRow: null,
      user: sanitizeUserForClient(rootAdmin) as AuthenticatedErpUser,
      storedPassword: rootAdmin._passwordHash,
    };
  }

  return { rawRow: null, user: null, storedPassword: null };
}

export async function verifyPasswordAndMigrateHash(params: {
  inputPassword: string;
  storedPassword: string | null;
  rawRow: any | null;
  user: AuthenticatedErpUser;
}): Promise<{ valid: boolean; migratedToBcrypt: boolean }> {
  const { inputPassword, storedPassword, rawRow, user } = params;
  if (!inputPassword || !storedPassword) {
    return { valid: false, migratedToBcrypt: false };
  }

  if (isBcryptHash(storedPassword)) {
    const match = await bcrypt.compare(inputPassword, storedPassword);
    return { valid: match, migratedToBcrypt: false };
  }

  // Legacy plaintext password comparison using constant-time byte check when lengths match
  const a = Buffer.from(inputPassword, 'utf8');
  const b = Buffer.from(storedPassword, 'utf8');
  const plainMatch = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!plainMatch) {
    return { valid: false, migratedToBcrypt: false };
  }

  // Controlled automatic migration: upgrade plaintext password in Supabase to bcrypt hash
  let migrated = false;
  try {
    const newHash = await hashPassword(inputPassword);
    indexUserInAuthCache(user, newHash);
    const db = getServerSupabase();
    if (db && rawRow) {
      const updateQuery = rawRow.id
        ? db.from('users').update({ password: newHash, updated_at: new Date().toISOString() }).eq('id', rawRow.id)
        : rawRow.email
        ? db.from('users').update({ password: newHash, updated_at: new Date().toISOString() }).ilike('email', rawRow.email)
        : null;
      if (updateQuery) {
        const { error } = await updateQuery;
        if (!error) {
          migrated = true;
          recordDbAuditEvent({
            eventType: 'PASSWORD_HASH_MIGRATED',
            actorId: user.id,
            actorName: user.name,
            actorRole: user.role,
            outcome: 'success',
            details: `Upgraded legacy credential storage to bcrypt hash for account ${user.userId}.`,
          });
        }
      }
    }
  } catch {
    // Non-fatal: login still succeeds while migration retries next login
  }

  return { valid: true, migratedToBcrypt: migrated };
}

export async function lookupAuthoritativeUser(
  hdrId: string,
  hdrCode: string,
  hdrEmail: string
): Promise<AuthenticatedErpUser | null> {
  const db = getServerSupabase();
  if (db) {
    try {
      if (hdrEmail) {
        const { data } = await db
          .from('users')
          .select('*')
          .ilike('email', hdrEmail)
          .limit(1)
          .maybeSingle();
        if (data) {
          const mapped = mapSupabaseUserRowSafe(data);
          indexUserInAuthCache(mapped);
          return mapped;
        }
      }
      const lookupUid = hdrCode || hdrId;
      if (lookupUid) {
        const { data } = await db
          .from('users')
          .select('*')
          .eq('uid', lookupUid)
          .limit(1)
          .maybeSingle();
        if (data) {
          const mapped = mapSupabaseUserRowSafe(data);
          indexUserInAuthCache(mapped);
          return mapped;
        }
      }
      if (/^u-sb-(\d+)$/i.test(hdrId)) {
        const numId = Number(hdrId.replace(/^u-sb-/i, ''));
        const { data } = await db
          .from('users')
          .select('*')
          .eq('id', numId)
          .limit(1)
          .maybeSingle();
        if (data) {
          const mapped = mapSupabaseUserRowSafe(data);
          indexUserInAuthCache(mapped);
          return mapped;
        }
      }
    } catch {
      // Fallback to cache below
    }
  }

  const candidates = [hdrId, hdrCode, hdrEmail]
    .map((s) => String(s || '').toLowerCase())
    .filter(Boolean);
  for (const key of candidates) {
    const hit = serverUsersCache.get(key);
    if (hit) {
      return sanitizeUserForClient(hit) as AuthenticatedErpUser;
    }
  }

  return null;
}

/**
 * Strictly resolves the authenticated ERP user from a signed, non-revoked,
 * non-expired session token (HttpOnly cookie, Bearer token, or x-erp-session-token).
 * NEVER trusts raw x-user-id / x-user-code / x-user-email headers or query params.
 */
export async function resolveRequestUser(req: express.Request): Promise<AuthenticatedErpUser | null> {
  const sessionToken = extractSessionToken(req);
  if (!sessionToken || revokedSessionTokens.has(sessionToken)) {
    return null;
  }

  const tokenClaims = verifyErpSessionToken(sessionToken);
  if (!tokenClaims) {
    return null;
  }

  const storedSession = erpActiveSessions.get(sessionToken);
  if (storedSession && Date.now() > storedSession.expiresAt) {
    erpActiveSessions.delete(sessionToken);
    return null;
  }

  const freshUser =
    (await lookupAuthoritativeUser(tokenClaims.uid, tokenClaims.code, tokenClaims.email)) ||
    storedSession?.user ||
    null;

  if (!freshUser || freshUser.status === 'Blocked' || freshUser.status === 'Inactive') {
    return null;
  }

  return sanitizeUserForClient(freshUser) as AuthenticatedErpUser;
}

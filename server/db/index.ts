/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Server Database Module Exports
 */

export {
  getServerDbConfig,
  getPublicSafeDatabaseSummary,
  computeProjectFingerprint,
  type ServerDatabaseConfig,
  type PublicSafeDatabaseSummary,
  type ServerDbAuthMode,
} from './config.ts';

export {
  getServerSupabase,
  requireServerSupabase,
  resetServerSupabaseClient,
  sanitizeDatabaseError,
  DatabaseNotConfiguredError,
} from './client.ts';

export { EXPECTED_ERP_TABLES, type ExpectedTableSpec } from './schemaRegistry.ts';

export {
  checkServerDatabaseStatus,
  verifyDatabaseSchema,
  recordDbAuditEvent,
  getDbAuditEvents,
  type DbAuditEvent,
  type ServerDatabaseStatusResult,
  type SchemaVerificationResult,
  type TableSchemaCheckResult,
} from './health.ts';

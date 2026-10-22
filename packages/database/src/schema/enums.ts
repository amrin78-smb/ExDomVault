import { pgEnum } from 'drizzle-orm/pg-core';

// Values mirror the zod enums in @exdomainvault/shared. Adding a value requires a migration;
// never remove or rename one that may be stored.

export const userRole = pgEnum('user_role', ['admin', 'analyst', 'asset_owner', 'viewer']);
export const authProvider = pgEnum('auth_provider', ['cloudflare_access', 'dev']);

export const criticality = pgEnum('criticality', ['low', 'medium', 'high', 'critical']);

export const domainVerificationStatus = pgEnum('domain_verification_status', [
  'unverified',
  'pending',
  'verified',
  'revoked',
]);
/** Whether registration (RDAP) data is known, redacted for privacy, or unavailable. */
export const registrationDataStatus = pgEnum('registration_data_status', [
  'unknown',
  'available',
  'redacted',
  'unavailable',
]);

export const verificationMethod = pgEnum('verification_method', ['dns_txt']);
export const challengeStatus = pgEnum('challenge_status', [
  'pending',
  'verified',
  'expired',
  'failed',
  'superseded',
]);

export const assetType = pgEnum('asset_type', ['apex', 'subdomain']);
export const assetApprovalStatus = pgEnum('asset_approval_status', [
  'pending',
  'approved',
  'rejected',
  'suspended',
]);
export const discoverySource = pgEnum('discovery_source', [
  'manual',
  'import',
  'certificate_transparency',
  'dns',
]);

export const scanJobType = pgEnum('scan_job_type', ['scan', 'discovery']);
export const scanJobStatus = pgEnum('scan_job_status', [
  'queued',
  'claimed',
  'running',
  'succeeded',
  'failed',
  'cancelled',
]);
export const scanTargetStatus = pgEnum('scan_target_status', [
  'pending',
  'running',
  'succeeded',
  'failed',
  'skipped',
]);

/** Outcome of a single check. Only `success` observations may resolve findings. */
export const observationResult = pgEnum('observation_result', [
  'success',
  'partial',
  'error',
  'timeout',
  'skipped',
]);

export const severity = pgEnum('severity', ['informational', 'low', 'medium', 'high', 'critical']);
export const confidence = pgEnum('confidence', ['low', 'medium', 'high']);
export const findingStatus = pgEnum('finding_status', [
  'open',
  'acknowledged',
  'remediation_in_progress',
  'resolved',
  'accepted_risk',
]);

export const workerStatus = pgEnum('worker_status', ['active', 'disabled']);
export const actorType = pgEnum('actor_type', ['user', 'worker', 'system']);

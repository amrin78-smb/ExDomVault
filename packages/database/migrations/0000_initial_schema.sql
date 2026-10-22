CREATE TYPE "public"."actor_type" AS ENUM('user', 'worker', 'system');--> statement-breakpoint
CREATE TYPE "public"."asset_approval_status" AS ENUM('pending', 'approved', 'rejected', 'suspended');--> statement-breakpoint
CREATE TYPE "public"."asset_type" AS ENUM('apex', 'subdomain');--> statement-breakpoint
CREATE TYPE "public"."auth_provider" AS ENUM('cloudflare_access', 'dev');--> statement-breakpoint
CREATE TYPE "public"."challenge_status" AS ENUM('pending', 'verified', 'expired', 'failed', 'superseded');--> statement-breakpoint
CREATE TYPE "public"."confidence" AS ENUM('low', 'medium', 'high');--> statement-breakpoint
CREATE TYPE "public"."criticality" AS ENUM('low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."discovery_source" AS ENUM('manual', 'import', 'certificate_transparency', 'dns');--> statement-breakpoint
CREATE TYPE "public"."domain_verification_status" AS ENUM('unverified', 'pending', 'verified', 'revoked');--> statement-breakpoint
CREATE TYPE "public"."finding_status" AS ENUM('open', 'acknowledged', 'remediation_in_progress', 'resolved', 'accepted_risk');--> statement-breakpoint
CREATE TYPE "public"."observation_result" AS ENUM('success', 'partial', 'error', 'timeout', 'skipped');--> statement-breakpoint
CREATE TYPE "public"."registration_data_status" AS ENUM('unknown', 'available', 'redacted', 'unavailable');--> statement-breakpoint
CREATE TYPE "public"."scan_job_status" AS ENUM('queued', 'claimed', 'running', 'succeeded', 'failed', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."scan_job_type" AS ENUM('scan', 'discovery');--> statement-breakpoint
CREATE TYPE "public"."scan_target_status" AS ENUM('pending', 'running', 'succeeded', 'failed', 'skipped');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('informational', 'low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('admin', 'analyst', 'asset_owner', 'viewer');--> statement-breakpoint
CREATE TYPE "public"."verification_method" AS ENUM('dns_txt');--> statement-breakpoint
CREATE TYPE "public"."worker_status" AS ENUM('active', 'disabled');--> statement-breakpoint
CREATE TABLE "notification_preferences" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"channel" text NOT NULL,
	"event_type" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"display_name" text,
	"role" "user_role" DEFAULT 'viewer' NOT NULL,
	"auth_provider" "auth_provider" NOT NULL,
	"auth_provider_subject" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_lowercase" CHECK ("users"."email" = lower("users"."email"))
);
--> statement-breakpoint
CREATE TABLE "domain_verifications" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"domain_id" uuid NOT NULL,
	"method" "verification_method" NOT NULL,
	"challenge_hash" text NOT NULL,
	"status" "challenge_status" DEFAULT 'pending' NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_checked_at" timestamp with time zone,
	"verified_at" timestamp with time zone,
	"failure_reason" text,
	CONSTRAINT "domain_verifications_expiry_after_creation" CHECK ("domain_verifications"."expires_at" > "domain_verifications"."created_at")
);
--> statement-breakpoint
CREATE TABLE "domains" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"fqdn" text NOT NULL,
	"registrar" text,
	"registered_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"registration_data_status" "registration_data_status" DEFAULT 'unknown' NOT NULL,
	"criticality" "criticality" DEFAULT 'medium' NOT NULL,
	"business_owner" text,
	"verification_status" "domain_verification_status" DEFAULT 'unverified' NOT NULL,
	"verified_at" timestamp with time zone,
	"monitoring_enabled" boolean DEFAULT false NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "domains_fqdn_normalised" CHECK ("domains"."fqdn" = lower("domains"."fqdn") AND "domains"."fqdn" NOT LIKE '%.' AND length("domains"."fqdn") <= 253),
	CONSTRAINT "domains_verified_at_consistent" CHECK (("domains"."verification_status" = 'verified') = ("domains"."verified_at" IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "asset_ips" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"ip_address" "inet" NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"is_current" boolean DEFAULT true NOT NULL,
	"source" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"domain_id" uuid NOT NULL,
	"hostname" text NOT NULL,
	"asset_type" "asset_type" NOT NULL,
	"verification_status" "asset_approval_status" DEFAULT 'pending' NOT NULL,
	"discovery_source" "discovery_source" NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"monitoring_enabled" boolean DEFAULT false NOT NULL,
	"criticality_override" "criticality",
	"owner_user_id" uuid,
	"approved_by" uuid,
	"approved_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "assets_hostname_normalised" CHECK ("assets"."hostname" = lower("assets"."hostname") AND "assets"."hostname" NOT LIKE '%.' AND length("assets"."hostname") <= 253),
	CONSTRAINT "assets_approval_consistent" CHECK ("assets"."verification_status" <> 'approved' OR ("assets"."approved_by" IS NOT NULL AND "assets"."approved_at" IS NOT NULL)),
	CONSTRAINT "assets_monitoring_requires_approval" CHECK (NOT "assets"."monitoring_enabled" OR "assets"."verification_status" = 'approved')
);
--> statement-breakpoint
CREATE TABLE "application_settings" (
	"key" text PRIMARY KEY NOT NULL,
	"value" jsonb NOT NULL,
	"updated_by" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_profiles" (
	"key" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"config" jsonb NOT NULL,
	"default_schedule" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_rules" (
	"rule_id" text PRIMARY KEY NOT NULL,
	"version" integer NOT NULL,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"default_severity" "severity" NOT NULL,
	"default_confidence" "confidence" NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "worker_registry" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"status" "worker_status" DEFAULT 'active' NOT NULL,
	"version" text,
	"last_seen_at" timestamp with time zone,
	"last_health" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_job_targets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_job_id" uuid NOT NULL,
	"asset_id" uuid,
	"target_hostname" text NOT NULL,
	"target_ip" "inet",
	"status" "scan_target_status" DEFAULT 'pending' NOT NULL,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"error_code" text,
	CONSTRAINT "scan_job_targets_key" UNIQUE NULLS NOT DISTINCT("scan_job_id","target_hostname","target_ip")
);
--> statement-breakpoint
CREATE TABLE "scan_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"job_type" "scan_job_type" NOT NULL,
	"profile" text NOT NULL,
	"domain_id" uuid,
	"status" "scan_job_status" DEFAULT 'queued' NOT NULL,
	"priority" smallint DEFAULT 100 NOT NULL,
	"requested_by" uuid,
	"reason" text,
	"scope_snapshot" jsonb NOT NULL,
	"idempotency_key" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"scheduled_at" timestamp with time zone DEFAULT now() NOT NULL,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"lease_expires_at" timestamp with time zone,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 3 NOT NULL,
	"worker_id" uuid,
	"progress" jsonb,
	"cancel_requested_at" timestamp with time zone,
	"error_code" text,
	"error_summary" text,
	CONSTRAINT "scan_jobs_attempts_bounded" CHECK ("scan_jobs"."attempts" >= 0 AND "scan_jobs"."attempts" <= "scan_jobs"."max_attempts"),
	CONSTRAINT "scan_jobs_lease_when_active" CHECK ("scan_jobs"."status" NOT IN ('claimed', 'running') OR ("scan_jobs"."lease_expires_at" IS NOT NULL AND "scan_jobs"."worker_id" IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "discovery_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"result_id" text NOT NULL,
	"asset_id" uuid,
	"scan_job_id" uuid NOT NULL,
	"scan_job_target_id" uuid,
	"observed_at" timestamp with time zone NOT NULL,
	"checker" text NOT NULL,
	"checker_version" text NOT NULL,
	"result_status" "observation_result" NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"domain_id" uuid NOT NULL,
	"hostname" text NOT NULL,
	"source" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dns_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"result_id" text NOT NULL,
	"asset_id" uuid,
	"scan_job_id" uuid NOT NULL,
	"scan_job_target_id" uuid,
	"observed_at" timestamp with time zone NOT NULL,
	"checker" text NOT NULL,
	"checker_version" text NOT NULL,
	"result_status" "observation_result" NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"hostname" text NOT NULL,
	"record_type" text NOT NULL,
	"ttl" integer,
	"record_values" text[] DEFAULT '{}' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "http_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"result_id" text NOT NULL,
	"asset_id" uuid,
	"scan_job_id" uuid NOT NULL,
	"scan_job_target_id" uuid,
	"observed_at" timestamp with time zone NOT NULL,
	"checker" text NOT NULL,
	"checker_version" text NOT NULL,
	"result_status" "observation_result" NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"url" text NOT NULL,
	"ip_address" "inet",
	"status_code" integer,
	"final_url" text,
	"redirect_count" integer DEFAULT 0 NOT NULL,
	"hsts_enabled" boolean
);
--> statement-breakpoint
CREATE TABLE "port_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"result_id" text NOT NULL,
	"asset_id" uuid,
	"scan_job_id" uuid NOT NULL,
	"scan_job_target_id" uuid,
	"observed_at" timestamp with time zone NOT NULL,
	"checker" text NOT NULL,
	"checker_version" text NOT NULL,
	"result_status" "observation_result" NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip_address" "inet" NOT NULL,
	"port" integer NOT NULL,
	"protocol" text DEFAULT 'tcp' NOT NULL,
	"state" text NOT NULL,
	"service" text
);
--> statement-breakpoint
CREATE TABLE "registration_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"result_id" text NOT NULL,
	"asset_id" uuid,
	"scan_job_id" uuid NOT NULL,
	"scan_job_target_id" uuid,
	"observed_at" timestamp with time zone NOT NULL,
	"checker" text NOT NULL,
	"checker_version" text NOT NULL,
	"result_status" "observation_result" NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"domain_id" uuid NOT NULL,
	"registrar" text,
	"registered_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"nameservers" text[] DEFAULT '{}' NOT NULL,
	"data_status" "registration_data_status" NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tls_observations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"result_id" text NOT NULL,
	"asset_id" uuid,
	"scan_job_id" uuid NOT NULL,
	"scan_job_target_id" uuid,
	"observed_at" timestamp with time zone NOT NULL,
	"checker" text NOT NULL,
	"checker_version" text NOT NULL,
	"result_status" "observation_result" NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"hostname" text NOT NULL,
	"ip_address" "inet",
	"port" integer NOT NULL,
	"protocol_version" text,
	"not_before" timestamp with time zone,
	"not_after" timestamp with time zone,
	"issuer" text,
	"subject" text,
	"subject_alt_names" text[] DEFAULT '{}' NOT NULL,
	"fingerprint_sha256" text,
	"hostname_matches" boolean
);
--> statement-breakpoint
CREATE TABLE "advisories" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"finding_id" uuid NOT NULL,
	"title" text NOT NULL,
	"summary" text NOT NULL,
	"business_impact" text NOT NULL,
	"recommended_actions" jsonb NOT NULL,
	"reference_links" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_status_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"finding_id" uuid NOT NULL,
	"from_status" "finding_status",
	"to_status" "finding_status" NOT NULL,
	"changed_by" uuid,
	"reason" text NOT NULL,
	"note" text,
	"scan_job_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"rule_id" text NOT NULL,
	"rule_version" integer NOT NULL,
	"fingerprint" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" "confidence" NOT NULL,
	"risk_score" integer NOT NULL,
	"risk_inputs" jsonb NOT NULL,
	"status" "finding_status" DEFAULT 'open' NOT NULL,
	"evidence" jsonb NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"recurrence_count" integer DEFAULT 0 NOT NULL,
	"assigned_to" uuid,
	"accepted_risk_reason" text,
	"accepted_risk_approved_by" uuid,
	"accepted_risk_review_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "findings_risk_score_range" CHECK ("findings"."risk_score" BETWEEN 0 AND 100),
	CONSTRAINT "findings_seen_order" CHECK ("findings"."last_seen_at" >= "findings"."first_seen_at"),
	CONSTRAINT "findings_resolved_at_consistent" CHECK (("findings"."status" = 'resolved') = ("findings"."resolved_at" IS NOT NULL)),
	CONSTRAINT "findings_accepted_risk_complete" CHECK ("findings"."status" <> 'accepted_risk' OR ("findings"."accepted_risk_reason" IS NOT NULL AND "findings"."accepted_risk_approved_by" IS NOT NULL AND "findings"."accepted_risk_review_at" IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"actor_type" "actor_type" NOT NULL,
	"actor_user_id" uuid,
	"action" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text,
	"request_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
ALTER TABLE "notification_preferences" ADD CONSTRAINT "notification_preferences_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "domain_verifications" ADD CONSTRAINT "domain_verifications_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "domain_verifications" ADD CONSTRAINT "domain_verifications_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "domains" ADD CONSTRAINT "domains_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_ips" ADD CONSTRAINT "asset_ips_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_owner_user_id_users_id_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_settings" ADD CONSTRAINT "application_settings_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_job_targets" ADD CONSTRAINT "scan_job_targets_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_job_targets" ADD CONSTRAINT "scan_job_targets_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_profile_scan_profiles_key_fk" FOREIGN KEY ("profile") REFERENCES "public"."scan_profiles"("key") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_worker_id_worker_registry_id_fk" FOREIGN KEY ("worker_id") REFERENCES "public"."worker_registry"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_observations" ADD CONSTRAINT "discovery_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_observations" ADD CONSTRAINT "discovery_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_observations" ADD CONSTRAINT "discovery_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_observations" ADD CONSTRAINT "discovery_observations_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_observations" ADD CONSTRAINT "dns_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_observations" ADD CONSTRAINT "dns_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_observations" ADD CONSTRAINT "dns_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "http_observations" ADD CONSTRAINT "http_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "http_observations" ADD CONSTRAINT "http_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "http_observations" ADD CONSTRAINT "http_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "port_observations" ADD CONSTRAINT "port_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "port_observations" ADD CONSTRAINT "port_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "port_observations" ADD CONSTRAINT "port_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "registration_observations" ADD CONSTRAINT "registration_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "registration_observations" ADD CONSTRAINT "registration_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "registration_observations" ADD CONSTRAINT "registration_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "registration_observations" ADD CONSTRAINT "registration_observations_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tls_observations" ADD CONSTRAINT "tls_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tls_observations" ADD CONSTRAINT "tls_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tls_observations" ADD CONSTRAINT "tls_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "advisories" ADD CONSTRAINT "advisories_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_status_history" ADD CONSTRAINT "finding_status_history_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_status_history" ADD CONSTRAINT "finding_status_history_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_status_history" ADD CONSTRAINT "finding_status_history_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_assigned_to_users_id_fk" FOREIGN KEY ("assigned_to") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_accepted_risk_approved_by_users_id_fk" FOREIGN KEY ("accepted_risk_approved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "notification_preferences_key" ON "notification_preferences" USING btree ("user_id","channel","event_type");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_key" ON "users" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "users_provider_subject_key" ON "users" USING btree ("auth_provider","auth_provider_subject");--> statement-breakpoint
CREATE INDEX "domain_verifications_domain_idx" ON "domain_verifications" USING btree ("domain_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "domain_verifications_one_pending" ON "domain_verifications" USING btree ("domain_id","method") WHERE "domain_verifications"."status" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX "domains_fqdn_key" ON "domains" USING btree ("fqdn");--> statement-breakpoint
CREATE UNIQUE INDEX "asset_ips_asset_ip_key" ON "asset_ips" USING btree ("asset_id","ip_address");--> statement-breakpoint
CREATE INDEX "asset_ips_ip_idx" ON "asset_ips" USING btree ("ip_address");--> statement-breakpoint
CREATE UNIQUE INDEX "assets_domain_hostname_key" ON "assets" USING btree ("domain_id","hostname");--> statement-breakpoint
CREATE INDEX "assets_hostname_idx" ON "assets" USING btree ("hostname");--> statement-breakpoint
CREATE INDEX "assets_status_idx" ON "assets" USING btree ("verification_status");--> statement-breakpoint
CREATE INDEX "assets_owner_idx" ON "assets" USING btree ("owner_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "worker_registry_name_key" ON "worker_registry" USING btree ("name");--> statement-breakpoint
CREATE INDEX "scan_job_targets_asset_idx" ON "scan_job_targets" USING btree ("asset_id");--> statement-breakpoint
CREATE UNIQUE INDEX "scan_jobs_idempotency_key" ON "scan_jobs" USING btree ("idempotency_key");--> statement-breakpoint
CREATE INDEX "scan_jobs_claim_idx" ON "scan_jobs" USING btree ("priority","scheduled_at") WHERE "scan_jobs"."status" = 'queued';--> statement-breakpoint
CREATE INDEX "scan_jobs_lease_idx" ON "scan_jobs" USING btree ("lease_expires_at") WHERE "scan_jobs"."status" IN ('claimed', 'running');--> statement-breakpoint
CREATE INDEX "scan_jobs_domain_idx" ON "scan_jobs" USING btree ("domain_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "discovery_observations_result_id_key" ON "discovery_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "discovery_observations_asset_time_idx" ON "discovery_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "discovery_observations_job_idx" ON "discovery_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "dns_observations_result_id_key" ON "dns_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "dns_observations_asset_time_idx" ON "dns_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "dns_observations_job_idx" ON "dns_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "http_observations_result_id_key" ON "http_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "http_observations_asset_time_idx" ON "http_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "http_observations_job_idx" ON "http_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "port_observations_result_id_key" ON "port_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "port_observations_asset_time_idx" ON "port_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "port_observations_job_idx" ON "port_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "registration_observations_result_id_key" ON "registration_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "registration_observations_asset_time_idx" ON "registration_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "registration_observations_job_idx" ON "registration_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tls_observations_result_id_key" ON "tls_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "tls_observations_asset_time_idx" ON "tls_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "tls_observations_job_idx" ON "tls_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "advisories_finding_key" ON "advisories" USING btree ("finding_id");--> statement-breakpoint
CREATE INDEX "finding_status_history_finding_idx" ON "finding_status_history" USING btree ("finding_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "findings_active_fingerprint_key" ON "findings" USING btree ("fingerprint") WHERE "findings"."status" <> 'resolved';--> statement-breakpoint
CREATE INDEX "findings_status_severity_idx" ON "findings" USING btree ("status","severity");--> statement-breakpoint
CREATE INDEX "findings_asset_idx" ON "findings" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "findings_assignee_idx" ON "findings" USING btree ("assigned_to");--> statement-breakpoint
CREATE INDEX "audit_logs_resource_idx" ON "audit_logs" USING btree ("resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "audit_logs_created_idx" ON "audit_logs" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "audit_logs_actor_idx" ON "audit_logs" USING btree ("actor_user_id");
-- Milestones 14–15: remediation SLAs (findings.due_at), daily security scores, monthly report
-- snapshots, brand (lookalike-domain) monitoring and IP-network ownership discovery. Additive.
-- Seeds: SLA policy, discovery organisation names, the weekly passive `brand` profile, and the
-- `network` check added to the discovery profile (version 2).
CREATE TABLE "domain_score_snapshots" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"domain_id" uuid NOT NULL,
	"day" date NOT NULL,
	"score" integer NOT NULL,
	"grade" text NOT NULL,
	"inputs" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "monthly_reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"period" date NOT NULL,
	"generated_at" timestamp with time zone NOT NULL,
	"data" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "lookalike_observations" (
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
	"candidate" text NOT NULL,
	"technique" text NOT NULL,
	"registered" boolean NOT NULL,
	"records" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "network_observations" (
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
	"domain_id" uuid,
	"ip_address" "inet" NOT NULL,
	"start_address" "inet",
	"end_address" "inet",
	"cidrs" text[] DEFAULT '{}' NOT NULL,
	"registry" text,
	"handle" text,
	"network_name" text,
	"org_name" text,
	"country" text,
	"matched_org" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
ALTER TABLE "domains" ADD COLUMN "brand_monitoring" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "due_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "domain_score_snapshots" ADD CONSTRAINT "domain_score_snapshots_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lookalike_observations" ADD CONSTRAINT "lookalike_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lookalike_observations" ADD CONSTRAINT "lookalike_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lookalike_observations" ADD CONSTRAINT "lookalike_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lookalike_observations" ADD CONSTRAINT "lookalike_observations_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "network_observations" ADD CONSTRAINT "network_observations_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "network_observations" ADD CONSTRAINT "network_observations_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "network_observations" ADD CONSTRAINT "network_observations_scan_job_target_id_scan_job_targets_id_fk" FOREIGN KEY ("scan_job_target_id") REFERENCES "public"."scan_job_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "network_observations" ADD CONSTRAINT "network_observations_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "domain_score_snapshots_domain_day_key" ON "domain_score_snapshots" USING btree ("domain_id","day");--> statement-breakpoint
CREATE UNIQUE INDEX "monthly_reports_period_key" ON "monthly_reports" USING btree ("period");--> statement-breakpoint
CREATE UNIQUE INDEX "lookalike_observations_result_id_key" ON "lookalike_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "lookalike_observations_asset_time_idx" ON "lookalike_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "lookalike_observations_job_idx" ON "lookalike_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE INDEX "lookalike_observations_domain_candidate_time_idx" ON "lookalike_observations" USING btree ("domain_id","candidate","observed_at" DESC NULLS LAST);--> statement-breakpoint
CREATE UNIQUE INDEX "network_observations_result_id_key" ON "network_observations" USING btree ("result_id");--> statement-breakpoint
CREATE INDEX "network_observations_asset_time_idx" ON "network_observations" USING btree ("asset_id","observed_at");--> statement-breakpoint
CREATE INDEX "network_observations_job_idx" ON "network_observations" USING btree ("scan_job_id");--> statement-breakpoint
CREATE INDEX "network_observations_ip_time_idx" ON "network_observations" USING btree ("ip_address","observed_at" DESC NULLS LAST);--> statement-breakpoint
INSERT INTO "application_settings" ("key", "value") VALUES
  ('sla_policy', '{"critical":7,"high":30,"medium":90,"low":180,"informational":null}'::jsonb),
  ('discovery_org_names', '["Thai Union"]'::jsonb)
ON CONFLICT ("key") DO NOTHING;--> statement-breakpoint
INSERT INTO "scan_profiles" ("key", "name", "description", "version", "config", "default_schedule") VALUES
  ('brand', 'Brand monitoring', 'Passive lookalike-domain monitoring: generates lookalike names of the domain (typos, homoglyphs, other TLDs) and checks through public resolvers whether they are registered. Never contacts the lookalike hosts or the domain''s own hosts.', 1, '{"active":false,"checks":["lookalike"],"tcpPorts":[],"timeouts":{"connectMs":5000,"readMs":10000,"targetSeconds":1800},"concurrency":8,"ratePerSecond":10,"maxTargets":1}'::jsonb, 'weekly')
ON CONFLICT ("key") DO NOTHING;--> statement-breakpoint
UPDATE "scan_profiles"
SET "version" = 2,
    "config" = jsonb_set("config", '{checks}', '["discovery","network"]'::jsonb),
    "description" = 'Passive subdomain discovery from Certificate Transparency logs (crt.sh, Cert Spotter) and reverse DNS of IP ranges registered to the organisation, with RDAP network ownership of current addresses. Never connects to the domain''s hosts; candidates are stored as pending assets and are never scanned until approved.'
WHERE "key" = 'discovery' AND "version" = 1;

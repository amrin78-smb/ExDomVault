-- Milestone 9: passive subdomain discovery. Assets record the last inventory decision (who, when,
-- why) and a deterministic hosting hint; discovery observations record wildcard-only names. Seeds the
-- `discovery` profile (passive, Certificate Transparency only, weekly); it never adds scan targets.
ALTER TABLE "assets" ADD COLUMN "decided_by" uuid;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "decided_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "decision_reason" text;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "hosting_hint" jsonb;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "wildcard_only" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "discovery_observations" ADD COLUMN "wildcard" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_decided_by_users_id_fk" FOREIGN KEY ("decided_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
INSERT INTO "scan_profiles" ("key", "name", "description", "version", "config", "default_schedule") VALUES
  ('discovery', 'Discovery', 'Passive subdomain discovery from Certificate Transparency logs, with DNS resolution of candidates through public resolvers. Never connects to the domain''s hosts; candidates are stored as pending assets and are never scanned until approved.', 1, '{"active":false,"checks":["discovery"],"tcpPorts":[],"timeouts":{"connectMs":10000,"readMs":60000,"targetSeconds":600},"concurrency":4,"ratePerSecond":5,"maxTargets":1}'::jsonb, 'weekly')
ON CONFLICT ("key") DO NOTHING;

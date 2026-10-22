-- Milestone 7: findings engine. findings gains domain_id/hostname/component/category (NOT NULL
-- without defaults: valid because no findings rows exist yet in any environment; no backfill), and
-- asset_id becomes nullable for domain-level findings. scan_jobs gains rules_evaluated_at; jobs that
-- succeeded before this migration are left NULL so the rules engine evaluates them (oldest first).
-- asset_id is SET NULL on asset deletion (findings keep their history; domain_id cascades).
ALTER TABLE "findings" DROP CONSTRAINT "findings_asset_id_assets_id_fk";
--> statement-breakpoint
ALTER TABLE "findings" ALTER COLUMN "asset_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_jobs" ADD COLUMN "rules_evaluated_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "domain_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "hostname" text NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "component" text NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "category" text NOT NULL;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "scan_jobs_rules_pending_idx" ON "scan_jobs" USING btree ("completed_at") WHERE "scan_jobs"."status" = 'succeeded' AND "scan_jobs"."rules_evaluated_at" IS NULL;--> statement-breakpoint
CREATE INDEX "findings_domain_status_idx" ON "findings" USING btree ("domain_id","status");--> statement-breakpoint
CREATE INDEX "findings_fingerprint_idx" ON "findings" USING btree ("fingerprint");--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_category_valid" CHECK ("findings"."category" IN ('dns', 'email', 'tls', 'http', 'exposure', 'registration', 'asset'));
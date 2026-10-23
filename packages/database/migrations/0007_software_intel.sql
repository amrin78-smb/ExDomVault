-- Milestone 11: exposed-software inventory and vulnerability intelligence (endoflife.date cycles,
-- CISA KEV entries with NVD version ranges, feed sync state); findings gain the 'software' category.
CREATE TABLE "intel_feeds" (
	"feed" text PRIMARY KEY NOT NULL,
	"last_success_at" timestamp with time zone,
	"last_attempt_at" timestamp with time zone,
	"last_error" text,
	"items" integer DEFAULT 0 NOT NULL,
	"source_version" text,
	"etag" text,
	"last_modified" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "software_eol_cycles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"product" text NOT NULL,
	"cycle" text NOT NULL,
	"release_date" date,
	"eol_date" date,
	"eol_boolean" boolean,
	"latest" text,
	"fetched_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "software_inventory" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"domain_id" uuid NOT NULL,
	"asset_id" uuid,
	"hostname" text,
	"ip_address" "inet",
	"port" integer,
	"source" text NOT NULL,
	"product" text NOT NULL,
	"version" text,
	"banner" text NOT NULL,
	"backport_distribution" text,
	"location_key" text NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"last_scan_job_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "software_inventory_source_valid" CHECK ("software_inventory"."source" IN ('http_header', 'service_identification'))
);
--> statement-breakpoint
CREATE TABLE "vulnerability_advisories" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"cve_id" text NOT NULL,
	"product" text NOT NULL,
	"ranges" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"cvss" real,
	"kev" boolean DEFAULT false NOT NULL,
	"kev_date_added" date,
	"ransomware" boolean DEFAULT false NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"published_at" timestamp with time zone,
	"nvd_fetched_at" timestamp with time zone,
	"nvd_status" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vulnerability_advisories_cve_format" CHECK ("vulnerability_advisories"."cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,}$')
);
--> statement-breakpoint
ALTER TABLE "findings" DROP CONSTRAINT "findings_category_valid";--> statement-breakpoint
ALTER TABLE "software_inventory" ADD CONSTRAINT "software_inventory_domain_id_domains_id_fk" FOREIGN KEY ("domain_id") REFERENCES "public"."domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "software_inventory" ADD CONSTRAINT "software_inventory_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "software_inventory" ADD CONSTRAINT "software_inventory_last_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("last_scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "software_eol_cycles_key" ON "software_eol_cycles" USING btree ("product","cycle");--> statement-breakpoint
CREATE UNIQUE INDEX "software_inventory_location_key" ON "software_inventory" USING btree ("domain_id","location_key");--> statement-breakpoint
CREATE INDEX "software_inventory_product_idx" ON "software_inventory" USING btree ("product","version");--> statement-breakpoint
CREATE UNIQUE INDEX "vulnerability_advisories_key" ON "vulnerability_advisories" USING btree ("cve_id","product");--> statement-breakpoint
CREATE INDEX "vulnerability_advisories_pending_idx" ON "vulnerability_advisories" USING btree ("nvd_fetched_at");--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_category_valid" CHECK ("findings"."category" IN ('dns', 'email', 'tls', 'http', 'exposure', 'registration', 'asset', 'software'));
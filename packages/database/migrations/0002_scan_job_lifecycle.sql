CREATE TABLE "worker_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"worker_id" uuid NOT NULL,
	"public_key" text NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	CONSTRAINT "worker_credentials_expiry_after_creation" CHECK ("worker_credentials"."expires_at" > "worker_credentials"."created_at")
);
--> statement-breakpoint
CREATE TABLE "worker_request_nonces" (
	"credential_id" uuid NOT NULL,
	"nonce" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "worker_request_nonces_credential_id_nonce_pk" PRIMARY KEY("credential_id","nonce")
);
--> statement-breakpoint
CREATE TABLE "scan_job_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_job_id" uuid NOT NULL,
	"result_id" text NOT NULL,
	"attempt" integer NOT NULL,
	"worker_id" uuid,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"summary" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
ALTER TABLE "worker_credentials" ADD CONSTRAINT "worker_credentials_worker_id_worker_registry_id_fk" FOREIGN KEY ("worker_id") REFERENCES "public"."worker_registry"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "worker_credentials" ADD CONSTRAINT "worker_credentials_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "worker_request_nonces" ADD CONSTRAINT "worker_request_nonces_credential_id_worker_credentials_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."worker_credentials"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_job_results" ADD CONSTRAINT "scan_job_results_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_job_results" ADD CONSTRAINT "scan_job_results_worker_id_worker_registry_id_fk" FOREIGN KEY ("worker_id") REFERENCES "public"."worker_registry"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "worker_credentials_worker_idx" ON "worker_credentials" USING btree ("worker_id");--> statement-breakpoint
CREATE UNIQUE INDEX "worker_credentials_public_key_key" ON "worker_credentials" USING btree ("public_key");--> statement-breakpoint
CREATE INDEX "worker_request_nonces_rate_idx" ON "worker_request_nonces" USING btree ("credential_id","created_at");--> statement-breakpoint
CREATE INDEX "worker_request_nonces_created_idx" ON "worker_request_nonces" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "scan_job_results_key" ON "scan_job_results" USING btree ("scan_job_id","result_id");--> statement-breakpoint
CREATE UNIQUE INDEX "scan_jobs_one_active_per_domain_profile" ON "scan_jobs" USING btree ("domain_id","profile") WHERE "scan_jobs"."status" IN ('queued', 'claimed', 'running');--> statement-breakpoint
-- Seed (hand-added): server-defined scan profiles (design §6). Conservative defaults; the application
-- validates `config` with scanProfileConfigSchema. Existing rows are left untouched.
INSERT INTO "scan_profiles" ("key", "name", "description", "version", "config", "default_schedule") VALUES
  ('passive', 'Passive', 'DNS records and registration (RDAP) data from public resolvers and registries. Never connects to the domain''s own hosts, so it runs for any monitored domain.', 1, '{"active":false,"checks":["dns","rdap"],"tcpPorts":[],"timeouts":{"connectMs":3000,"readMs":5000,"targetSeconds":60},"concurrency":4,"ratePerSecond":5,"maxTargets":50}'::jsonb, 'daily'),
  ('quick', 'Quick', 'Passive checks plus TLS certificate validity and expiry and lightweight HTTP availability. Requires a verified domain.', 1, '{"active":true,"checks":["dns","rdap","tls_certificate","http_availability"],"tcpPorts":[],"timeouts":{"connectMs":5000,"readMs":10000,"targetSeconds":120},"concurrency":4,"ratePerSecond":2,"maxTargets":50}'::jsonb, 'daily'),
  ('standard', 'Standard', 'Quick checks plus HTTP security headers, approved TCP port checks and limited service identification. Requires a verified domain.', 1, '{"active":true,"checks":["dns","rdap","tls_certificate","http_availability","http_headers","tcp_ports","service_identification"],"tcpPorts":[21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017],"timeouts":{"connectMs":5000,"readMs":10000,"targetSeconds":600},"concurrency":2,"ratePerSecond":1,"maxTargets":50}'::jsonb, 'weekly'),
  ('deep', 'Deep', 'Standard checks with expanded approved port coverage, fuller service identification and additional TLS configuration checks. Requires a verified domain; run on request.', 1, '{"active":true,"checks":["dns","rdap","tls_certificate","http_availability","http_headers","tcp_ports","service_identification","tls_configuration"],"tcpPorts":[21,22,23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,636,873,993,995,1080,1194,1433,1521,1723,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900,5984,6379,6443,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,9200,9443,10250,11211,15672,27017],"timeouts":{"connectMs":5000,"readMs":15000,"targetSeconds":1800},"concurrency":1,"ratePerSecond":0.5,"maxTargets":50}'::jsonb, 'monthly')
ON CONFLICT ("key") DO NOTHING;

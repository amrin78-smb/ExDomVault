-- Milestone 13: IP geolocation country on asset addresses (display-only, from the worker's DB-IP
-- Lite lookup) and latest-per-key indexes for the port and certificate inventory views. Additive.
ALTER TABLE "asset_ips" ADD COLUMN "country_code" text;--> statement-breakpoint
CREATE INDEX "port_observations_ip_port_time_idx" ON "port_observations" USING btree ("ip_address","port","protocol","observed_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "tls_observations_host_port_time_idx" ON "tls_observations" USING btree ("hostname","port","observed_at" DESC NULLS LAST);--> statement-breakpoint
ALTER TABLE "asset_ips" ADD CONSTRAINT "asset_ips_country_code_format" CHECK ("asset_ips"."country_code" ~ '^[A-Z]{2}$');
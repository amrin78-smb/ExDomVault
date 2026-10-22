ALTER TYPE "public"."challenge_status" ADD VALUE 'revoked';--> statement-breakpoint
ALTER TYPE "public"."verification_method" ADD VALUE 'admin_attestation';--> statement-breakpoint
ALTER TABLE "domain_verifications" ALTER COLUMN "challenge_hash" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "domain_verifications" ADD COLUMN "reason" text;--> statement-breakpoint
ALTER TABLE "domain_verifications" ADD COLUMN "reference" text;--> statement-breakpoint
ALTER TABLE "domains" ADD COLUMN "verification_method" "verification_method";--> statement-breakpoint
ALTER TABLE "domains" ADD COLUMN "verification_expires_at" timestamp with time zone;--> statement-breakpoint
-- Backfill (hand-added): domains verified before this migration were verified by DNS TXT.
UPDATE "domains" SET "verification_method" = 'dns_txt' WHERE "verification_status" = 'verified';--> statement-breakpoint
ALTER TABLE "domain_verifications" ADD CONSTRAINT "domain_verifications_method_fields" CHECK (CASE "domain_verifications"."method"
        WHEN 'dns_txt' THEN "domain_verifications"."challenge_hash" IS NOT NULL AND "domain_verifications"."reason" IS NULL
        ELSE "domain_verifications"."challenge_hash" IS NULL AND "domain_verifications"."reason" IS NOT NULL END);--> statement-breakpoint
ALTER TABLE "domains" ADD CONSTRAINT "domains_verification_method_consistent" CHECK (("domains"."verification_status" = 'verified') = ("domains"."verification_method" IS NOT NULL));--> statement-breakpoint
ALTER TABLE "domains" ADD CONSTRAINT "domains_attestation_has_review_date" CHECK (COALESCE("domains"."verification_method" <> 'dns_txt', false) = ("domains"."verification_expires_at" IS NOT NULL));
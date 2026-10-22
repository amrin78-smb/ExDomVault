-- Milestone 8: finding lifecycle. finding_comments holds remediation notes (append-only); a partial
-- index on accepted_risk_review_at supports the cron sweep that lapses expired risk acceptances.
CREATE TABLE "finding_comments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"finding_id" uuid NOT NULL,
	"author_user_id" uuid,
	"body" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "finding_comments_body_length" CHECK (char_length("finding_comments"."body") BETWEEN 1 AND 4000)
);
--> statement-breakpoint
ALTER TABLE "finding_comments" ADD CONSTRAINT "finding_comments_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_comments" ADD CONSTRAINT "finding_comments_author_user_id_users_id_fk" FOREIGN KEY ("author_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "finding_comments_finding_idx" ON "finding_comments" USING btree ("finding_id","created_at");--> statement-breakpoint
CREATE INDEX "findings_accepted_risk_review_idx" ON "findings" USING btree ("accepted_risk_review_at") WHERE "findings"."status" = 'accepted_risk';
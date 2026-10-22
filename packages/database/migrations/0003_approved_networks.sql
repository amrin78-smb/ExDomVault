CREATE TABLE "approved_networks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"cidr" "cidr" NOT NULL,
	"label" text NOT NULL,
	"reason" text NOT NULL,
	"reference" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	"revoked_by" uuid,
	CONSTRAINT "approved_networks_reason_not_empty" CHECK (length(btrim("approved_networks"."reason")) > 0),
	CONSTRAINT "approved_networks_expiry_after_creation" CHECK ("approved_networks"."expires_at" > "approved_networks"."created_at"),
	CONSTRAINT "approved_networks_revoke_reason" CHECK ("approved_networks"."revoked_at" is null or "approved_networks"."revoke_reason" is not null)
);
--> statement-breakpoint
ALTER TABLE "approved_networks" ADD CONSTRAINT "approved_networks_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approved_networks" ADD CONSTRAINT "approved_networks_revoked_by_users_id_fk" FOREIGN KEY ("revoked_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "approved_networks_cidr_active_key" ON "approved_networks" USING btree ("cidr") WHERE "approved_networks"."revoked_at" is null;
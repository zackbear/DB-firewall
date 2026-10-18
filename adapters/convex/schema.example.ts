/**
 * Example schema for the DB Firewall Convex adapter.
 * Every tenant-owned table needs the `tenantId` field and the `by_tenant` index;
 * `tenant.ts` relies on both. Copy into convex/schema.ts.
 */
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  orders: defineTable({
    tenantId: v.string(),
    customer: v.string(),
    total: v.number(),
  }).index("by_tenant", ["tenantId"]),

  customers: defineTable({
    tenantId: v.string(),
    name: v.string(),
    email: v.string(),
  })
    .index("by_tenant", ["tenantId"])
    // Compound indexes must still lead with tenantId so lookups stay scoped.
    .index("by_tenant_email", ["tenantId", "email"]),
});

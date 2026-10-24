import { z } from 'zod';

// Branded types for security-critical strings (AGENTS.md Rule 3)
export const CsrfTokenSchema = z.string().min(16).brand<'CsrfToken'>();
export type CsrfToken = z.infer<typeof CsrfTokenSchema>;

export const RecordIdSchema = z.string().min(1).max(128).brand<'RecordId'>();
export type RecordId = z.infer<typeof RecordIdSchema>;

export const ZoneIdSchema = z.string().min(1).max(128).brand<'ZoneId'>();
export type ZoneId = z.infer<typeof ZoneIdSchema>;

export const RuleIdSchema = z.string().min(1).max(128).brand<'RuleId'>();
export type RuleId = z.infer<typeof RuleIdSchema>;

export const AdminRoleSchema = z.enum(['SuperAdmin', 'Admin', 'ReadOnly']);
export type AdminRole = z.infer<typeof AdminRoleSchema>;

export const ProblemDetailsSchema = z.object({
  type: z.string(),
  title: z.string(),
  status: z.number(),
  detail: z.string(),
  code: z.string(),
  request_id: z.string().optional()
});
export type ProblemDetails = z.infer<typeof ProblemDetailsSchema>;

export function createPaginatedSchema<T extends z.ZodType>(itemSchema: T) {
  return z.object({
    items: z.array(itemSchema),
    total: z.number().int().nonnegative(),
    page: z.number().int().positive(),
    per_page: z.number().int().positive().max(100)
  });
}

export interface PaginatedList<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

export type NavigationTab = 'records' | 'policy' | 'lookup' | 'telemetry';

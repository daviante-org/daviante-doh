import { z } from 'zod';
import { AdminRoleSchema, CsrfTokenSchema } from '../../../types';

export const SessionStatusResponseSchema = z.object({
  authenticated: z.boolean(),
  username: z
    .string()
    .nullable()
    .optional()
    .transform((v) => v ?? null),
  role: AdminRoleSchema.nullable()
    .optional()
    .transform((v) => v ?? null),
  auth_method: z
    .string()
    .nullable()
    .optional()
    .transform((v) => v ?? null),
  csrf_token: CsrfTokenSchema.nullable()
    .optional()
    .transform((v) => v ?? null),
  local_auth_enabled: z.boolean(),
  oidc_enabled: z.boolean(),
  oidc_provider_name: z
    .string()
    .nullable()
    .optional()
    .transform((v) => v ?? null)
});
export type SessionStatusResponse = z.infer<typeof SessionStatusResponseSchema>;

export interface LoginViewProps {
  readonly localAuthEnabled: boolean;
  readonly oidcEnabled: boolean;
  readonly oidcProviderName: string | null;
  readonly onLoginLocal: (username: string, password: string) => Promise<void>;
}

export interface CredentialRecoveryModalProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
}

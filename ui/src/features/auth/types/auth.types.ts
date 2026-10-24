import { z } from 'zod';
import { AdminRoleSchema, CsrfTokenSchema } from '../../../types';

export const SessionStatusResponseSchema = z.object({
  authenticated: z.boolean(),
  username: z.string().nullable(),
  role: AdminRoleSchema.nullable(),
  auth_method: z.string().nullable(),
  csrf_token: CsrfTokenSchema.nullable(),
  local_auth_enabled: z.boolean(),
  oidc_enabled: z.boolean(),
  oidc_provider_name: z.string().nullable()
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

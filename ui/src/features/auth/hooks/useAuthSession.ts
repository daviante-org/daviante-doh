import { useEffect, useState } from 'react';
import { AdminApiError, mapErrorCodeToStaticMessage } from '../../../services';
import type { AdminRole } from '../../../types';
import { authService } from '../services/authService';

export type AuthViewState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'unauthenticated';
      readonly localAuthEnabled: boolean;
      readonly oidcEnabled: boolean;
      readonly oidcProviderName: string | null;
    }
  | {
      readonly status: 'authenticated';
      readonly username: string;
      readonly role: AdminRole;
      readonly authMethod: string;
    }
  | { readonly status: 'error'; readonly message: string };

export function useAuthSession() {
  const [authState, setAuthState] = useState<AuthViewState>({ status: 'loading' });

  const refreshSession = async (): Promise<void> => {
    setAuthState({ status: 'loading' });
    try {
      const session = await authService.getSession();
      if (session.authenticated && session.username !== null && session.role !== null) {
        setAuthState({
          status: 'authenticated',
          username: session.username,
          role: session.role,
          authMethod: session.auth_method ?? 'local'
        });
      } else {
        setAuthState({
          status: 'unauthenticated',
          localAuthEnabled: session.local_auth_enabled,
          oidcEnabled: session.oidc_enabled,
          oidcProviderName: session.oidc_provider_name
        });
      }
    } catch (err: unknown) {
      if (err instanceof AdminApiError) {
        setAuthState({ status: 'error', message: err.userMessage });
      } else {
        setAuthState({
          status: 'error',
          message: mapErrorCodeToStaticMessage('NETWORK_ERROR')
        });
      }
    }
  };

  useEffect(() => {
    void refreshSession();
  }, []);

  const handleLoginLocal = async (username: string, password: string): Promise<void> => {
    const session = await authService.loginLocal(username, password);
    if (session.authenticated && session.username !== null && session.role !== null) {
      setAuthState({
        status: 'authenticated',
        username: session.username,
        role: session.role,
        authMethod: session.auth_method ?? 'local'
      });
    }
  };

  const handleLogout = async (): Promise<void> => {
    try {
      await authService.logout();
    } finally {
      await refreshSession();
    }
  };

  return {
    authState,
    refreshSession,
    handleLoginLocal,
    handleLogout
  };
}

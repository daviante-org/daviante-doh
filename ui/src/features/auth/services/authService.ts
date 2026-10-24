import { z } from 'zod';
import { httpClient } from '../../../services';
import { SessionStatusResponseSchema, type SessionStatusResponse } from '../types/auth.types';

export const authService = {
  async getSession(): Promise<SessionStatusResponse> {
    const session = await httpClient.request('/api/v1/auth/session', { method: 'GET' }, SessionStatusResponseSchema);
    httpClient.setCsrfToken(session.csrf_token);
    return session;
  },

  async loginLocal(username: string, password: string): Promise<SessionStatusResponse> {
    const session = await httpClient.request(
      '/api/v1/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ username, password })
      },
      SessionStatusResponseSchema
    );
    httpClient.setCsrfToken(session.csrf_token);
    return session;
  },

  async logout(): Promise<void> {
    await httpClient.request(
      '/api/v1/auth/logout',
      { method: 'POST', body: JSON.stringify({}) },
      z.object({ ok: z.boolean() })
    );
    httpClient.setCsrfToken(null);
  }
};

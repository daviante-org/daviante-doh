import type { z } from 'zod';
import { type CsrfToken, ProblemDetailsSchema } from '../types';
import { assertNever } from '../utils';

export type ApiErrorCode =
  | 'UNAUTHENTICATED'
  | 'SESSION_EXPIRED'
  | 'INVALID_CREDENTIALS'
  | 'LOCAL_AUTH_DISABLED'
  | 'OIDC_DISABLED'
  | 'OIDC_FLOW_FAILED'
  | 'OIDC_TOKEN_EXCHANGE_FAILED'
  | 'OIDC_USERINFO_FAILED'
  | 'CSRF_REQUIRED'
  | 'CSRF_INVALID'
  | 'ORIGIN_FORBIDDEN'
  | 'INSUFFICIENT_ROLE'
  | 'RATE_LIMITED'
  | 'PAYLOAD_TOO_LARGE'
  | 'INVALID_JSON'
  | 'VALIDATION_FAILED'
  | 'CNAME_CONFLICT'
  | 'CNAME_LOOP'
  | 'RECORD_NOT_FOUND'
  | 'ZONE_NOT_FOUND'
  | 'ZONE_CONFLICT'
  | 'RULE_NOT_FOUND'
  | 'UPSTREAM_LOOKUP_FAILED'
  | 'STORAGE_FAULT'
  | 'NETWORK_ERROR'
  | 'SCHEMA_VALIDATION_ERROR'
  | 'UNKNOWN_ERROR';

const KNOWN_ERROR_CODES: ReadonlySet<ApiErrorCode> = new Set<ApiErrorCode>([
  'UNAUTHENTICATED',
  'SESSION_EXPIRED',
  'INVALID_CREDENTIALS',
  'LOCAL_AUTH_DISABLED',
  'OIDC_DISABLED',
  'OIDC_FLOW_FAILED',
  'OIDC_TOKEN_EXCHANGE_FAILED',
  'OIDC_USERINFO_FAILED',
  'CSRF_REQUIRED',
  'CSRF_INVALID',
  'ORIGIN_FORBIDDEN',
  'INSUFFICIENT_ROLE',
  'RATE_LIMITED',
  'PAYLOAD_TOO_LARGE',
  'INVALID_JSON',
  'VALIDATION_FAILED',
  'CNAME_CONFLICT',
  'CNAME_LOOP',
  'RECORD_NOT_FOUND',
  'ZONE_NOT_FOUND',
  'ZONE_CONFLICT',
  'RULE_NOT_FOUND',
  'UPSTREAM_LOOKUP_FAILED',
  'STORAGE_FAULT',
  'NETWORK_ERROR',
  'SCHEMA_VALIDATION_ERROR',
  'UNKNOWN_ERROR'
]);

export function toKnownErrorCode(raw: string): ApiErrorCode {
  if (KNOWN_ERROR_CODES.has(raw as ApiErrorCode)) {
    return raw as ApiErrorCode;
  }
  return 'UNKNOWN_ERROR';
}

/**
 * Static mapped messages chosen by backend error code (AGENTS.md Rule 4.2 & Rule 3).
 * Never renders raw backend errors or stack traces.
 */
export function mapErrorCodeToStaticMessage(code: ApiErrorCode): string {
  switch (code) {
    case 'UNAUTHENTICATED':
    case 'SESSION_EXPIRED':
      return 'Your session has expired or you are not signed in. Please sign in again.';
    case 'INVALID_CREDENTIALS':
      return 'Invalid username or password.';
    case 'LOCAL_AUTH_DISABLED':
      return 'Local username/password sign-in is disabled on this server.';
    case 'OIDC_DISABLED':
      return 'Single Sign-On (OIDC) is not enabled on this server.';
    case 'OIDC_FLOW_FAILED':
    case 'OIDC_TOKEN_EXCHANGE_FAILED':
    case 'OIDC_USERINFO_FAILED':
      return 'Single Sign-On authentication failed. Please try signing in again.';
    case 'CSRF_REQUIRED':
    case 'CSRF_INVALID':
      return 'Security token verification failed. Please refresh the page and try again.';
    case 'ORIGIN_FORBIDDEN':
      return 'Cross-origin request was blocked by security policy.';
    case 'INSUFFICIENT_ROLE':
      return 'Your account role does not have permission to perform this action.';
    case 'RATE_LIMITED':
      return 'Too many requests in a short period. Please wait a moment before retrying.';
    case 'PAYLOAD_TOO_LARGE':
      return 'The submitted payload exceeds the maximum allowed size.';
    case 'INVALID_JSON':
      return 'The request payload could not be parsed.';
    case 'VALIDATION_FAILED':
      return 'One or more fields failed DNS or RFC validation. Check the highlighted fields and try again.';
    case 'CNAME_CONFLICT':
      return 'RFC 2181 §10.1 conflict: a CNAME record cannot coexist with any other record type at the same domain name.';
    case 'CNAME_LOOP':
      return 'CNAME loop detected: this alias target creates a circular resolution chain.';
    case 'RECORD_NOT_FOUND':
      return 'The requested DNS record no longer exists.';
    case 'ZONE_NOT_FOUND':
      return 'The selected DNS zone no longer exists.';
    case 'ZONE_CONFLICT':
      return 'A DNS zone with this domain name already exists.';
    case 'RULE_NOT_FOUND':
      return 'The requested protective DNS policy rule no longer exists.';
    case 'UPSTREAM_LOOKUP_FAILED':
      return 'The live DNS diagnostic query timed out or failed against the upstream resolver.';
    case 'STORAGE_FAULT':
      return 'A persistent storage error occurred on the server.';
    case 'NETWORK_ERROR':
      return 'Unable to reach the DoH Admin API. Check your network connection.';
    case 'SCHEMA_VALIDATION_ERROR':
      return 'The server returned an unexpected response format.';
    case 'UNKNOWN_ERROR':
      return 'An unexpected error occurred while processing your request.';
    default:
      return assertNever(code);
  }
}

export class AdminApiError extends Error {
  public readonly code: ApiErrorCode;
  public readonly status: number;
  public readonly userMessage: string;

  constructor(code: ApiErrorCode, status: number) {
    const userMessage = mapErrorCodeToStaticMessage(code);
    super(userMessage);
    this.name = 'AdminApiError';
    this.code = code;
    this.status = status;
    this.userMessage = userMessage;
  }
}

/**
 * Shared HTTP Client (AGENTS.md Rule 4.3).
 * Never stores tokens in localStorage or sessionStorage; keeps the CSRF token in memory only.
 */
export class HttpClient {
  private csrfToken: CsrfToken | null = null;

  public setCsrfToken(token: CsrfToken | null): void {
    this.csrfToken = token;
  }

  public getCsrfToken(): CsrfToken | null {
    return this.csrfToken;
  }

  public async request<T>(
    path: string,
    options: RequestInit,
    schema: z.ZodType<T>
  ): Promise<T> {
    const method = (options.method ?? 'GET').toUpperCase();
    const headers = new Headers(options.headers);

    if (options.body !== undefined && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    if (
      (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') &&
      this.csrfToken !== null
    ) {
      headers.set('X-CSRF-Token', this.csrfToken);
    }

    let response: Response;
    try {
      response = await fetch(path, {
        ...options,
        method,
        headers,
        credentials: 'same-origin'
      });
    } catch {
      throw new AdminApiError('NETWORK_ERROR', 0);
    }

    let rawJson: unknown;
    try {
      rawJson = await response.json();
    } catch {
      throw new AdminApiError(
        response.ok ? 'SCHEMA_VALIDATION_ERROR' : 'UNKNOWN_ERROR',
        response.status
      );
    }

    if (!response.ok) {
      const parsedProblem = ProblemDetailsSchema.safeParse(rawJson);
      if (parsedProblem.success) {
        const code = toKnownErrorCode(parsedProblem.data.code);
        throw new AdminApiError(code, response.status);
      }
      throw new AdminApiError('UNKNOWN_ERROR', response.status);
    }

    const parsedData = schema.safeParse(rawJson);
    if (!parsedData.success) {
      throw new AdminApiError('SCHEMA_VALIDATION_ERROR', response.status);
    }

    return parsedData.data;
  }
}

export const httpClient = new HttpClient();

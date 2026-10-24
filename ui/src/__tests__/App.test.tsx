import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AppShell } from '../components';
import { LoginView } from '../features/auth';
import { dnsRecordsService } from '../features/dns-records';
import { LocalDnsRecordsPage } from '../pages';
import { mapErrorCodeToStaticMessage, toKnownErrorCode } from '../services';
import { RecordIdSchema, ZoneIdSchema } from '../types';

describe('LoginView, Branding, Governance & Static Error Mapping (Rule 4.2 & OWASP A07)', () => {
  it('shows a single generic error message on failed login and switches between /logo.svg (light) and /logo-dark.svg (dark)', async () => {
    document.documentElement.classList.remove('pf-v6-theme-dark');
    const mockLogin = vi.fn().mockRejectedValue(new Error('backend detailed error'));

    render(
      <LoginView
        localAuthEnabled={true}
        oidcEnabled={true}
        oidcProviderName="Keycloak OIDC"
        onLoginLocal={mockLogin}
      />
    );

    const brandImg = screen.getByAltText(
      'Daviante DoH — Enterprise DNS & Protective Policy Control-Plane'
    );
    expect(brandImg).toHaveAttribute('src', '/logo.svg');

    // Toggle dark theme on LoginView -> brandImg switches to /logo-dark.svg
    const darkSwitch = screen.getByLabelText(/Dark theme/i, { selector: 'input' });
    fireEvent.click(darkSwitch);
    expect(brandImg).toHaveAttribute('src', '/logo-dark.svg');
    fireEvent.click(darkSwitch);
    expect(brandImg).toHaveAttribute('src', '/logo.svg');

    const orgLink = screen.getByRole('link', { name: /Daviante Organization/i });
    expect(orgLink).toHaveAttribute('href', 'https://github.com/orgs/daviante-org');
    expect(orgLink).toHaveAttribute('rel', 'noopener noreferrer');

    const userField = screen.getByLabelText(/Username/i, { selector: 'input' });
    const passField = screen.getByLabelText(/^Password/i, { selector: 'input' });
    fireEvent.change(userField, { target: { value: 'admin' } });
    fireEvent.change(passField, { target: { value: 'wrong-pass' } });

    const signInBtn = screen.getByRole('button', { name: /^Sign in$/i });
    fireEvent.click(signInBtn);

    await waitFor(() => {
      expect(screen.getByText('Invalid username or password.')).toBeInTheDocument();
    });

    const oidcBtn = screen.getByTestId('oidc-sso-button');
    expect(oidcBtn).toHaveAttribute('href', '/api/v1/auth/oidc/login');

    // Open Terms of Service modal from login footer
    const termsLink = screen.getByRole('link', { name: /Terms of Service/i });
    fireEvent.click(termsLink);

    await waitFor(() => {
      expect(
        screen.getByText('Daviante DoH — Governance, Terms, Privacy & Security Policies')
      ).toBeInTheDocument();
    });
  });

  it('renders AppShell with /logo.svg (light) and /logo-dark.svg (dark), Policies & Terms modal, and AboutModal with /favicon.svg', async () => {
    document.documentElement.classList.remove('pf-v6-theme-dark');
    const mockLogout = vi.fn().mockResolvedValue(undefined);
    const mockSelectTab = vi.fn();

    render(
      <AppShell
        activeTab="records"
        onSelectTab={mockSelectTab}
        username="admin"
        role="Admin"
        authMethod="local"
        onLogout={mockLogout}
      >
        <div>Workspace Content</div>
      </AppShell>
    );

    const mastheadLogo = screen.getByAltText('Daviante DoH Control-Plane');
    expect(mastheadLogo).toHaveAttribute('src', '/logo.svg');

    // Toggle dark theme in Masthead -> switches to /logo-dark.svg
    const darkSwitch = screen.getByLabelText(/Dark theme/i, { selector: 'input' });
    fireEvent.click(darkSwitch);
    expect(mastheadLogo).toHaveAttribute('src', '/logo-dark.svg');

    const aboutBtn = screen.getByRole('button', { name: /About Daviante DoH/i });
    fireEvent.click(aboutBtn);

    await waitFor(() => {
      expect(
        screen.getByText('Daviante DoH Enterprise Control-Plane')
      ).toBeInTheDocument();
    });

    const aboutEmblem = screen.getByAltText('Daviante DoH Emblem');
    expect(aboutEmblem).toHaveAttribute('src', '/favicon.svg');
  });

  it('renders LocalDnsRecordsPage master-detail zone navigator, RDATA value summary, category filter, and Clone modal', async () => {
    vi.spyOn(dnsRecordsService, 'listZones').mockResolvedValue([
      {
        id: ZoneIdSchema.parse('zone-1'),
        name: 'internal.corp',
        mode: 'authoritative',
        primary_ns: 'ns1.internal.corp',
        admin_email: 'dnsops.internal.corp',
        serial: 2026102401,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: 300,
        default_ttl: 300,
        enabled: true,
        comment: 'Corporate internal zone',
        updated_at_epoch: 1730000000,
        record_count: 2
      }
    ]);

    vi.spyOn(dnsRecordsService, 'listRecords').mockResolvedValue({
      items: [
        {
          id: RecordIdSchema.parse('rec-1'),
          zone_id: 'zone-1',
          domain: 'api.internal.corp',
          ttl: 300,
          enabled: true,
          comment: 'Primary API gateway',
          updated_at: '2026-10-24T16:00:00Z',
          updated_at_epoch: 1730000000,
          rr_type_code: 1,
          bind_preview: 'api.internal.corp. 300 IN A 10.20.0.10',
          record: {
            type: 'A',
            ip: '10.20.0.10',
            auto_ptr: true
          }
        }
      ],
      total: 1,
      page: 1,
      per_page: 20
    });

    render(<LocalDnsRecordsPage role="Admin" />);

    await waitFor(() => {
      expect(screen.getByText('api.internal.corp')).toBeInTheDocument();
    });

    // Check RDATA value summary badge and human-friendly TTL
    expect(screen.getByText('Auto-PTR')).toBeInTheDocument();
    expect(screen.getByText('5m (300s)')).toBeInTheDocument();

    // Click Clone button -> opens CloudflareRecordModal in Clone mode
    const cloneBtn = screen.getByRole('button', { name: /Clone api.internal.corp/i });
    fireEvent.click(cloneBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/Clone Local DNS Record \(A — api\.internal\.corp\)/i)
      ).toBeInTheDocument();
    });
  });

  it('maps all backend error codes to static user-safe messages', () => {
    expect(mapErrorCodeToStaticMessage(toKnownErrorCode('INVALID_CREDENTIALS'))).toBe(
      'Invalid username or password.'
    );
    expect(mapErrorCodeToStaticMessage(toKnownErrorCode('CNAME_CONFLICT'))).toContain(
      'RFC 2181'
    );
    expect(mapErrorCodeToStaticMessage(toKnownErrorCode('UNEXPECTED_RAW_CODE'))).toBe(
      'An unexpected error occurred while processing your request.'
    );
  });
});

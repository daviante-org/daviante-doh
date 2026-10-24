import React, { useState } from 'react';
import {
  Alert,
  Button,
  Divider,
  ListVariant,
  LoginFooterItem,
  LoginForm,
  LoginMainFooterBandItem,
  LoginPage,
  Stack,
  StackItem,
  Switch
} from '@patternfly/react-core';
import { LegalPoliciesModal, type LegalPolicyTab } from '../../../components';
import { DAVIANTE_ORG_URL } from '../../../constants';
import { useDarkTheme } from '../../../hooks';
import { isSafeHrefUrl } from '../../../utils';
import type { LoginViewProps } from '../types/auth.types';
import { CredentialRecoveryModal } from './CredentialRecoveryModal';

const OIDC_LOGIN_PATH = '/api/v1/auth/oidc/login';

export function LoginView({
  localAuthEnabled,
  oidcEnabled,
  oidcProviderName,
  onLoginLocal
}: LoginViewProps): React.JSX.Element {
  const { isDarkTheme, setIsDarkTheme } = useDarkTheme();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showInvalidCreds, setShowInvalidCreds] = useState(false);
  const [legalModalOpen, setLegalModalOpen] = useState(false);
  const [legalModalTab, setLegalModalTab] = useState<LegalPolicyTab>('terms');
  const [recoveryModalOpen, setRecoveryModalOpen] = useState(false);

  const openPolicyTab = (tab: LegalPolicyTab): void => {
    setLegalModalTab(tab);
    setLegalModalOpen(true);
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (!username.trim() || !password) {
      setShowInvalidCreds(true);
      return;
    }
    setIsSubmitting(true);
    setShowInvalidCreds(false);
    try {
      await onLoginLocal(username.trim(), password);
      setPassword('');
    } catch {
      // Single error channel & generic auth error message (AGENTS.md Rule 4.2, OWASP A07)
      setShowInvalidCreds(true);
      setPassword('');
    } finally {
      setIsSubmitting(false);
    }
  };

  const footerItems = (
    <>
      <LoginFooterItem>
        <Switch
          id="login-dark-theme-toggle"
          label="Dark theme"
          isChecked={isDarkTheme}
          onChange={(_event, checked) => { setIsDarkTheme(checked); }}
        />
      </LoginFooterItem>
      <LoginFooterItem
        href="#terms"
        onClick={(e) => {
          e.preventDefault();
          openPolicyTab('terms');
        }}
      >
        Terms of Service
      </LoginFooterItem>
      <LoginFooterItem
        href="#privacy"
        onClick={(e) => {
          e.preventDefault();
          openPolicyTab('privacy');
        }}
      >
        Privacy Policy
      </LoginFooterItem>
      <LoginFooterItem
        href="#security"
        onClick={(e) => {
          e.preventDefault();
          openPolicyTab('security');
        }}
      >
        Security &amp; Disclosure
      </LoginFooterItem>
      <LoginFooterItem
        href="#rfcs"
        onClick={(e) => {
          e.preventDefault();
          openPolicyTab('rfcs');
        }}
      >
        RFC Compliance
      </LoginFooterItem>
      {isSafeHrefUrl(DAVIANTE_ORG_URL) && (
        <LoginFooterItem href={DAVIANTE_ORG_URL} target="_blank" rel="noopener noreferrer">
          Daviante Organization
        </LoginFooterItem>
      )}
    </>
  );

  return (
    <>
      <LoginPage
        brandImgSrc={isDarkTheme ? '/logo-dark.svg' : '/logo.svg'}
        brandImgAlt="Daviante DoH — Enterprise DNS & Protective Policy Control-Plane"
        loginTitle="Sign in to Daviante DoH"
        loginSubtitle="Authoritative & Split-Horizon DNS Engine · Protective Threat Sinkhole · RFC 8484 Control-Plane"
        footerListItems={footerItems}
        footerListVariants={ListVariant.inline}
        textContent="Engineered by Daviante Organization (github.com/orgs/daviante-org). Protected by OWASP ASVS v4.0 Level 2 controls, Argon2id key derivation, and strict Content-Security-Policy."
        forgotCredentials={
          <LoginMainFooterBandItem>
            <Button variant="link" isInline onClick={() => { setRecoveryModalOpen(true); }}>
              Credential recovery &amp; CLI password rotation
            </Button>
            {' · '}
            <Button variant="link" isInline onClick={() => { openPolicyTab('security'); }}>
              Security architecture
            </Button>
          </LoginMainFooterBandItem>
        }
      >
        <Stack hasGutter>
          {localAuthEnabled && (
            <StackItem>
              <LoginForm
                showHelperText={showInvalidCreds}
                helperText="Invalid username or password."
                usernameLabel="Username"
                usernameValue={username}
                onChangeUsername={(_event, val) => { setUsername(val); }}
                isValidUsername={!showInvalidCreds}
                passwordLabel="Password"
                passwordValue={password}
                onChangePassword={(_event, val) => { setPassword(val); }}
                isShowPasswordEnabled
                isValidPassword={!showInvalidCreds}
                loginButtonLabel={isSubmitting ? 'Signing in...' : 'Sign in'}
                isLoginButtonDisabled={isSubmitting}
                onLoginButtonClick={(event) => {
                  void handleSubmit(event as unknown as React.FormEvent<HTMLFormElement>);
                }}
              />
            </StackItem>
          )}

          {localAuthEnabled && oidcEnabled && (
            <StackItem>
              <Divider />
            </StackItem>
          )}

          {oidcEnabled && isSafeHrefUrl(OIDC_LOGIN_PATH) && (
            <StackItem>
              <Button
                variant="secondary"
                isBlock
                component="a"
                href={OIDC_LOGIN_PATH}
                data-testid="oidc-sso-button"
              >
                Sign in with {oidcProviderName ?? 'Enterprise OIDC SSO'}
              </Button>
            </StackItem>
          )}

          {!localAuthEnabled && !oidcEnabled && (
            <StackItem>
              <Alert
                variant="warning"
                isInline
                title="No authentication provider is currently enabled on this server."
              />
            </StackItem>
          )}
        </Stack>
      </LoginPage>

      <CredentialRecoveryModal
        isOpen={recoveryModalOpen}
        onClose={() => { setRecoveryModalOpen(false); }}
      />

      <LegalPoliciesModal
        isOpen={legalModalOpen}
        initialTab={legalModalTab}
        onClose={() => { setLegalModalOpen(false); }}
      />
    </>
  );
}

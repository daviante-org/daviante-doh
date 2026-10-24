export type LegalPolicyTab = 'terms' | 'privacy' | 'security' | 'rfcs';

export interface LegalPoliciesModalProps {
  readonly isOpen: boolean;
  readonly initialTab?: LegalPolicyTab;
  readonly onClose: () => void;
}

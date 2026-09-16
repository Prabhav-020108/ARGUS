import { createContext, useContext, useState } from 'react';

export const SCENARIOS = {
  iam_escalation: {
    id: 'iam_escalation',
    name: 'CloudGoat — IAM Privilege Escalation',
    shortName: 'IAM Escalation',
    description: 'Simulated multi-stage privilege escalation from a public EC2 instance to S3 customer data via misconfigured IAM roles.',
    environment: { cloud: 'AWS', region: 'us-east-1', account: '194721538912', accountAlias: 'argus-demo' },
    riskScore: 78,
    dpdpScore: 64,
    findingCounts: { critical: 2, high: 5, medium: 8, low: 12 },
    totalResources: 47,
  },
  dpdp_violation: {
    id: 'dpdp_violation',
    name: 'DPDP Non-Compliance — Unencrypted PII Storage',
    shortName: 'DPDP Violation',
    description: 'S3 buckets holding personal data with no encryption, no versioning, no lifecycle policies — multiple DPDP Rule 6/7/8 violations.',
    environment: { cloud: 'AWS', region: 'us-east-1', account: '194721538912', accountAlias: 'argus-demo' },
    riskScore: 62,
    dpdpScore: 42,
    findingCounts: { critical: 3, high: 4, medium: 6, low: 9 },
    totalResources: 47,
  },
};

const ScenarioContext = createContext(null);

export function ScenarioProvider({ children }) {
  const [activeScenario, setActiveScenario] = useState('iam_escalation');
  const scenario = SCENARIOS[activeScenario];
  return (
    <ScenarioContext.Provider value={{ scenario, activeScenario, setActiveScenario, scenarios: SCENARIOS }}>
      {children}
    </ScenarioContext.Provider>
  );
}

export function useScenario() {
  const ctx = useContext(ScenarioContext);
  if (!ctx) throw new Error('useScenario must be used within ScenarioProvider');
  return ctx;
}

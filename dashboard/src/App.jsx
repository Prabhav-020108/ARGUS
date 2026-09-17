import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip as RTooltip, ResponsiveContainer,
  Area, AreaChart
} from 'recharts';
import {
  Shield, Activity, AlertTriangle, CheckCircle2, XCircle, ChevronDown,
  BarChart3, Network, FileCheck, Settings, Clock, TrendingDown,
  ChevronRight, Search, Send, Bot, User, Zap, Lock, Server, Database,
  Cloud, Globe, ArrowRight, X, Check, MessageSquare,
  Target, ShieldCheck, ChevronUp,
  ZoomIn, ZoomOut, RotateCcw, Filter, Bell
} from 'lucide-react';
import { ScenarioProvider, useScenario, SCENARIOS } from './data/scenarios';

// ============================================================
// DATA — Attack Graph
// ============================================================
const NODE_COLORS = {
  user: '#7c3aed', role: '#9333ea', ec2: '#2563eb', s3: '#d97706',
  rds: '#ea580c', sg: '#475569', vpc: '#334155', lambda: '#059669',
  policy: '#db2777', entry: '#dc2626',
};

function getGraphData(scenarioId) {
  if (scenarioId === 'dpdp_violation') return { nodes: dpdpNodes, edges: dpdpEdges, criticalPath: dpdpCriticalPath };
  return { nodes: iamNodes, edges: iamEdges, criticalPath: iamCriticalPath };
}

const iamPositions = {
  inet:         { x: 80,  y: 270 },
  'sg-pub':     { x: 230, y: 270 },
  'ec2-web':    { x: 390, y: 180 },
  'ec2-internal':{ x: 390, y: 360 },
  'role-ec2':   { x: 560, y: 140 },
  'user-dev':   { x: 560, y: 340 },
  'role-lambda':{ x: 730, y: 100 },
  'policy-admin':{ x: 900, y: 100 },
  'lambda-proc':{ x: 730, y: 260 },
  's3-customer':{ x: 1050, y: 100 },
  's3-logs':    { x: 1050, y: 280 },
  'rds-main':   { x: 1050, y: 380 },
  'vpc-1':      { x: 900, y: 460 },
};
const dpdpPositions = {
  inet:         { x: 80,  y: 250 },
  'sg-web':     { x: 230, y: 250 },
  'ec2-api':    { x: 390, y: 160 },
  'role-api':   { x: 560, y: 160 },
  'user-admin': { x: 560, y: 380 },
  's3-pii':     { x: 780, y: 80  },
  's3-backup':  { x: 780, y: 220 },
  's3-analytics':{ x: 780, y: 360 },
  'rds-main':   { x: 780, y: 460 },
  cloudtrail:   { x: 960, y: 280 },
  'vpc-1':      { x: 960, y: 440 },
};

const iamCriticalPath = ['inet','sg-pub','ec2-web','role-ec2','role-lambda','policy-admin','s3-customer'];
const iamNodes = [
  { id: 'inet', label: 'Internet (0.0.0.0/0)', type: 'entry', risk: 0 },
  { id: 'sg-pub', label: 'sg-public-web', type: 'sg', risk: 65, issue: 'SSH open to world' },
  { id: 'ec2-web', label: 'ec2-web-prod', type: 'ec2', risk: 72, issue: 'Public IP + weak IAM role', detail: 'i-0a1b2c3d4e5f6789 · t3.medium · 54.210.32.178' },
  { id: 'ec2-internal', label: 'ec2-batch-proc', type: 'ec2', risk: 28, detail: 'i-9a8b7c6d5e4f3210 · t3.small' },
  { id: 'role-ec2', label: 'EC2-WebRole', type: 'role', risk: 68, issue: 'Can assume LambdaAdminRole' },
  { id: 'role-lambda', label: 'LambdaAdminRole', type: 'role', risk: 89, issue: 'AdministratorAccess' },
  { id: 'user-dev', label: 'dev-intern', type: 'user', risk: 42, issue: 'No MFA' },
  { id: 'policy-admin', label: 'AdminAccess', type: 'policy', risk: 95, issue: 'Allow *:*' },
  { id: 'lambda-proc', label: 'λ data-processor', type: 'lambda', risk: 55, issue: 'Overprivileged role' },
  { id: 's3-customer', label: 's3://customer-data', type: 's3', risk: 91, crown: true, detail: '~2.4M records' },
  { id: 's3-logs', label: 's3://app-logs', type: 's3', risk: 22 },
  { id: 'rds-main', label: 'rds-prod-mysql', type: 'rds', risk: 45 },
  { id: 'vpc-1', label: 'vpc-prod-01', type: 'vpc', risk: 12 },
];
const iamEdges = [
  { s: 'inet', t: 'sg-pub', label: 'NetworkReachable', w: 0.9, crit: true },
  { s: 'sg-pub', t: 'ec2-web', label: 'NetworkReachable', w: 0.85, crit: true },
  { s: 'ec2-web', t: 'role-ec2', label: 'AttachedTo', w: 0.7, crit: true },
  { s: 'role-ec2', t: 'role-lambda', label: 'CanAssume', w: 0.82, crit: true },
  { s: 'role-lambda', t: 'policy-admin', label: 'AttachedTo', w: 0.95, crit: true },
  { s: 'policy-admin', t: 's3-customer', label: 'CanAccess', w: 0.98, crit: true },
  { s: 'policy-admin', t: 'rds-main', label: 'CanAccess', w: 0.75 },
  { s: 'policy-admin', t: 's3-logs', label: 'CanAccess', w: 0.3 },
  { s: 'role-lambda', t: 'lambda-proc', label: 'AttachedTo', w: 0.6 },
  { s: 'lambda-proc', t: 's3-customer', label: 'CanWrite', w: 0.7 },
  { s: 'ec2-web', t: 'vpc-1', label: 'MemberOf', w: 0.1 },
  { s: 'ec2-internal', t: 'vpc-1', label: 'MemberOf', w: 0.1 },
  { s: 'rds-main', t: 'vpc-1', label: 'MemberOf', w: 0.1 },
  { s: 'user-dev', t: 'role-ec2', label: 'CanAssume', w: 0.5 },
];

const dpdpCriticalPath = ['inet','sg-web','ec2-api','role-api','s3-pii'];
const dpdpNodes = [
  { id: 'inet', label: 'Internet (0.0.0.0/0)', type: 'entry', risk: 0 },
  { id: 'sg-web', label: 'sg-web-public', type: 'sg', risk: 45 },
  { id: 'ec2-api', label: 'ec2-api-server', type: 'ec2', risk: 38, detail: 'i-0a1b2c3d · t3.medium' },
  { id: 'role-api', label: 'API-ServiceRole', type: 'role', risk: 52 },
  { id: 'user-admin', label: 'admin-user', type: 'user', risk: 35 },
  { id: 's3-pii', label: 's3://customer-pii-raw', type: 's3', risk: 94, crown: true, issue: 'No encryption, no versioning, no lifecycle', detail: '~1.8M PII records' },
  { id: 's3-backup', label: 's3://pii-backup', type: 's3', risk: 72, issue: 'No encryption, EU region' },
  { id: 's3-analytics', label: 's3://analytics-output', type: 's3', risk: 25 },
  { id: 'rds-main', label: 'rds-userdb-prod', type: 'rds', risk: 58, issue: 'Low backup retention' },
  { id: 'cloudtrail', label: 'CloudTrail Config', type: 'policy', risk: 68, issue: 'Log retention 90d < 365d' },
  { id: 'vpc-1', label: 'vpc-prod-01', type: 'vpc', risk: 10 },
];
const dpdpEdges = [
  { s: 'inet', t: 'sg-web', label: 'NetworkReachable', w: 0.7 },
  { s: 'sg-web', t: 'ec2-api', label: 'NetworkReachable', w: 0.6 },
  { s: 'ec2-api', t: 'role-api', label: 'AttachedTo', w: 0.5 },
  { s: 'role-api', t: 's3-pii', label: 'CanAccess', w: 0.85, crit: true },
  { s: 'role-api', t: 's3-backup', label: 'CanAccess', w: 0.6 },
  { s: 'role-api', t: 'rds-main', label: 'CanAccess', w: 0.7 },
  { s: 'user-admin', t: 's3-pii', label: 'CanWrite', w: 0.8, crit: true },
  { s: 'user-admin', t: 's3-backup', label: 'CanWrite', w: 0.5 },
  { s: 'ec2-api', t: 'vpc-1', label: 'MemberOf', w: 0.1 },
  { s: 'rds-main', t: 'vpc-1', label: 'MemberOf', w: 0.1 },
  { s: 'role-api', t: 's3-analytics', label: 'CanAccess', w: 0.3 },
];

// ============================================================
// DATA — Findings
// ============================================================
function getFindings(sid) {
  return sid === 'dpdp_violation' ? dpdpFindings : iamFindings;
}
const iamFindings = [
  { id:'F-001', title:'IAM Role Allows Cross-Role Assumption to Admin', severity:'critical', risk:89, resource:'EC2-WebRole', type:'IAM Role', stackRank:1, naiveRank:2, dpdp:[], status:'open' },
  { id:'F-002', title:'Security Group Allows SSH from 0.0.0.0/0', severity:'critical', risk:72, resource:'sg-public-web', type:'Security Group', stackRank:2, naiveRank:1, dpdp:[], status:'open' },
  { id:'F-003', title:'IAM User Without MFA Enabled', severity:'high', risk:42, resource:'dev-intern', type:'IAM User', stackRank:4, naiveRank:3, dpdp:['Rule 6(b)'], status:'open' },
  { id:'F-004', title:'Lambda With Overprivileged Execution Role', severity:'high', risk:55, resource:'λ data-processor', type:'Lambda', stackRank:3, naiveRank:4, dpdp:['Rule 6(b)'], status:'open' },
  { id:'F-005', title:'CloudTrail Log Retention Below 1 Year', severity:'medium', risk:35, resource:'CloudTrail', type:'CloudTrail', stackRank:6, naiveRank:5, dpdp:['Rule 6(c)'], status:'open' },
  { id:'F-006', title:'S3 Bucket Without Access Logging', severity:'medium', risk:28, resource:'s3://app-logs', type:'S3 Bucket', stackRank:7, naiveRank:7, dpdp:['Rule 6(c)'], status:'open' },
  { id:'F-007', title:'Default VPC In Use', severity:'low', risk:15, resource:'vpc-prod-01', type:'VPC', stackRank:5, naiveRank:6, dpdp:[], status:'open' },
];
const dpdpFindings = [
  { id:'F-101', title:'S3 Bucket With PII Has No Encryption At Rest', severity:'critical', risk:94, resource:'s3://customer-pii-raw', type:'S3 Bucket', stackRank:1, naiveRank:1, dpdp:['Rule 6(a)'], status:'open' },
  { id:'F-102', title:'PII Bucket Has No Versioning', severity:'critical', risk:88, resource:'s3://customer-pii-raw', type:'S3 Bucket', stackRank:2, naiveRank:3, dpdp:['Rule 6(d)'], status:'open' },
  { id:'F-103', title:'No Lifecycle Policy on PII Bucket', severity:'critical', risk:82, resource:'s3://customer-pii-raw', type:'S3 Bucket', stackRank:3, naiveRank:2, dpdp:['Rule 8'], status:'open' },
  { id:'F-104', title:'Backup Bucket Has No Encryption', severity:'high', risk:72, resource:'s3://pii-backup', type:'S3 Bucket', stackRank:4, naiveRank:4, dpdp:['Rule 6(a)'], status:'open' },
  { id:'F-105', title:'PII Data in EU Region — Cross-Border Awareness', severity:'high', risk:65, resource:'s3://pii-backup (eu-west-1)', type:'S3 Bucket', stackRank:6, naiveRank:5, dpdp:['Rule 15'], status:'open' },
  { id:'F-106', title:'CloudTrail Log Retention Only 90 Days', severity:'high', risk:68, resource:'CloudTrail Config', type:'CloudTrail', stackRank:5, naiveRank:6, dpdp:['Rule 6(c)'], status:'open' },
  { id:'F-107', title:'RDS Backup Retention Below Best Practice', severity:'medium', risk:45, resource:'rds-userdb-prod', type:'RDS', stackRank:7, naiveRank:7, dpdp:['Rule 6(d)'], status:'open' },
];

// ============================================================
// DATA — DPDP Compliance
// ============================================================
const DPDP_RULES = [
  { id:'rule6a', ref:'Rule 6(a)', title:'Encryption & Data Masking', meaning:'Personal data must be unreadable if stolen.', penalty:'₹250 Cr', weight:5 },
  { id:'rule6b', ref:'Rule 6(b)', title:'Access Control', meaning:'Only authorized identities touch personal data.', penalty:'₹250 Cr', weight:5 },
  { id:'rule6c', ref:'Rule 6(c)', title:'Monitoring & Logging', meaning:'Must see who accessed what, logs ≥ 1 year.', penalty:'₹250 Cr', weight:4 },
  { id:'rule6d', ref:'Rule 6(d)', title:'Backup & Continuity', meaning:'Data survives failures — versioning & backups.', penalty:'₹250 Cr', weight:4 },
  { id:'rule7', ref:'Rule 7', title:'72-Hour Breach Notification', meaning:'Detect and report breaches within 72 hours.', penalty:'₹200 Cr', weight:3 },
  { id:'rule8', ref:'Rule 8', title:'Data Retention & Erasure', meaning:'Data not kept indefinitely — lifecycle policies.', penalty:'₹150 Cr', weight:3 },
  { id:'rule15', ref:'Rule 15', title:'Cross-Border Transfer', meaning:'Transfer allowed unless government restricts it.', penalty:'Varies', weight:2 },
];

function getDPDPCompliance(sid) {
  return sid === 'dpdp_violation' ? dpdpComp : iamComp;
}
const iamComp = {
  score: 64, postScore: 88,
  rules: {
    rule6a: { s:'pass', sc:100, fail:[], total:3 },
    rule6b: { s:'fail', sc:40, fail:['EC2-WebRole','dev-intern','λ data-processor'], total:5 },
    rule6c: { s:'warn', sc:60, fail:['CloudTrail (90d retention)'], total:2 },
    rule6d: { s:'pass', sc:100, fail:[], total:3 },
    rule7: { s:'pass', sc:80, fail:[], total:1 },
    rule8: { s:'warn', sc:70, fail:['s3://app-logs'], total:3 },
    rule15: { s:'pass', sc:100, fail:[], total:3 },
  }
};
const dpdpComp = {
  score: 42, postScore: 85,
  rules: {
    rule6a: { s:'fail', sc:20, fail:['s3://customer-pii-raw','s3://pii-backup'], total:3 },
    rule6b: { s:'warn', sc:70, fail:['API-ServiceRole'], total:4 },
    rule6c: { s:'fail', sc:30, fail:['CloudTrail (90d)'], total:1 },
    rule6d: { s:'fail', sc:25, fail:['s3://customer-pii-raw','rds-userdb-prod'], total:3 },
    rule7: { s:'warn', sc:60, fail:[], total:1 },
    rule8: { s:'fail', sc:10, fail:['s3://customer-pii-raw','s3://pii-backup'], total:3 },
    rule15: { s:'warn', sc:50, fail:['s3://pii-backup (eu-west-1)'], total:3 },
  }
};

// ============================================================
// DATA — Remediations
// ============================================================
function getRemediations(sid) {
  return sid === 'dpdp_violation' ? dpdpRem : iamRem;
}
const iamRem = [
  { id:'R-001', title:'Remove Cross-Role Assumption', sev:'critical', status:'verified', resource:'EC2-WebRole', rBefore:89, rAfter:24, dpdp:[], checks:{gen:true,dpdp:true,risk:true}, conf:0.94,
    before:`{\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": "sts:AssumeRole",\n    "Resource": [\n      "arn:aws:iam::194721538912:role/LambdaAdminRole",\n      "arn:aws:iam::194721538912:role/ReadOnlyRole"\n    ]\n  }]\n}`,
    after:`{\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": "sts:AssumeRole",\n    "Resource": [\n      "arn:aws:iam::194721538912:role/ReadOnlyRole"\n    ]\n  }]\n}`,
    explanation:'Removes ability for EC2-WebRole to assume LambdaAdminRole, severing the privilege escalation path.', time:'2 min ago' },
  { id:'R-002', title:'Restrict SSH to VPN CIDR', sev:'critical', status:'drafted', resource:'sg-public-web', rBefore:72, rAfter:18, dpdp:[], checks:{gen:true,dpdp:true,risk:true}, conf:0.91,
    before:`cidr_blocks = ["0.0.0.0/0"]`,
    after:`cidr_blocks = ["10.0.0.0/8"]\ndescription = "SSH restricted to VPN"`,
    explanation:'Restricts SSH from all IPs to internal VPN range.', time:'5 min ago' },
  { id:'R-003', title:'Enable MFA for dev-intern', sev:'high', status:'approved', resource:'dev-intern', rBefore:42, rAfter:12, dpdp:['Rule 6(b)'], checks:{gen:true,dpdp:true,risk:true}, conf:0.97,
    before:`# No MFA policy exists`,
    after:`policy = "EnforceMFA"\nCondition: aws:MultiFactorAuthPresent = false → Deny all`,
    explanation:'Forces MFA on next login.', time:'8 min ago' },
  { id:'R-004', title:'Scope Lambda Execution Role', sev:'high', status:'applied', resource:'λ data-processor', rBefore:55, rAfter:15, dpdp:['Rule 6(b)'], checks:{gen:true,dpdp:true,risk:true}, conf:0.96,
    before:`managed_policy_arns = ["AdministratorAccess"]`,
    after:`inline_policy: s3:GetObject, s3:PutObject\nResource: customer-data-prod/*`,
    explanation:'Replaces AdministratorAccess with scoped S3-only policy.', time:'12 min ago' },
];
const dpdpRem = [
  { id:'R-101', title:'Enable Encryption on PII Bucket', sev:'critical', status:'verified', resource:'s3://customer-pii-raw', rBefore:94, rAfter:38, dpdp:['Rule 6(a)'], checks:{gen:true,dpdp:true,risk:true}, conf:0.98,
    before:`# No encryption configuration`,
    after:`server_side_encryption {\n  sse_algorithm = "AES256"\n  bucket_key_enabled = true\n}`,
    explanation:'Enables AES-256 SSE. Satisfies DPDP Rule 6(a).', time:'1 min ago' },
  { id:'R-102', title:'Enable Versioning on PII Bucket', sev:'critical', status:'drafted', resource:'s3://customer-pii-raw', rBefore:88, rAfter:22, dpdp:['Rule 6(d)'], checks:{gen:true,dpdp:true,risk:true}, conf:0.96,
    before:`versioning {\n  status = "Disabled"\n}`,
    after:`versioning {\n  status = "Enabled"\n}`,
    explanation:'Enables versioning for point-in-time recovery. Satisfies DPDP Rule 6(d).', time:'3 min ago' },
  { id:'R-103', title:'Add Lifecycle Policy for Retention', sev:'critical', status:'approved', resource:'s3://customer-pii-raw', rBefore:82, rAfter:15, dpdp:['Rule 8'], checks:{gen:true,dpdp:true,risk:true}, conf:0.92,
    before:`# No lifecycle configuration`,
    after:`lifecycle_rule {\n  transition: 90d → GLACIER\n  expiration: 730d (2 years)\n}`,
    explanation:'Data moves to Glacier after 90d, expires after 2y. Satisfies DPDP Rule 8.', time:'5 min ago' },
  { id:'R-104', title:'Increase Log Retention to 365 Days', sev:'high', status:'applied', resource:'CloudTrail Config', rBefore:68, rAfter:10, dpdp:['Rule 6(c)'], checks:{gen:true,dpdp:true,risk:true}, conf:0.99,
    before:`retention_in_days = 90`,
    after:`retention_in_days = 365`,
    explanation:'Meets DPDP Rule 6(c) monitoring/logging retention requirement.', time:'15 min ago' },
];

// ============================================================
// DATA — Chat
// ============================================================
const CHAT_SUGGESTIONS = [
  'Why is the #1 finding critical?',
  'What DPDP rules are we violating?',
  'Show me the attack path',
  'How does Stackelberg prioritize?',
  'What happens if I ignore encryption?',
];

const CHAT_RESPONSES = {
  'default': `I can help with security posture, DPDP compliance, attack paths, and remediation priorities. Try asking about specific findings or compliance rules.`,
  'critical': `**The #1 finding** has the highest Stackelberg priority because it sits on the critical attack path — the shortest route an attacker can take from the internet to your crown jewel data.\n\nThe game model rates this higher than a naive severity sort because fixing it **changes the attacker's best response** — they lose their most valuable path entirely, not just one step of it.`,
  'dpdp': `Based on the current scan:\n\n• **Rule 6(a)** — Encryption: PII buckets unencrypted\n• **Rule 6(c)** — Logging: Retention < 365 days\n• **Rule 6(d)** — Backup: No versioning on PII data\n• **Rule 8** — Retention: No lifecycle policies\n\nApplying all verified remediations would raise the DPDP score significantly.`,
  'path': `The critical path traces from the internet through your public-facing resources to the crown jewel:\n\n\`Internet → SG → EC2 → IAM Role → Admin Policy → Crown Jewel\`\n\nEach hop has an exploitability weight. The cumulative path probability shows the real-world likelihood of an attacker traversing this entire chain.`,
  'stackelberg': `The Stackelberg game differs from naive sorting because it models a **rational attacker**. With a limited remediation budget, the game picks fixes that change the attacker's best-response — sometimes a lower-severity fix matters more because it eliminates the attacker's **fallback path**.`,
  'ignore': `Ignoring encryption on PII storage has two consequences:\n\n**1. Security**: Risk score stays at 94/100 — highest in the environment\n**2. DPDP**: Rule 6(a) violation under the ₹250 crore penalty tier\n\nThis is #1 priority in both Stackelberg and naive ranking.`,
};

function getChatReply(q) {
  const l = q.toLowerCase();
  if (l.includes('critical') || l.includes('#1') || l.includes('flagged')) return CHAT_RESPONSES.critical;
  if (l.includes('dpdp') || l.includes('rule') || l.includes('violat') || l.includes('comply')) return CHAT_RESPONSES.dpdp;
  if (l.includes('path') || l.includes('escalat') || l.includes('attack')) return CHAT_RESPONSES.path;
  if (l.includes('stackelberg') || l.includes('game') || l.includes('priorit')) return CHAT_RESPONSES.stackelberg;
  if (l.includes('ignore') || l.includes('encrypt') || l.includes('happen')) return CHAT_RESPONSES.ignore;
  return CHAT_RESPONSES.default;
}

// ============================================================
// UTILITY COMPONENTS
// ============================================================
function AnimatedNumber({ value, duration = 1000 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = (ts) => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / duration, 1);
      setDisplay(Math.round(p * value));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value, duration]);
  return <>{display}</>;
}

function SeverityBadge({ severity }) {
  const colors = {
    critical: 'bg-red-50 text-red-700 border-red-200',
    high: 'bg-orange-50 text-orange-700 border-orange-200',
    medium: 'bg-amber-50 text-amber-700 border-amber-200',
    low: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider border ${colors[severity] || colors.low}`}>
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${severity === 'critical' ? 'bg-red-500' : severity === 'high' ? 'bg-orange-500' : severity === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'}`} />
      {severity}
    </span>
  );
}

function RiskGauge({ value, size = 130, label, color }) {
  const r = (size - 16) / 2;
  const circ = 2 * Math.PI * r;
  const arc = circ * 0.75;
  const offset = arc - (arc * Math.min(value, 100) / 100);
  const c = color || (value > 70 ? '#dc2626' : value > 40 ? '#f59e0b' : '#059669');
  return (
    <div className="relative flex flex-col items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-[135deg]">
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#e2e8f0" strokeWidth="8" strokeDasharray={`${arc} ${circ}`} strokeLinecap="round" />
        <motion.circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth="8" strokeDasharray={`${arc} ${circ}`} strokeLinecap="round"
          initial={{ strokeDashoffset: arc }} animate={{ strokeDashoffset: offset }} transition={{ duration: 1.2, ease: 'easeOut' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-extrabold tabular-nums text-slate-900 tracking-tight"><AnimatedNumber value={value} /></span>
        {label && <span className="text-[11px] text-slate-500 font-semibold uppercase tracking-wider">{label}</span>}
      </div>
    </div>
  );
}

// Modern executive KPI Metric Card
function MetricCard({ title, value, subtext, suffix, accentColor = '#2563eb', alertText }) {
  return (
    <div 
      className="bg-white border-x border-b border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] hover:shadow-md transition-all flex flex-col justify-between group"
      style={{ borderTop: `4px solid ${accentColor}` }}
    >
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] uppercase font-extrabold text-slate-400 tracking-wider block leading-tight">{title}</span>
        </div>
        <div className="flex items-baseline gap-2 my-1">
          <span className="text-3xl font-extrabold text-slate-900 tabular-nums tracking-tight">
            {typeof value === 'number' ? <AnimatedNumber value={value} /> : value}
          </span>
          {suffix && <span className="text-xs font-bold text-slate-400 font-mono">{suffix}</span>}
        </div>
        {subtext && <p className="text-xs text-slate-500 font-medium mt-1 leading-relaxed">{subtext}</p>}
        {alertText && (
          <div className="text-[11px] font-bold text-amber-700 mt-3 flex items-center gap-1.5 bg-amber-50 border border-amber-200 px-2.5 py-1 rounded-lg">
            <AlertTriangle size={13} className="text-amber-600 flex-shrink-0" /> {alertText}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================
// SIDEBAR
// ============================================================
const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: BarChart3 },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'graph', label: 'Attack Graph', icon: Network },
  { id: 'dpdp', label: 'DPDP Compliance', icon: ShieldCheck },
  { id: 'remediation', label: 'Remediation', icon: FileCheck },
  { id: 'settings', label: 'Settings', icon: Settings },
];

function Sidebar({ active, onNav, collapsed, onToggle }) {
  return (
    <aside className={`h-full bg-white border-r border-slate-200/90 flex flex-col transition-all duration-300 z-20 flex-shrink-0 ${collapsed ? 'w-20' : 'w-64'}`}>
      {/* Logo */}
      <div className="h-16 flex items-center gap-3 px-5 border-b border-slate-100">
        <button onClick={onToggle} className="flex items-center gap-3 text-left w-full hover:opacity-90 transition-opacity">
          <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center flex-shrink-0 shadow-sm shadow-blue-500/20 text-white">
            <Shield size={18} />
          </div>
          {!collapsed && (
            <div>
              <span className="text-base font-extrabold tracking-tight text-slate-900 leading-none block">ARGUS</span>
              <span className="text-[10px] text-slate-500 font-bold tracking-wider">CLOUD SECURITY</span>
            </div>
          )}
        </button>
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-5 px-3 flex flex-col gap-1.5">
        {NAV_ITEMS.map(item => {
          const isActive = active === item.id;
          return (
            <button key={item.id} onClick={() => onNav(item.id)}
              className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-semibold transition-all duration-150 ${
                isActive
                  ? 'bg-blue-50 text-blue-700 border border-blue-100 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
              title={collapsed ? item.label : undefined}
            >
              <item.icon size={18} className={isActive ? 'text-blue-600' : 'text-slate-400'} />
              {!collapsed && <span>{item.label}</span>}
              {!collapsed && isActive && <ChevronRight size={14} className="ml-auto text-blue-500" />}
            </button>
          );
        })}
      </nav>

      {/* Environment badge */}
      {!collapsed && (
        <div className="px-3 pb-5">
          <div className="bg-slate-50 rounded-xl p-3.5 border border-slate-200/80">
            <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-400 font-bold mb-1">
              <Cloud size={12} className="text-slate-500" /> Target AWS
            </div>
            <div className="text-xs text-slate-800 font-mono font-bold">us-east-1 · Production</div>
            <div className="flex items-center justify-between mt-1 text-[11px] text-slate-500">
              <span className="font-mono text-[10px]">argus-demo</span>
              <span className="text-emerald-700 font-bold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" /> Live
              </span>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}

// ============================================================
// TOP BAR
// ============================================================
function TopBar({ scenarioId, onScenarioChange }) {
  const [open, setOpen] = useState(false);
  const sc = SCENARIOS[scenarioId];
  return (
    <header className="h-16 bg-white border-b border-slate-200/90 flex items-center justify-between px-8 z-10 flex-shrink-0">
      <div className="flex items-center gap-4">
        <div className="relative">
          <button onClick={() => setOpen(!open)}
            className="flex items-center gap-2.5 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-800 transition-colors shadow-2xs">
            <Zap size={15} className="text-blue-600" />
            <span className="max-w-[320px] truncate">{sc.shortName}</span>
            <ChevronDown size={14} className="text-slate-400" />
          </button>
          <AnimatePresence>
            {open && (
              <motion.div initial={{ opacity:0, y:-4 }} animate={{ opacity:1, y:0 }} exit={{ opacity:0, y:-4 }}
                className="absolute top-full left-0 mt-2 w-96 bg-white border border-slate-200 rounded-2xl shadow-xl z-50 overflow-hidden p-2">
                {Object.values(SCENARIOS).map(s => (
                  <button key={s.id} onClick={() => { onScenarioChange(s.id); setOpen(false); }}
                    className={`w-full text-left px-4 py-3 rounded-xl transition-colors ${s.id === scenarioId ? 'bg-blue-50 text-blue-900 border border-blue-100' : 'hover:bg-slate-50'}`}>
                    <div className="text-sm font-bold text-slate-900">{s.name}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{s.description}</div>
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
      <div className="flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1.5 bg-slate-50 text-slate-600 px-3.5 py-2 rounded-xl border border-slate-200 font-semibold">
          <Clock size={13} className="text-slate-400" /> Last scan: 2 min ago
        </div>
        <div className="flex items-center gap-1.5 bg-emerald-50 text-emerald-800 px-3.5 py-2 rounded-xl border border-emerald-200 font-bold">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> Live Guard Active
        </div>
      </div>
    </header>
  );
}

// ============================================================
// PAGE: OVERVIEW
// ============================================================
const RISK_TREND = [
  { t: '-15m', risk: 82, dpdp: 58 },
  { t: '-12m', risk: 82, dpdp: 58 },
  { t: '-10m', risk: 79, dpdp: 60 },
  { t: '-8m',  risk: 80, dpdp: 60 },
  { t: '-5m',  risk: 78, dpdp: 62 },
  { t: '-3m',  risk: 78, dpdp: 63 },
  { t: 'now',  risk: 78, dpdp: 64 },
];
const RISK_TREND_DPDP = [
  { t: '-15m', risk: 68, dpdp: 35 },
  { t: '-12m', risk: 68, dpdp: 35 },
  { t: '-10m', risk: 65, dpdp: 38 },
  { t: '-8m',  risk: 66, dpdp: 38 },
  { t: '-5m',  risk: 63, dpdp: 40 },
  { t: '-3m',  risk: 62, dpdp: 41 },
  { t: 'now',  risk: 62, dpdp: 42 },
];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-xs shadow-lg">
      <p className="text-slate-500 font-bold mb-1">{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }} className="font-bold flex items-center justify-between gap-4">
          <span>{p.name}:</span>
          <span>{p.value}</span>
        </p>
      ))}
    </div>
  );
};

function OverviewPage() {
  const { scenario, activeScenario, setActiveScenario } = useScenario();
  const findings = getFindings(activeScenario);
  const compliance = getDPDPCompliance(activeScenario);
  const remediations = getRemediations(activeScenario);

  const pipeline = useMemo(() => {
    const counts = { drafted: 0, verified: 0, approved: 0, applied: 0 };
    remediations.forEach(r => counts[r.status]++);
    return counts;
  }, [remediations]);

  const trendData = activeScenario === 'dpdp_violation' ? RISK_TREND_DPDP : RISK_TREND;

  // Chart data for Stackelberg vs Naive
  const chartData = findings.slice(0, 6).map(f => ({
    id: f.id,
    name: f.title.length > 24 ? f.title.slice(0, 22) + '…' : f.title,
    stackelberg: f.stackRank,
    naive: f.naiveRank,
    risk: f.risk,
    severity: f.severity,
  }));

  const activity = [
    { time: '2m ago',  text: 'PageRank risk scoring completed (47 nodes indexed)', icon: Activity, color: 'text-blue-600' },
    { time: '3m ago',  text: 'Verification gate: R-001 passed all 3 OPA policy checks', icon: CheckCircle2, color: 'text-emerald-600' },
    { time: '5m ago',  text: 'LLM generated least-privilege fix for sg-public-web', icon: Bot, color: 'text-indigo-600' },
    { time: '8m ago',  text: 'Stackelberg LP solved: budget B=3, 7 findings re-ranked', icon: Target, color: 'text-amber-600' },
    { time: '12m ago', text: 'R-004 auto-applied (Bayesian confidence 0.96 ≥ 0.90)', icon: Zap, color: 'text-emerald-600' },
    { time: '15m ago', text: 'Cartography graph sync: 47 cloud resources indexed', icon: Network, color: 'text-blue-600' },
  ];

  const sevColors = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#059669' };

  return (
    <div className="p-6 md:p-8 overflow-y-auto h-full space-y-6 pb-28 max-w-[1600px] mx-auto w-full">
      {/* 1. Top Posture Banner (Spacious Executive Bar) */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] flex items-center justify-between gap-6 flex-wrap">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-6 items-center flex-1 min-w-[320px]">
          <div>
            <span className="text-[11px] uppercase font-extrabold text-slate-400 block tracking-wider mb-1.5 leading-none">SESSION</span>
            <span className="font-extrabold text-slate-900 text-sm flex items-center gap-2 leading-snug">
              <Activity size={15} className="text-blue-600 flex-shrink-0" /> Posture Audit
            </span>
          </div>

          <div>
            <span className="text-[11px] uppercase font-extrabold text-slate-400 block tracking-wider mb-1.5 leading-none">AUDIT STATUS</span>
            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold leading-none ${
              scenario.riskScore > 70 ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-amber-50 text-amber-700 border border-amber-200'
            }`}>
              <span className={`w-2 h-2 rounded-full ${scenario.riskScore > 70 ? 'bg-rose-500' : 'bg-amber-500'} animate-pulse`} />
              {scenario.riskScore > 70 ? 'OVERLOADED RISK' : 'ELEVATED RISK'}
            </span>
          </div>

          <div>
            <span className="text-[11px] uppercase font-extrabold text-slate-400 block tracking-wider mb-1.5 leading-none">TARGET DEVICE</span>
            <span className="font-semibold text-slate-700 text-xs flex items-center gap-2 leading-snug">
              <span className="w-2 h-2 rounded-full bg-emerald-500 flex-shrink-0" /> AWS us-east-1
            </span>
          </div>

          <div className="hidden lg:block">
            <span className="text-[11px] uppercase font-extrabold text-slate-400 block tracking-wider mb-1.5 leading-none">OPTIMAL SOLVER</span>
            <span className="font-bold text-blue-600 text-xs leading-snug">Stackelberg LP + GNN</span>
          </div>

          <div className="hidden lg:block">
            <span className="text-[11px] uppercase font-extrabold text-slate-400 block tracking-wider mb-1.5 leading-none">COMPLIANCE ENGINE</span>
            <span className="font-bold text-emerald-700 text-xs flex items-center gap-1.5 leading-snug">
              <CheckCircle2 size={14} className="flex-shrink-0" /> DPDP 2025 Active
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <button className="px-4 py-2.5 text-xs font-bold text-slate-700 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-xl transition-colors shadow-2xs">
            Run Scan Cycle
          </button>
          <div className="text-base font-extrabold font-mono text-blue-600 bg-blue-50 border border-blue-200 px-3.5 py-2 rounded-xl tabular-nums">
            00:15
          </div>
        </div>
      </div>

      {/* 2. Target Scenario Hero Strip */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2.5">
            <span className="w-3 h-3 rounded-full bg-blue-600" />
            <h2 className="font-extrabold text-slate-900 text-base">{scenario.name}</h2>
          </div>
          <div className="flex items-center gap-2.5 flex-wrap text-xs">
            <span className="font-bold bg-amber-50 text-amber-800 border border-amber-200 px-3 py-1 rounded-lg">
              PRIORITY FIX #1: R-001
            </span>
            <span className="font-bold bg-blue-50 text-blue-800 border border-blue-200 px-3 py-1 rounded-lg">
              ATTACK HOPS: 7
            </span>
            <span className="font-bold bg-rose-50 text-rose-800 border border-rose-200 px-3 py-1 rounded-lg">
              DPDP PENALTY: ₹250 CR
            </span>
          </div>
        </div>
        <button onClick={() => setActiveScenario(activeScenario === 'iam_escalation' ? 'dpdp_violation' : 'iam_escalation')}
          className="text-xs font-bold text-slate-700 hover:text-slate-900 bg-slate-50 border border-slate-200 px-4 py-2 rounded-xl hover:bg-slate-100 transition-colors shadow-2xs">
          Change Scenario
        </button>
      </div>

      {/* 3. Five KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">
        <MetricCard
          title="ATTACK RISK SCORE"
          value={scenario.riskScore}
          suffix="/100"
          subtext="PageRank weighted graph analysis"
          accentColor="#dc2626"
          alertText={scenario.riskScore > 70 ? "High blast radius" : undefined}
        />
        <MetricCard
          title="DPDP COMPLIANCE"
          value={compliance.score}
          suffix="%"
          subtext={`Post-remediation: ${compliance.postScore}%`}
          accentColor="#2563eb"
        />
        <MetricCard
          title="CRITICAL FINDINGS"
          value={scenario.findingCounts.critical}
          suffix="open"
          subtext="Immediate remediation required"
          accentColor="#ea580c"
        />
        <MetricCard
          title="CLOUD ASSETS"
          value={scenario.totalResources}
          suffix="nodes"
          subtext="IAM, S3, RDS, EC2, VPC indexed"
          accentColor="#4f46e5"
        />
        <MetricCard
          title="AUTO-APPLIED FIXES"
          value={pipeline.applied}
          suffix="applied"
          subtext="Bayesian confidence ≥ 0.90"
          accentColor="#059669"
        />
      </div>

      {/* 4. Main Analytics Charts Section */}
      <div className="grid grid-cols-12 gap-6">
        {/* Left Column: Stackelberg Prioritization + Risk Activation */}
        <div className="col-span-12 lg:col-span-7 bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-4">
            <div>
              <h3 className="text-base font-extrabold text-slate-900">Stackelberg vs Naive Prioritization</h3>
              <p className="text-xs text-slate-500 mt-0.5 font-medium">Comparison of Game-Theoretic Priority Rank vs Traditional Severity Rank (Lower # = Higher Urgency)</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-bold">
              <div className="flex items-center gap-1.5 text-blue-700"><div className="w-3 h-3 rounded-md bg-blue-600" /> Stackelberg LP</div>
              <div className="flex items-center gap-1.5 text-slate-500"><div className="w-3 h-3 rounded-md bg-slate-300" /> Naive Rank</div>
            </div>
          </div>

          <div className="w-full mb-4">
            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={chartData} margin={{ top: 15, right: 20, bottom: 20, left: 15 }}>
                <XAxis dataKey="id" tick={{ fill: '#475569', fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)' }} dy={4} />
                <YAxis tick={{ fill: '#475569', fontSize: 11 }} domain={[0, 8]} tickFormatter={v => `Rank #${v}`} dx={-6} width={58} />
                <RTooltip content={<CustomTooltip />} />
                <Bar dataKey="stackelberg" name="Stackelberg Rank" fill="#2563eb" radius={[6, 6, 0, 0]} maxBarSize={28} />
                <Bar dataKey="naive" name="Naive Rank" fill="#cbd5e1" radius={[6, 6, 0, 0]} maxBarSize={28} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Neural Resource Risk Activation */}
          <div className="border-t border-slate-200 pt-6 mt-6 space-y-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-extrabold text-slate-400 uppercase tracking-wider">NEURAL RESOURCE RISK ACTIVATION</span>
              <span className="text-xs text-slate-500 font-semibold">Normalized Impact Score</span>
            </div>
            <div className="space-y-4">
              {chartData.slice(0, 4).map(f => (
                <div key={f.id} className="space-y-2 pb-1">
                  <div className="flex items-center justify-between text-xs font-semibold gap-4 mb-1">
                    <span className="font-mono text-slate-800 truncate">{f.id} — {f.name}</span>
                    <span className="font-bold tabular-nums font-mono flex-shrink-0" style={{ color: sevColors[f.severity] }}>{f.risk} / 100</span>
                  </div>
                  <div className="w-full bg-slate-100 rounded-full h-3.5 overflow-hidden p-0.5 border border-slate-200/60">
                    <motion.div className="h-full rounded-full" style={{ backgroundColor: sevColors[f.severity] }}
                      initial={{ width: 0 }} animate={{ width: `${f.risk}%` }} transition={{ duration: 1, delay: 0.2 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Score Trend, Pipeline & Security Events */}
        <div className="col-span-12 lg:col-span-5 space-y-6">
          {/* Risk Trend Chart */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] space-y-4">
            <div className="flex items-center justify-between mb-1">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">Posture Score Trend</h3>
                <span className="text-xs text-slate-500 font-medium">15-minute telemetry window</span>
              </div>
              <span className="text-[11px] font-bold text-emerald-800 bg-emerald-50 px-2.5 py-1 rounded-lg border border-emerald-200">
                Live · 30s
              </span>
            </div>
            
            <div className="w-full">
              <ResponsiveContainer width="100%" height={190}>
                <AreaChart data={trendData} margin={{ top: 10, right: 10, bottom: 15, left: 0 }}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#dc2626" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="dpdpGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563eb" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 11 }} dy={2} />
                  <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} dx={-4} width={28} />
                  <RTooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="risk" name="Risk Score" stroke="#dc2626" strokeWidth={2.5} fill="url(#riskGrad)" />
                  <Area type="monotone" dataKey="dpdp" name="DPDP Score" stroke="#2563eb" strokeWidth={2.5} fill="url(#dpdpGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            
            <div className="flex items-center justify-center gap-6 pt-4 text-xs font-bold border-t border-slate-200 mt-4">
              <div className="flex items-center gap-1.5 text-rose-600"><span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Attack Risk Score</div>
              <div className="flex items-center gap-1.5 text-blue-600"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> DPDP Compliance</div>
            </div>
          </div>

          {/* Remediation Pipeline Status Grid */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] space-y-4">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-sm font-extrabold text-slate-900">Remediation Pipeline</h3>
              <span className="text-xs font-bold text-blue-600 bg-blue-50 px-2.5 py-1 rounded-lg border border-blue-100">{remediations.length} Active Actions</span>
            </div>
            <div className="grid grid-cols-4 gap-3">
              <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-3.5 text-center">
                <div className="text-2xl font-extrabold text-slate-800">{pipeline.drafted}</div>
                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wide mt-0.5">Drafted</div>
              </div>
              <div className="bg-blue-50 border border-blue-200/80 rounded-xl p-3.5 text-center">
                <div className="text-2xl font-extrabold text-blue-700">{pipeline.verified}</div>
                <div className="text-[11px] font-bold text-blue-700 uppercase tracking-wide mt-0.5">Verified</div>
              </div>
              <div className="bg-amber-50 border border-amber-200/80 rounded-xl p-3.5 text-center">
                <div className="text-2xl font-extrabold text-amber-700">{pipeline.approved}</div>
                <div className="text-[11px] font-bold text-amber-700 uppercase tracking-wide mt-0.5">Approved</div>
              </div>
              <div className="bg-emerald-50 border border-emerald-200/80 rounded-xl p-3.5 text-center">
                <div className="text-2xl font-extrabold text-emerald-700">{pipeline.applied}</div>
                <div className="text-[11px] font-bold text-emerald-700 uppercase tracking-wide mt-0.5">Applied</div>
              </div>
            </div>
          </div>

          {/* Recent Security Activity Stream */}
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.03)] space-y-4">
            <h3 className="text-sm font-extrabold text-slate-900 mb-1">Recent Security Activity</h3>
            <div className="space-y-3">
              {activity.map((a, i) => (
                <div key={i} className="flex items-start gap-3.5 text-xs p-3.5 bg-slate-50/60 border border-slate-200/80 rounded-xl hover:bg-slate-50 transition-colors">
                  <a.icon size={16} className={`${a.color} mt-0.5 flex-shrink-0`} />
                  <div className="min-w-0 flex-1 space-y-1">
                    <p className="text-slate-800 font-semibold leading-relaxed">{a.text}</p>
                    <span className="text-[11px] text-slate-400 font-medium font-mono block">{a.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// PAGE: FINDINGS
// ============================================================
function FindingsPage() {
  const { activeScenario } = useScenario();
  const findings = getFindings(activeScenario);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortKey, setSortKey] = useState('stackRank');
  const [sortDir, setSortDir] = useState('asc');
  const [selectedFinding, setSelectedFinding] = useState(null);

  const severities = ['all', 'critical', 'high', 'medium', 'low'];
  const sevPills = {
    all: 'bg-slate-100 text-slate-700 border-slate-200',
    critical: 'bg-red-50 text-red-700 border-red-200',
    high: 'bg-orange-50 text-orange-700 border-orange-200',
    medium: 'bg-amber-50 text-amber-700 border-amber-200',
    low: 'bg-emerald-50 text-emerald-700 border-emerald-200'
  };

  const filtered = useMemo(() => {
    return findings
      .filter(f => severityFilter === 'all' || f.severity === severityFilter)
      .filter(f => !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.resource.toLowerCase().includes(search.toLowerCase()) || f.type.toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => {
        let av = a[sortKey], bv = b[sortKey];
        if (typeof av === 'string') av = av.toLowerCase(), bv = bv.toLowerCase();
        return sortDir === 'asc' ? (av < bv ? -1 : av > bv ? 1 : 0) : (av > bv ? -1 : av < bv ? 1 : 0);
      });
  }, [findings, search, severityFilter, sortKey, sortDir]);

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('asc'); }
  };

  const SortIcon = ({ k }) => {
    if (sortKey !== k) return <ChevronUp size={12} className="opacity-20" />;
    return sortDir === 'asc' ? <ChevronUp size={12} className="text-blue-600" /> : <ChevronDown size={12} className="text-blue-600" />;
  };

  const selectedF = findings.find(f => f.id === selectedFinding);
  const remediations = getRemediations(activeScenario);
  const relatedRem = selectedF ? remediations.filter(r => r.resource === selectedF.resource || r.resource === selectedF.id) : [];

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => c[f.severity]++);
    return c;
  }, [findings]);

  return (
    <div className="h-full flex flex-col max-w-[1600px] mx-auto w-full p-6 md:p-8 space-y-6 overflow-hidden">
      {/* Search & Filter Header */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-4 shadow-[0_2px_8px_rgba(15,23,42,0.04)] flex items-center gap-4 flex-wrap justify-between flex-shrink-0">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 w-72 focus-within:border-blue-500 focus-within:bg-white transition-all">
            <Search size={15} className="text-slate-400" />
            <input
              type="text" value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search findings or resources..."
              className="bg-transparent text-sm text-slate-800 placeholder-slate-400 outline-none w-full font-medium" />
            {search && <button onClick={() => setSearch('')}><X size={13} className="text-slate-400 hover:text-slate-600" /></button>}
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {severities.map(s => (
              <button key={s} onClick={() => setSeverityFilter(s)}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all border ${
                  severityFilter === s
                    ? 'bg-blue-600 text-white border-blue-600 shadow-xs'
                    : `${sevPills[s]} hover:opacity-80`
                }`}>
                {s}{s !== 'all' && sevCounts[s] > 0 ? ` (${sevCounts[s]})` : ''}
              </button>
            ))}
          </div>
        </div>
        <div className="text-xs font-bold text-slate-500">
          Showing {filtered.length} of {findings.length} findings
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex min-h-0 gap-6 overflow-hidden">
        {/* Table list */}
        <div className="flex-1 overflow-y-auto pr-1 space-y-3">
          {/* Table column headers */}
          <div className="grid grid-cols-12 gap-3 px-5 py-2 text-[11px] uppercase tracking-wider text-slate-400 font-extrabold">
            {[{k:'stackRank',l:'Stack #',c:'col-span-1'},{k:'title',l:'Finding Title',c:'col-span-4'},{k:'severity',l:'Severity',c:'col-span-2'},{k:'resource',l:'Resource Asset',c:'col-span-2'},{k:'risk',l:'Risk Score',c:'col-span-2'},{k:'status',l:'Status',c:'col-span-1'}].map(col => (
              <button key={col.k} onClick={() => toggleSort(col.k)}
                className={`${col.c} flex items-center gap-1 hover:text-slate-700 transition-colors text-left`}>
                {col.l}<SortIcon k={col.k} />
              </button>
            ))}
          </div>

          {/* Finding Cards */}
          {filtered.map(f => (
            <motion.div key={f.id} layout onClick={() => setSelectedFinding(selectedFinding === f.id ? null : f.id)}
              className={`grid grid-cols-12 gap-3 items-center px-5 py-4 rounded-2xl border cursor-pointer transition-all bg-white ${
                selectedFinding === f.id
                  ? 'border-blue-500 ring-2 ring-blue-500/10 shadow-md'
                  : 'border-slate-200/90 hover:border-slate-300 shadow-2xs hover:shadow-xs'
              }`}>
              {/* Stackelberg Rank */}
              <div className="col-span-1">
                <span className="text-base font-extrabold text-blue-600 font-mono">#{f.stackRank}</span>
                {f.stackRank !== f.naiveRank && (
                  <span className={`block text-[10px] font-bold ${f.stackRank < f.naiveRank ? 'text-emerald-600' : 'text-rose-600'}`}>
                    {f.stackRank < f.naiveRank ? `↑${f.naiveRank - f.stackRank} rank` : `↓${f.stackRank - f.naiveRank} rank`}
                  </span>
                )}
              </div>
              {/* Title */}
              <div className="col-span-4">
                <p className="text-sm font-bold text-slate-900 leading-snug">{f.title}</p>
                {f.dpdp.length > 0 && (
                  <div className="flex gap-1.5 mt-1">
                    {f.dpdp.map(d => <span key={d} className="text-[10px] bg-blue-50 text-blue-700 border border-blue-200 px-2 py-0.5 rounded font-mono font-bold">{d}</span>)}
                  </div>
                )}
              </div>
              {/* Severity */}
              <div className="col-span-2">
                <SeverityBadge severity={f.severity} />
              </div>
              {/* Resource */}
              <div className="col-span-2">
                <span className="text-xs font-mono font-bold text-slate-700 block truncate">{f.resource}</span>
                <span className="text-[11px] text-slate-400 font-medium">{f.type}</span>
              </div>
              {/* Risk bar */}
              <div className="col-span-2">
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{
                      width: `${f.risk}%`,
                      backgroundColor: f.severity === 'critical' ? '#dc2626' : f.severity === 'high' ? '#ea580c' : '#f59e0b'
                    }} />
                  </div>
                  <span className="text-xs font-bold font-mono text-slate-800">{f.risk}</span>
                </div>
              </div>
              {/* Status */}
              <div className="col-span-1">
                <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                  {f.status}
                </span>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Detail drawer */}
        <AnimatePresence>
          {selectedF && (
            <motion.div initial={{ x: 380, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 380, opacity: 0 }}
              className="w-96 bg-white border border-slate-200/90 rounded-2xl p-6 shadow-lg overflow-y-auto flex-shrink-0 space-y-5">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <SeverityBadge severity={selectedF.severity} />
                    <span className="text-xs font-mono font-bold text-slate-400">{selectedF.id}</span>
                  </div>
                  <h3 className="text-base font-extrabold text-slate-900 leading-snug">{selectedF.title}</h3>
                </div>
                <button onClick={() => setSelectedFinding(null)} className="text-slate-400 hover:text-slate-700 p-1">
                  <X size={18} />
                </button>
              </div>

              {/* Stackelberg Summary Card */}
              <div className="bg-blue-50/70 border border-blue-100 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-blue-700 font-extrabold mb-1.5 flex items-center gap-1.5">
                  <Target size={13} /> Stackelberg Optimal Fix
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Optimal Rank</span>
                    <span className="text-lg font-extrabold text-blue-700">#{selectedF.stackRank}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Naive Severity Rank</span>
                    <span className="text-lg font-extrabold text-slate-500">#{selectedF.naiveRank}</span>
                  </div>
                </div>
                <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                  Eliminating this finding breaks the attacker's fallback path to customer records, yielding maximal blast reduction per remediation credit.
                </p>
              </div>

              {/* Related Remediations */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Recommended Fix</h4>
                {relatedRem.length > 0 ? (
                  relatedRem.map(r => (
                    <div key={r.id} className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-slate-900">{r.title}</span>
                        <span className="text-[10px] font-bold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded">OPA Passed</span>
                      </div>
                      <p className="text-xs text-slate-600">{r.explanation}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-400 italic">No automated remediation in pipeline yet.</p>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

// ============================================================
// PAGE: ATTACK GRAPH
// ============================================================
function AttackGraphPage() {
  const { activeScenario } = useScenario();
  const { nodes, edges, criticalPath } = getGraphData(activeScenario);
  const [selected, setSelected] = useState(null);
  const [showCritical, setShowCritical] = useState(true);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 0.95 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const svgRef = useRef(null);

  const positions = activeScenario === 'dpdp_violation' ? dpdpPositions : iamPositions;

  const isOnCritPath = useCallback((id) => criticalPath.includes(id), [criticalPath]);
  const isEdgeCrit = useCallback((s, t) => {
    const sIdx = criticalPath.indexOf(s);
    const tIdx = criticalPath.indexOf(t);
    return sIdx !== -1 && tIdx !== -1 && tIdx === sIdx + 1;
  }, [criticalPath]);

  const zoomIn = () => setTransform(t => ({ ...t, scale: Math.min(t.scale * 1.2, 2.5) }));
  const zoomOut = () => setTransform(t => ({ ...t, scale: Math.max(t.scale / 1.2, 0.4) }));
  const resetView = () => setTransform({ x: 0, y: 0, scale: 0.95 });

  const handleMouseDown = (e) => {
    if (e.target.tagName === 'svg' || e.target.tagName === 'rect') {
      setDragging(true);
      setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
    }
  };
  const handleMouseMove = (e) => {
    if (dragging) {
      setTransform(t => ({ ...t, x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }));
    }
  };
  const handleMouseUp = () => setDragging(false);

  const selectedNode = nodes.find(n => n.id === selected);

  return (
    <div className="h-full flex flex-col max-w-[1600px] mx-auto w-full p-6 md:p-8 space-y-4 overflow-hidden">
      {/* Toolbar */}
      <div className="bg-white border border-slate-200/90 rounded-2xl px-6 py-3.5 shadow-[0_2px_8px_rgba(15,23,42,0.04)] flex items-center justify-between flex-wrap gap-3 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button onClick={() => setShowCritical(!showCritical)}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all border ${
              showCritical
                ? 'bg-red-50 text-red-700 border-red-200 shadow-2xs'
                : 'bg-slate-50 text-slate-600 border-slate-200'
            }`}>
            <Target size={14} /> {showCritical ? 'Critical Attack Path: Active' : 'Highlight Critical Path'}
          </button>
          <div className="flex items-center gap-1 bg-slate-50 border border-slate-200 rounded-xl p-1">
            <button onClick={zoomIn} className="p-1.5 rounded-lg hover:bg-white text-slate-600 transition-colors"><ZoomIn size={14} /></button>
            <button onClick={zoomOut} className="p-1.5 rounded-lg hover:bg-white text-slate-600 transition-colors"><ZoomOut size={14} /></button>
            <button onClick={resetView} className="p-1.5 rounded-lg hover:bg-white text-slate-600 transition-colors"><RotateCcw size={14} /></button>
            <span className="text-[11px] font-mono font-bold text-slate-500 px-2">{Math.round(transform.scale * 100)}%</span>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs font-semibold text-slate-500">
          <span className="hidden md:inline">Drag to pan · Click node to inspect details</span>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-blue-600 inline-block" /> EC2</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-purple-600 inline-block" /> Role</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> S3</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-600 inline-block" /> Entry</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas and Node Inspector */}
      <div className="flex-1 flex min-h-0 gap-6 overflow-hidden">
        <div
          ref={svgRef}
          className="flex-1 bg-white border border-slate-200/90 rounded-2xl relative overflow-hidden cursor-grab active:cursor-grabbing shadow-[0_2px_8px_rgba(15,23,42,0.04)]"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          <svg width="100%" height="100%" viewBox="0 0 1200 600">
            <defs>
              <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M0,0 L10,3 L0,6 Z" fill="#94a3b8" />
              </marker>
              <marker id="arrow-crit" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M0,0 L10,3 L0,6 Z" fill="#dc2626" />
              </marker>
              <pattern id="gridDots" width="30" height="30" patternUnits="userSpaceOnUse">
                <circle cx="15" cy="15" r="1.5" fill="#cbd5e1" opacity="0.6" />
              </pattern>
            </defs>

            <rect width="100%" height="100%" fill="url(#gridDots)" />

            <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
              {/* Edges */}
              {edges.map((e, i) => {
                const from = positions[e.s];
                const to = positions[e.t];
                if (!from || !to) return null;
                const isCrit = isEdgeCrit(e.s, e.t);
                return (
                  <g key={i}>
                    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={isCrit ? '#dc2626' : '#94a3b8'}
                      strokeWidth={isCrit ? 3 : 1.5}
                      strokeDasharray={isCrit ? 'none' : '4 3'}
                      markerEnd={isCrit ? 'url(#arrow-crit)' : 'url(#arrow)'}
                      opacity={showCritical && !isCrit ? 0.3 : 0.9}
                    />
                    {isCrit && (
                      <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 8}
                        fill="#dc2626" fontSize="10" fontWeight="bold" textAnchor="middle" fontFamily="var(--font-mono)">
                        {e.label}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map(n => {
                const pos = positions[n.id];
                if (!pos) return null;
                const color = NODE_COLORS[n.type] || '#64748b';
                const onPath = isOnCritPath(n.id);
                const isSel = selected === n.id;
                const dim = showCritical && !onPath;
                const r = n.crown ? 24 : 18;
                return (
                  <g key={n.id} onClick={() => setSelected(n.id)} className="cursor-pointer">
                    {n.crown && (
                      <circle cx={pos.x} cy={pos.y} r={r + 8} fill="none" stroke="#ea580c" strokeWidth="2" strokeDasharray="3 3" opacity="0.6">
                        <animate attributeName="r" values={`${r+6};${r+12};${r+6}`} dur="3s" repeatCount="indefinite" />
                      </circle>
                    )}
                    <circle cx={pos.x} cy={pos.y} r={r} fill="#ffffff" stroke={isSel ? '#2563eb' : onPath ? '#dc2626' : color}
                      strokeWidth={isSel ? 3.5 : onPath ? 3 : 2} opacity={dim ? 0.3 : 1} filter="drop-shadow(0 2px 4px rgba(0,0,0,0.08))" />
                    <text x={pos.x} y={pos.y + 1} fill={dim ? '#94a3b8' : color} fontSize="11" textAnchor="middle" dominantBaseline="middle"
                      fontFamily="var(--font-mono)" fontWeight="bold">{n.risk}</text>
                    <text x={pos.x} y={pos.y + r + 15} fill={dim ? '#94a3b8' : '#0f172a'} fontSize="11" textAnchor="middle"
                      fontFamily="var(--font-sans)" fontWeight="700">
                      {n.label.length > 18 ? n.label.slice(0,16)+'…' : n.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Node Inspector Drawer */}
        <AnimatePresence>
          {selectedNode && (
            <motion.div initial={{ x: 340, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 340, opacity: 0 }}
              className="w-88 bg-white border border-slate-200/90 rounded-2xl p-6 shadow-lg overflow-y-auto flex-shrink-0 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase font-extrabold text-blue-600 tracking-wider">Node Inspector</span>
                <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-700"><X size={16} /></button>
              </div>
              <div>
                <h4 className="text-base font-extrabold text-slate-900 font-mono">{selectedNode.label}</h4>
                <span className="text-xs uppercase font-bold text-slate-400">{selectedNode.type}</span>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Risk Contribution</span>
                <div className="text-2xl font-extrabold text-slate-900 font-mono">{selectedNode.risk} <span className="text-sm text-slate-400 font-normal">/ 100</span></div>
              </div>
              {selectedNode.issue && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-3 text-xs text-red-800 space-y-1">
                  <div className="font-bold flex items-center gap-1 text-red-700"><AlertTriangle size={12} /> Detected Issue</div>
                  <p>{selectedNode.issue}</p>
                </div>
              )}
              {selectedNode.detail && (
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 text-xs font-mono text-slate-700">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Metadata</span>
                  {selectedNode.detail}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

// ============================================================
// PAGE: DPDP COMPLIANCE
// ============================================================
function DPDPCompliancePage() {
  const { activeScenario } = useScenario();
  const compliance = getDPDPCompliance(activeScenario);
  const [showPost, setShowPost] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const displayScore = showPost ? compliance.postScore : compliance.score;

  return (
    <div className="p-6 md:p-8 overflow-y-auto h-full space-y-6 pb-28 max-w-[1600px] mx-auto w-full pr-8">
      {/* Header */}
      <div className="bg-white border border-slate-200/90 rounded-2xl px-6 py-4 shadow-[0_2px_8px_rgba(15,23,42,0.04)] flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-lg font-extrabold text-slate-900">DPDP Act Compliance — Rules 6, 7, 8, 15</h2>
          <p className="text-xs text-slate-500 mt-0.5 font-medium">Digital Personal Data Protection Rules · Effective Enforceability May 2027</p>
        </div>
        <div className="flex items-center gap-3 bg-slate-50 border border-slate-200 px-3.5 py-1.5 rounded-xl">
          <span className="text-xs font-bold text-slate-600">Current</span>
          <button onClick={() => setShowPost(!showPost)}
            className={`relative w-11 h-6 rounded-full transition-colors ${showPost ? 'bg-blue-600' : 'bg-slate-300'}`}>
            <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform shadow-xs ${showPost ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
          <span className="text-xs font-bold text-blue-700">Post-Remediation (+{compliance.postScore - compliance.score}%)</span>
        </div>
      </div>

      {/* Grid: Dial + Rule Cards */}
      <div className="grid grid-cols-12 gap-6">
        {/* Score Dial */}
        <div className="col-span-12 lg:col-span-4 bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.04)] flex flex-col items-center justify-center text-center">
          <span className="text-xs uppercase font-extrabold text-slate-400 tracking-wider mb-4">DPDP Readiness Score</span>
          <RiskGauge value={displayScore} size={160} label="READINESS %" color={displayScore > 70 ? '#059669' : displayScore > 50 ? '#f59e0b' : '#dc2626'} />
          <div className="mt-4 text-xs font-semibold text-slate-600">
            {displayScore > 70 ? 'Audit Ready — Low Legal Liability' : 'High Regulatory Exposure — Penalty Cap ₹250 Cr'}
          </div>
        </div>

        {/* Rule Cards */}
        <div className="col-span-12 lg:col-span-8 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {DPDP_RULES.map(rule => {
            const status = compliance.rules[rule.id];
            if (!status) return null;
            const isExpanded = expanded === rule.id;
            const statusStyle = {
              pass: 'border-emerald-200 bg-emerald-50/50 text-emerald-800',
              fail: 'border-rose-200 bg-rose-50/50 text-rose-800',
              warn: 'border-amber-200 bg-amber-50/50 text-amber-800'
            };
            return (
              <div key={rule.id}
                onClick={() => setExpanded(isExpanded ? null : rule.id)}
                className={`bg-white border rounded-2xl p-5 shadow-2xs hover:shadow-xs transition-all cursor-pointer overflow-visible ${
                  status.s === 'fail' ? 'border-rose-300' : 'border-slate-200/90'
                }`}>
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <span className="text-xs font-mono font-bold text-blue-600">{rule.ref}</span>
                    <h4 className="text-sm font-bold text-slate-900 mt-0.5">{rule.title}</h4>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase flex-shrink-0 ${statusStyle[status.s]}`}>
                    {status.s}
                  </span>
                </div>
                <p className="text-xs text-slate-500 font-medium leading-snug">{rule.meaning}</p>
                <div className="flex items-center justify-between mt-3 text-[11px] font-semibold text-slate-400">
                  <span>Penalty: <strong className="text-slate-700">{rule.penalty}</strong></span>
                  <span>{status.fail.length} of {status.total} failed</span>
                </div>
                {isExpanded && status.fail.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-100 text-xs text-rose-700 font-mono space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">Non-Compliant Resources:</span>
                    {status.fail.map((r, i) => (
                      <div key={i} className="flex items-center gap-1.5">• {r}</div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// PAGE: REMEDIATION
// ============================================================
function RemediationPage() {
  const { activeScenario } = useScenario();
  const remediations = getRemediations(activeScenario);
  const [selectedRem, setSelectedRem] = useState(null);
  const [bayesThreshold, setBayesThreshold] = useState(0.90);

  const columns = [
    { key: 'drafted', label: 'Drafted', color: 'bg-blue-600' },
    { key: 'verified', label: 'Verified (OPA)', color: 'bg-indigo-600' },
    { key: 'approved', label: 'Approved', color: 'bg-amber-500' },
    { key: 'applied', label: 'Applied', color: 'bg-emerald-600' },
  ];

  const grouped = useMemo(() => {
    const g = { drafted: [], verified: [], approved: [], applied: [] };
    remediations.forEach(r => g[r.status]?.push(r));
    return g;
  }, [remediations]);

  return (
    <div className="h-full flex flex-col max-w-[1600px] mx-auto w-full p-6 md:p-8 space-y-6 overflow-hidden">
      {/* Controls */}
      <div className="bg-white border border-slate-200/90 rounded-2xl px-6 py-4 shadow-[0_2px_8px_rgba(15,23,42,0.04)] flex items-center justify-between flex-wrap gap-4 flex-shrink-0">
        <div>
          <h2 className="text-base font-extrabold text-slate-900">Remediation Action Pipeline</h2>
          <p className="text-xs text-slate-500 mt-0.5">Automated Least-Privilege Generation &amp; Open Policy Agent Gates</p>
        </div>
        <div className="flex items-center gap-3 bg-slate-50 border border-slate-200 px-4 py-2 rounded-xl">
          <span className="text-xs font-bold text-slate-600">Bayes Threshold</span>
          <input type="range" min="0.5" max="0.99" step="0.01" value={bayesThreshold}
            onChange={e => setBayesThreshold(parseFloat(e.target.value))}
            className="w-28 accent-blue-600" />
          <span className="text-xs font-mono font-bold text-blue-700">{bayesThreshold.toFixed(2)}</span>
        </div>
      </div>

      {/* Kanban Board */}
      <div className="flex-1 overflow-x-auto pb-4">
        <div className="flex gap-6 h-full min-w-[1000px]">
          {columns.map(col => (
            <div key={col.key} className="flex-1 flex flex-col min-w-[240px] bg-slate-100/60 rounded-2xl p-4 border border-slate-200/80">
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-200">
                <div className="flex items-center gap-2">
                  <span className={`w-2.5 h-2.5 rounded-full ${col.color}`} />
                  <span className="text-xs font-extrabold text-slate-800 uppercase tracking-wider">{col.label}</span>
                </div>
                <span className="text-xs font-bold text-slate-500 bg-white px-2 py-0.5 rounded-md border border-slate-200">
                  {grouped[col.key].length}
                </span>
              </div>
              <div className="space-y-3 flex-1 overflow-y-auto pr-1">
                {grouped[col.key].map(r => (
                  <motion.div key={r.id} layout onClick={() => setSelectedRem(selectedRem === r.id ? null : r.id)}
                    className="bg-white border border-slate-200/90 rounded-xl p-4 shadow-2xs hover:shadow-xs transition-all cursor-pointer space-y-2">
                    <div className="flex items-center justify-between">
                      <SeverityBadge severity={r.sev} />
                      <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                        conf: {(r.conf * 100).toFixed(0)}%
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-slate-900">{r.title}</h4>
                    <p className="text-[11px] font-mono text-slate-500 truncate">{r.resource}</p>
                    <div className="flex items-center gap-2 text-xs font-bold">
                      <span className="text-rose-600">{r.rBefore}</span>
                      <ArrowRight size={12} className="text-slate-400" />
                      <span className="text-emerald-600">{r.rAfter}</span>
                      <span className="text-[10px] font-normal text-slate-400">risk delta</span>
                    </div>
                    {/* Expandable diff */}
                    {selectedRem === r.id && (
                      <div className="mt-3 pt-3 border-t border-slate-100 space-y-2 text-[10px] font-mono">
                        <div className="bg-rose-50 border border-rose-200 rounded-lg p-2.5 text-rose-800 whitespace-pre-wrap">
                          <strong className="block text-rose-900 mb-1">ORIGINAL CONFIG</strong>
                          {r.before}
                        </div>
                        <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-2.5 text-emerald-800 whitespace-pre-wrap">
                          <strong className="block text-emerald-900 mb-1">REMEDIATED PATCH</strong>
                          {r.after}
                        </div>
                        <p className="text-xs font-sans text-slate-600">{r.explanation}</p>
                      </div>
                    )}
                  </motion.div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// PAGE: SETTINGS
// ============================================================
function SettingsPage() {
  const [settings, setSettings] = useState({
    autoApply: true,
    dpdpAlerts: true,
    liveRefresh: true,
    damping: 0.85,
    bayesThreshold: 0.90,
  });

  return (
    <div className="p-6 md:p-8 overflow-y-auto h-full space-y-6 pb-28 max-w-[1200px] mx-auto w-full">
      <div className="bg-white border border-slate-200/90 rounded-2xl px-6 py-4 shadow-[0_2px_8px_rgba(15,23,42,0.04)] flex items-center justify-between">
        <div>
          <h2 className="text-lg font-extrabold text-slate-900">System Configuration</h2>
          <p className="text-xs text-slate-500 mt-0.5 font-medium">ARGUS Engine, Policy Gates, and Algorithmic Parameters</p>
        </div>
        <span className="text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1 rounded-lg flex items-center gap-1.5">
          <CheckCircle2 size={13} /> Engine Active
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.04)] space-y-4">
          <h3 className="text-sm font-extrabold text-slate-900">Risk Solver Parameters</h3>
          <div className="space-y-3 text-xs">
            <div>
              <div className="flex justify-between font-bold text-slate-700 mb-1">
                <span>PageRank Damping Factor</span>
                <span className="font-mono text-blue-600">{settings.damping}</span>
              </div>
              <input type="range" min="0.5" max="0.99" step="0.01" value={settings.damping}
                onChange={e => setSettings(s => ({ ...s, damping: parseFloat(e.target.value) }))}
                className="w-full accent-blue-600" />
            </div>
            <div>
              <div className="flex justify-between font-bold text-slate-700 mb-1">
                <span>Bayesian Auto-Apply Cutoff</span>
                <span className="font-mono text-blue-600">{settings.bayesThreshold}</span>
              </div>
              <input type="range" min="0.5" max="0.99" step="0.01" value={settings.bayesThreshold}
                onChange={e => setSettings(s => ({ ...s, bayesThreshold: parseFloat(e.target.value) }))}
                className="w-full accent-blue-600" />
            </div>
          </div>
        </div>

        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-[0_2px_8px_rgba(15,23,42,0.04)] space-y-4">
          <h3 className="text-sm font-extrabold text-slate-900">Automation &amp; Alerts</h3>
          <div className="space-y-3 text-xs">
            <label className="flex items-center justify-between cursor-pointer">
              <span className="font-bold text-slate-700">Auto-Apply Safe Remediations</span>
              <input type="checkbox" checked={settings.autoApply}
                onChange={e => setSettings(s => ({ ...s, autoApply: e.target.checked }))}
                className="w-4 h-4 accent-blue-600" />
            </label>
            <label className="flex items-center justify-between cursor-pointer">
              <span className="font-bold text-slate-700">DPDP High-Penalty Alerts</span>
              <input type="checkbox" checked={settings.dpdpAlerts}
                onChange={e => setSettings(s => ({ ...s, dpdpAlerts: e.target.checked }))}
                className="w-4 h-4 accent-blue-600" />
            </label>
            <label className="flex items-center justify-between cursor-pointer">
              <span className="font-bold text-slate-700">Telemetry Live Refresh (30s)</span>
              <input type="checkbox" checked={settings.liveRefresh}
                onChange={e => setSettings(s => ({ ...s, liveRefresh: e.target.checked }))}
                className="w-4 h-4 accent-blue-600" />
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// CHAT PANEL
// ============================================================
function ChatPanel({ isOpen, onClose }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', text: 'I am ARGUS AI Assistant. Inquire about attack paths, DPDP liability exposure, or Stackelberg priorities.' }
  ]);
  const [input, setInput] = useState('');
  const bottomRef = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = (q) => {
    const question = q || input;
    if (!question.trim()) return;
    setMessages(prev => [...prev, { role: 'user', text: question }]);
    setInput('');
    setTimeout(() => {
      setMessages(prev => [...prev, { role: 'assistant', text: getChatReply(question) }]);
    }, 400);
  };

  if (!isOpen) return null;

  return (
    <motion.div initial={{ x: 400, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 400, opacity: 0 }}
      className="w-96 border-l border-slate-200 bg-white flex flex-col h-full shadow-2xl z-40">
      <div className="h-16 border-b border-slate-200 flex items-center justify-between px-5">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl bg-blue-600 flex items-center justify-center text-white">
            <Bot size={16} />
          </div>
          <span className="text-sm font-bold text-slate-900">Ask ARGUS</span>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-600 p-1"><X size={18} /></button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3 text-xs">
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`p-3 rounded-2xl max-w-[85%] leading-relaxed ${
              m.role === 'user' ? 'bg-blue-600 text-white rounded-br-none' : 'bg-slate-100 text-slate-800 rounded-bl-none font-medium'
            }`}>
              {m.text}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <div className="p-3 border-t border-slate-200 space-y-2">
        <div className="flex flex-wrap gap-1">
          {CHAT_SUGGESTIONS.slice(0, 2).map(s => (
            <button key={s} onClick={() => send(s)} className="text-[10px] bg-slate-50 hover:bg-slate-100 border border-slate-200 px-2 py-1 rounded-lg text-slate-600">
              {s}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3 py-2">
          <input type="text" value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && send()}
            placeholder="Ask security question..."
            className="flex-1 bg-transparent text-xs text-slate-800 outline-none" />
          <button onClick={() => send()} className="text-blue-600 hover:text-blue-800 font-bold"><Send size={15} /></button>
        </div>
      </div>
    </motion.div>
  );
}

// ============================================================
// APP ROOT
// ============================================================
export default function App() {
  return (
    <ScenarioProvider>
      <AppShell />
    </ScenarioProvider>
  );
}

function AppShell() {
  const { activeScenario, setActiveScenario } = useScenario();
  const [activePage, setActivePage] = useState('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);

  const pages = {
    overview: OverviewPage,
    findings: FindingsPage,
    graph: AttackGraphPage,
    dpdp: DPDPCompliancePage,
    remediation: RemediationPage,
    settings: SettingsPage,
  };
  const PageComponent = pages[activePage] || OverviewPage;

  return (
    <div className="flex h-full w-full bg-[#ebf1f6] overflow-hidden">
      <Sidebar active={activePage} onNav={setActivePage} collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        <TopBar scenarioId={activeScenario} onScenarioChange={setActiveScenario} />
        <div className="flex-1 flex min-h-0 overflow-hidden">
          <main className="flex-1 min-w-0 overflow-y-auto">
            <AnimatePresence mode="wait">
              <motion.div key={activePage + activeScenario}
                initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.15 }} className="h-full">
                <PageComponent />
              </motion.div>
            </AnimatePresence>
          </main>
          <AnimatePresence>
            {chatOpen && <ChatPanel isOpen={chatOpen} onClose={() => setChatOpen(false)} />}
          </AnimatePresence>
        </div>
      </div>

      {/* Floating Chat Button */}
      {!chatOpen && (
        <button onClick={() => setChatOpen(true)}
          className="fixed bottom-6 right-6 w-12 h-12 rounded-full bg-blue-600 text-white shadow-lg shadow-blue-600/30 flex items-center justify-center hover:scale-105 transition-all z-50">
          <MessageSquare size={20} />
        </button>
      )}
    </div>
  );
}

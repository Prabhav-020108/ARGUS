import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip as RTooltip, ResponsiveContainer,
  LineChart, Line, Area, AreaChart, ReferenceLine, Cell
} from 'recharts';
import {
  Shield, Activity, AlertTriangle, CheckCircle2, XCircle, ChevronDown,
  BarChart3, Network, FileCheck, Settings, Eye, Clock, TrendingDown,
  ChevronRight, Search, Send, Bot, User, Zap, Lock, Server, Database,
  Cloud, Globe, ArrowRight, X, Check, Info, MessageSquare, Layers,
  GitBranch, Target, ShieldCheck, ShieldAlert, ArrowUpRight, Minus, Menu,
  FileCode, ExternalLink
} from 'lucide-react';
import { ScenarioProvider, useScenario, SCENARIOS } from './data/scenarios';

// ============================================================
// DATA — Attack Graph
// ============================================================
const NODE_COLORS = {
  user: '#a78bfa', role: '#c084fc', ec2: '#60a5fa', s3: '#fbbf24',
  rds: '#f97316', sg: '#6b7280', vpc: '#4b5563', lambda: '#34d399',
  policy: '#f472b6', entry: '#ef4444',
};

const NODE_ICONS = {
  user: User, role: Lock, ec2: Server, s3: Database, rds: Database,
  sg: Shield, vpc: Cloud, lambda: Zap, policy: FileCheck, entry: Globe,
};

function getGraphData(scenarioId) {
  if (scenarioId === 'dpdp_violation') return { nodes: dpdpNodes, edges: dpdpEdges, criticalPath: dpdpCriticalPath };
  return { nodes: iamNodes, edges: iamEdges, criticalPath: iamCriticalPath };
}

// Deterministic semantic positions for IAM scenario graph
// Columns: 0=Internet, 1=SG, 2=EC2, 3=Role/User, 4=Policy, 5=Data
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
  const d = sid === 'dpdp_violation' ? dpdpComp : iamComp;
  return d;
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
function AnimatedNumber({ value, duration = 1200 }) {
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
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/15 text-green-400 border-green-500/30',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider border ${colors[severity]}`}>
      {severity}
    </span>
  );
}

function StatusDot({ status }) {
  const c = { pass: 'bg-emerald-400', fail: 'bg-red-400', warn: 'bg-amber-400', info: 'bg-cyan-400' };
  return <span className={`inline-block w-2 h-2 rounded-full ${c[status] || c.info}`} />;
}

function RiskGauge({ value, size = 120, label, color }) {
  const r = (size - 12) / 2;
  const circ = 2 * Math.PI * r;
  const arc = circ * 0.75;
  const offset = arc - (arc * Math.min(value, 100) / 100);
  const c = color || (value > 70 ? '#ef4444' : value > 40 ? '#f59e0b' : '#10b981');
  return (
    <div className="relative flex flex-col items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-[135deg]">
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e293b" strokeWidth="8" strokeDasharray={`${arc} ${circ}`} strokeLinecap="round" />
        <motion.circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth="8" strokeDasharray={`${arc} ${circ}`} strokeLinecap="round"
          initial={{ strokeDashoffset: arc }} animate={{ strokeDashoffset: offset }} transition={{ duration: 1.2, ease: 'easeOut' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums" style={{ color: c }}><AnimatedNumber value={value} /></span>
        {label && <span className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wider mt-0.5">{label}</span>}
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, sub, accent }) {
  return (
    <div className="bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-4 flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">{label}</span>
        {Icon && <Icon size={14} className="text-[var(--color-text-muted)]" />}
      </div>
      <span className={`text-2xl font-bold tabular-nums ${accent || 'text-[var(--color-text-primary)]'}`}>
        {typeof value === 'number' ? <AnimatedNumber value={value} /> : value}
      </span>
      {sub && <span className="text-xs text-[var(--color-text-muted)]">{sub}</span>}
    </div>
  );
}

// ============================================================
// SIDEBAR
// ============================================================
const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: BarChart3 },
  { id: 'graph', label: 'Attack Graph', icon: Network },
  { id: 'dpdp', label: 'DPDP Compliance', icon: ShieldCheck },
  { id: 'remediation', label: 'Remediation', icon: FileCheck },
  { id: 'settings', label: 'Settings', icon: Settings },
];

function Sidebar({ active, onNav, collapsed, onToggle }) {
  return (
    <aside className={`h-full bg-[var(--color-bg-secondary)] border-r border-[var(--color-border)] flex flex-col transition-all duration-300 ${collapsed ? 'w-16' : 'w-56'}`}>
      {/* Logo */}
      <div className="h-14 flex items-center gap-2.5 px-4 border-b border-[var(--color-border)]">
        <button onClick={onToggle} className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center flex-shrink-0">
            <Shield size={16} className="text-white" />
          </div>
          {!collapsed && <span className="text-base font-bold tracking-tight">ARGUS</span>}
        </button>
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-3 px-2 flex flex-col gap-0.5">
        {NAV_ITEMS.map(item => {
          const isActive = active === item.id;
          return (
            <button key={item.id} onClick={() => onNav(item.id)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-[var(--color-bg-elevated)] text-[var(--color-text-primary)] shadow-sm'
                  : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)]'
              }`}
              title={collapsed ? item.label : undefined}
            >
              <item.icon size={18} className={isActive ? 'text-amber-400' : ''} />
              {!collapsed && <span>{item.label}</span>}
              {!collapsed && isActive && <ChevronRight size={14} className="ml-auto text-[var(--color-text-muted)]" />}
            </button>
          );
        })}
      </nav>

      {/* Environment badge */}
      {!collapsed && (
        <div className="px-3 pb-4">
          <div className="bg-[var(--color-bg-tertiary)] rounded-lg p-3 border border-[var(--color-border-subtle)]">
            <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-[var(--color-text-muted)] font-semibold mb-1">
              <Cloud size={10} /> Environment
            </div>
            <div className="text-xs text-[var(--color-text-secondary)] font-mono">AWS · us-east-1</div>
            <div className="text-[10px] text-[var(--color-text-muted)] font-mono mt-0.5">argus-demo</div>
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
    <header className="h-14 bg-[var(--color-bg-secondary)] border-b border-[var(--color-border)] flex items-center justify-between px-5">
      <div className="flex items-center gap-3">
        <div className="relative">
          <button onClick={() => setOpen(!open)}
            className="flex items-center gap-2 bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] rounded-lg px-3 py-1.5 text-sm font-medium hover:border-[var(--color-text-muted)] transition-colors">
            <Zap size={14} className="text-amber-400" />
            <span className="max-w-[280px] truncate">{sc.shortName}</span>
            <ChevronDown size={14} className="text-[var(--color-text-muted)]" />
          </button>
          <AnimatePresence>
            {open && (
              <motion.div initial={{ opacity:0, y:-4 }} animate={{ opacity:1, y:0 }} exit={{ opacity:0, y:-4 }}
                className="absolute top-full left-0 mt-1 w-80 bg-[var(--color-bg-elevated)] border border-[var(--color-border)] rounded-xl shadow-2xl z-50 overflow-hidden">
                {Object.values(SCENARIOS).map(s => (
                  <button key={s.id} onClick={() => { onScenarioChange(s.id); setOpen(false); }}
                    className={`w-full text-left px-4 py-3 hover:bg-[var(--color-bg-tertiary)] transition-colors ${s.id === scenarioId ? 'bg-[var(--color-bg-tertiary)]' : ''}`}>
                    <div className="text-sm font-medium text-[var(--color-text-primary)]">{s.name}</div>
                    <div className="text-xs text-[var(--color-text-muted)] mt-0.5">{s.description.slice(0, 80)}...</div>
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
      <div className="flex items-center gap-4 text-xs text-[var(--color-text-muted)]">
        <div className="flex items-center gap-1.5"><Clock size={12} /> Last scan: 2 min ago</div>
        <div className="flex items-center gap-1.5"><Activity size={12} className="text-emerald-400" /> Live</div>
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
    <div className="bg-[var(--color-bg-elevated)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="text-[var(--color-text-muted)] mb-1">{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>{p.name}: <strong>{p.value}</strong></p>
      ))}
    </div>
  );
};

function OverviewPage() {
  const { scenario, activeScenario } = useScenario();
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
    name: f.title.length > 28 ? f.title.slice(0, 26) + '…' : f.title,
    stackelberg: f.stackRank,
    naive: f.naiveRank,
    risk: f.risk,
    severity: f.severity,
  }));

  const activity = [
    { time: '2m ago',  text: 'PageRank risk scoring completed (47 nodes)', icon: Activity, color: 'text-cyan-400' },
    { time: '3m ago',  text: 'Verification gate: R-001 passed all 3 checks', icon: CheckCircle2, color: 'text-emerald-400' },
    { time: '5m ago',  text: 'LLM drafted remediation for sg-public-web', icon: Bot, color: 'text-purple-400' },
    { time: '8m ago',  text: 'Stackelberg LP solved: budget B=3, 7 findings ranked', icon: Target, color: 'text-amber-400' },
    { time: '12m ago', text: 'R-004 auto-applied (Bayes confidence 0.96 ≥ 0.90)', icon: Zap, color: 'text-emerald-400' },
    { time: '15m ago', text: 'Cartography ingest: 47 resources, 3 regions', icon: Network, color: 'text-blue-400' },
  ];

  const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' };

  return (
    <div className="p-5 overflow-y-auto h-full">
      {/* Row 1: KPI bar */}
      <div className="grid grid-cols-8 gap-3 mb-5">
        <div className="col-span-2 bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-4 flex items-center gap-4">
          <RiskGauge value={scenario.riskScore} size={90} />
          <div>
            <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">Attack Risk</div>
            <div className="text-xs text-[var(--color-text-secondary)] mt-0.5">PageRank weighted</div>
            <div className={`text-xs mt-1.5 font-semibold ${scenario.riskScore > 70 ? 'text-red-400' : 'text-amber-400'}`}>
              {scenario.riskScore > 70 ? '⚠ HIGH RISK' : '▲ ELEVATED'}
            </div>
          </div>
        </div>
        <div className="col-span-2 bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-4 flex items-center gap-4">
          <RiskGauge value={compliance.score} size={90} color={compliance.score > 70 ? '#10b981' : compliance.score > 50 ? '#f59e0b' : '#ef4444'} />
          <div>
            <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">DPDP Readiness</div>
            <div className="text-xs text-[var(--color-text-secondary)] mt-0.5">Rules 6/7/8/15</div>
            <div className={`text-xs mt-1.5 font-semibold ${compliance.score < 50 ? 'text-red-400' : 'text-amber-400'}`}>
              Post-fix: {compliance.postScore}%
            </div>
          </div>
        </div>
        {[
          { label: 'Critical', val: scenario.findingCounts.critical, color: 'text-red-400', bg: 'bg-red-500/10' },
          { label: 'High', val: scenario.findingCounts.high, color: 'text-orange-400', bg: 'bg-orange-500/10' },
          { label: 'Resources', val: scenario.totalResources, color: 'text-blue-400', bg: 'bg-blue-500/10' },
          { label: 'Auto-Applied', val: pipeline.applied, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
        ].map(s => (
          <div key={s.label} className={`${s.bg} border border-[var(--color-border)] rounded-xl p-4 flex flex-col justify-between`}>
            <span className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">{s.label}</span>
            <span className={`text-3xl font-bold tabular-nums ${s.color}`}><AnimatedNumber value={s.val} /></span>
          </div>
        ))}
      </div>

      {/* Row 2: main content */}
      <div className="grid grid-cols-12 gap-5">
        {/* Stackelberg vs Naive bar chart */}
        <div className="col-span-7 bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold">Stackelberg vs Naive Prioritization</h3>
              <p className="text-[11px] text-[var(--color-text-muted)] mt-0.5">Lower rank number = higher priority. Game model shifts budget away from naive severity ordering.</p>
            </div>
            <div className="flex items-center gap-4 text-[10px]">
              <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-amber-500" /> Stackelberg</div>
              <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#334155]" /> Naive</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData} margin={{ top: 0, right: 8, bottom: 40, left: -20 }}>
              <XAxis dataKey="id" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                angle={-35} textAnchor="end" interval={0} />
              <YAxis reversed tick={{ fill: '#64748b', fontSize: 10 }} domain={[0, chartData.length + 1]}
                tickFormatter={v => `#${v}`} />
              <RTooltip content={<CustomTooltip />}
                formatter={(val, name) => [`#${val}`, name === 'stackelberg' ? 'Stackelberg Rank' : 'Naive Rank']} />
              <Bar dataKey="stackelberg" name="Stackelberg" fill="#f59e0b" radius={[4,4,0,0]} maxBarSize={28} />
              <Bar dataKey="naive" name="Naive" fill="#334155" radius={[4,4,0,0]} maxBarSize={28} />
            </BarChart>
          </ResponsiveContainer>
          {/* Risk delta visual */}
          <div className="mt-3 space-y-1.5">
            {chartData.slice(0, 4).map(f => (
              <div key={f.id} className="flex items-center gap-3 text-xs">
                <span className="font-mono text-[var(--color-text-muted)] w-12">{f.id}</span>
                <div className="flex-1 bg-[var(--color-bg-tertiary)] rounded-full h-1.5 overflow-hidden">
                  <motion.div className="h-full rounded-full" style={{ background: sevColors[f.severity] }}
                    initial={{ width: 0 }} animate={{ width: `${f.risk}%` }} transition={{ duration: 1, delay: 0.2 }} />
                </div>
                <span className="w-6 text-right" style={{ color: sevColors[f.severity] }}>{f.risk}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right column */}
        <div className="col-span-5 space-y-4">
          {/* Risk trend */}
          <div className="bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold">Score Trend (last 15 min)</h3>
              <span className="text-[10px] text-[var(--color-text-muted)]">Live · 30s refresh</span>
            </div>
            <ResponsiveContainer width="100%" height={90}>
              <AreaChart data={trendData} margin={{ top: 4, right: 4, bottom: 0, left: -30 }}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="dpdpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fill: '#475569', fontSize: 9 }} />
                <YAxis domain={[20, 100]} tick={{ fill: '#475569', fontSize: 9 }} />
                <RTooltip content={<CustomTooltip />} formatter={(v, n) => [v, n === 'risk' ? 'Risk' : 'DPDP']} />
                <Area type="monotone" dataKey="risk" name="risk" stroke="#ef4444" fill="url(#riskGrad)" strokeWidth={1.5} dot={false} />
                <Area type="monotone" dataKey="dpdp" name="dpdp" stroke="#06b6d4" fill="url(#dpdpGrad)" strokeWidth={1.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Pipeline */}
          <div className="bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-4">
            <h3 className="text-sm font-semibold mb-3">Remediation Pipeline</h3>
            <div className="space-y-2">
              {[
                { label: 'Drafted by LLM', count: pipeline.drafted, color: 'bg-blue-500', total: 4 },
                { label: 'Verification Passed', count: pipeline.verified, color: 'bg-purple-500', total: 4 },
                { label: 'Approved', count: pipeline.approved, color: 'bg-amber-500', total: 4 },
                { label: 'Auto-Applied', count: pipeline.applied, color: 'bg-emerald-500', total: 4 },
              ].map(s => (
                <div key={s.label} className="flex items-center gap-3">
                  <div className={`w-2 h-2 rounded-full ${s.color} flex-shrink-0`} />
                  <span className="text-xs text-[var(--color-text-secondary)] flex-1">{s.label}</span>
                  <div className="flex gap-1">
                    {Array.from({ length: s.total }).map((_, i) => (
                      <div key={i} className={`w-4 h-4 rounded ${i < s.count ? s.color : 'bg-[var(--color-bg-elevated)]'}`} />
                    ))}
                  </div>
                  <span className="text-xs font-mono text-[var(--color-text-muted)] w-4">{s.count}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Activity feed */}
          <div className="bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-4">
            <h3 className="text-sm font-semibold mb-2">Recent Activity</h3>
            <div className="space-y-2.5">
              {activity.map((a, i) => (
                <div key={i} className="flex items-start gap-2">
                  <a.icon size={13} className={`${a.color} mt-0.5 flex-shrink-0`} />
                  <div className="min-w-0">
                    <p className="text-[11px] text-[var(--color-text-secondary)] leading-relaxed">{a.text}</p>
                    <span className="text-[10px] text-[var(--color-text-muted)]">{a.time}</span>
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
// PAGE: ATTACK GRAPH
// ============================================================
function AttackGraphPage() {
  const { activeScenario } = useScenario();
  const { nodes, edges, criticalPath } = getGraphData(activeScenario);
  const [selected, setSelected] = useState(null);
  const [showCritical, setShowCritical] = useState(false);
  const [layout, setLayout] = useState('force');

  const selectedNode = nodes.find(n => n.id === selected);

  // Use deterministic semantic positions, not random layout
  const positions = useMemo(() => {
    return activeScenario === 'dpdp_violation' ? dpdpPositions : iamPositions;
  }, [activeScenario]);

  useEffect(() => { setSelected(null); }, [activeScenario]);

  const svgWidth = 1100;
  const svgHeight = 550;
  const isOnCritPath = (id) => showCritical && criticalPath.includes(id);
  const isEdgeCrit = (s, t) => {
    if (!showCritical) return false;
    const si = criticalPath.indexOf(s);
    const ti = criticalPath.indexOf(t);
    return si >= 0 && ti >= 0 && Math.abs(si - ti) === 1;
  };

  return (
    <div className="h-full flex">
      {/* Graph area */}
      <div className="flex-1 flex flex-col">
        {/* Controls */}
        <div className="px-5 py-3 border-b border-[var(--color-border)] flex items-center gap-3">
          <button onClick={() => setShowCritical(!showCritical)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              showCritical ? 'bg-red-500/15 text-red-400 border border-red-500/30' : 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] border border-[var(--color-border)]'
            }`}>
            <Target size={13} /> {showCritical ? 'Critical Path Active' : 'Highlight Critical Path'}
          </button>
          <div className="flex items-center bg-[var(--color-bg-tertiary)] rounded-lg border border-[var(--color-border)] overflow-hidden">
            {['force', 'hierarchical'].map(l => (
              <button key={l} onClick={() => setLayout(l)}
                className={`px-3 py-1.5 text-xs font-medium transition-colors ${layout === l ? 'bg-[var(--color-bg-elevated)] text-[var(--color-text-primary)]' : 'text-[var(--color-text-muted)]'}`}>
                {l === 'force' ? 'Force' : 'Hierarchical'}
              </button>
            ))}
          </div>
          <div className="ml-auto flex items-center gap-3 text-[10px] text-[var(--color-text-muted)]">
            {Object.entries(NODE_COLORS).filter(([k]) => k !== 'entry').map(([type, color]) => (
              <div key={type} className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                <span className="uppercase">{type}</span>
              </div>
            ))}
          </div>
        </div>

        {/* SVG Graph */}
        <div className="flex-1 overflow-hidden bg-[var(--color-bg-primary)] relative">
          <svg width="100%" height="100%" viewBox={`0 0 ${svgWidth} ${svgHeight}`}>
            <defs>
              <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M0,0 L10,3 L0,6 Z" fill="#374151" />
              </marker>
              <marker id="arrow-crit" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M0,0 L10,3 L0,6 Z" fill="#ef4444" />
              </marker>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            {/* Edges */}
            {edges.map((e, i) => {
              const from = positions[e.s];
              const to = positions[e.t];
              if (!from || !to) return null;
              const isCrit = isEdgeCrit(e.s, e.t);
              return (
                <g key={i}>
                  <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                    stroke={isCrit ? '#ef4444' : '#1e293b'}
                    strokeWidth={isCrit ? 2.5 : 1}
                    markerEnd={isCrit ? 'url(#arrow-crit)' : 'url(#arrow)'}
                    opacity={showCritical && !isCrit ? 0.2 : 0.8}
                    filter={isCrit ? 'url(#glow)' : undefined}
                  />
                  {isCrit && (
                    <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 6}
                      fill="#ef4444" fontSize="9" textAnchor="middle" fontFamily="var(--font-mono)">{e.label}</text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map(n => {
              const pos = positions[n.id];
              if (!pos) return null;
              const color = NODE_COLORS[n.type] || '#6b7280';
              const onPath = isOnCritPath(n.id);
              const isSel = selected === n.id;
              const dim = showCritical && !onPath;
              const r = n.crown ? 22 : 16;
              return (
                <g key={n.id} onClick={() => setSelected(n.id)} className="cursor-pointer">
                  {/* Crown jewel glow */}
                  {n.crown && (
                    <circle cx={pos.x} cy={pos.y} r={r + 8} fill="none" stroke={color} strokeWidth="1" opacity="0.3">
                      <animate attributeName="r" values={`${r+4};${r+10};${r+4}`} dur="3s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.3;0.1;0.3" dur="3s" repeatCount="indefinite" />
                    </circle>
                  )}
                  {/* Main circle */}
                  <circle cx={pos.x} cy={pos.y} r={r} fill={`${color}20`} stroke={isSel ? '#fff' : onPath ? '#ef4444' : color}
                    strokeWidth={isSel ? 2.5 : onPath ? 2 : 1.5} opacity={dim ? 0.2 : 1} filter={onPath ? 'url(#glow)' : undefined} />
                  {/* Risk score inside */}
                  <text x={pos.x} y={pos.y + 1} fill={dim ? '#374151' : color} fontSize="10" textAnchor="middle" dominantBaseline="middle"
                    fontFamily="var(--font-mono)" fontWeight="600">{n.risk}</text>
                  {/* Label below */}
                  <text x={pos.x} y={pos.y + r + 14} fill={dim ? '#374151' : '#94a3b8'} fontSize="10" textAnchor="middle"
                    fontFamily="var(--font-sans)" fontWeight="500">{n.label.length > 18 ? n.label.slice(0,16)+'…' : n.label}</text>
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      {/* Node inspector panel */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div initial={{ x: 320, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 320, opacity: 0 }}
            className="w-80 border-l border-[var(--color-border)] bg-[var(--color-bg-secondary)] overflow-y-auto">
            <div className="p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold">Node Inspector</h3>
                <button onClick={() => setSelected(null)} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"><X size={16} /></button>
              </div>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-3 h-3 rounded-full" style={{ background: NODE_COLORS[selectedNode.type] }} />
                    <span className="text-xs uppercase tracking-wider text-[var(--color-text-muted)]">{selectedNode.type}</span>
                  </div>
                  <h4 className="text-base font-semibold font-mono">{selectedNode.label}</h4>
                </div>
                <div className="bg-[var(--color-bg-tertiary)] rounded-lg p-3">
                  <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">Risk Score</div>
                  <div className="flex items-center gap-2">
                    <div className="text-2xl font-bold tabular-nums" style={{ color: selectedNode.risk > 70 ? '#ef4444' : selectedNode.risk > 40 ? '#f59e0b' : '#10b981' }}>
                      {selectedNode.risk}
                    </div>
                    <span className="text-sm text-[var(--color-text-muted)]">/ 100</span>
                  </div>
                </div>
                {selectedNode.detail && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">Details</div>
                    <p className="text-xs text-[var(--color-text-secondary)] font-mono">{selectedNode.detail}</p>
                  </div>
                )}
                {selectedNode.issue && (
                  <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-red-400 mb-1">
                      <AlertTriangle size={11} /> Issue
                    </div>
                    <p className="text-xs text-red-300">{selectedNode.issue}</p>
                  </div>
                )}
                {selectedNode.crown && (
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-amber-400">
                      <Target size={11} /> Crown Jewel Asset
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
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
    <div className="p-6 overflow-y-auto h-full space-y-6">
      {/* Header with toggle */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">DPDP Act Compliance — Rules 6/7/8/15</h2>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">Digital Personal Data Protection Rules, 2025 · Notified 13 Nov 2025 · Effective May 2027</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--color-text-muted)]">Current</span>
          <button onClick={() => setShowPost(!showPost)}
            className={`relative w-10 h-5 rounded-full transition-colors ${showPost ? 'bg-emerald-600' : 'bg-[var(--color-bg-elevated)]'}`}>
            <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${showPost ? 'translate-x-5' : 'translate-x-0.5'}`} />
          </button>
          <span className="text-xs text-[var(--color-text-muted)]">Post-remediation</span>
        </div>
      </div>

      {/* Score + rules grid */}
      <div className="grid grid-cols-12 gap-5">
        {/* Score gauge */}
        <div className="col-span-3 bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-6 flex flex-col items-center">
          <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold mb-4">DPDP Readiness Score</span>
          <div className="relative">
            <RiskGauge value={displayScore} size={160} label="%" color={displayScore > 70 ? '#10b981' : displayScore > 50 ? '#f59e0b' : '#ef4444'} />
          </div>
          {showPost && (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
              className="mt-4 flex items-center gap-1.5 text-emerald-400 text-xs font-medium">
              <TrendingDown size={13} className="rotate-180" /> +{compliance.postScore - compliance.score}% after remediation
            </motion.div>
          )}
        </div>

        {/* Rule cards */}
        <div className="col-span-9 grid grid-cols-2 gap-3">
          {DPDP_RULES.map(rule => {
            const status = compliance.rules[rule.id];
            if (!status) return null;
            const isExpanded = expanded === rule.id;
            const statusColor = { pass: 'border-emerald-500/30 bg-emerald-500/5', fail: 'border-red-500/30 bg-red-500/5', warn: 'border-amber-500/30 bg-amber-500/5' };
            const statusText = { pass: 'Passing', fail: 'Failing', warn: 'Warning' };
            const statusIcon = { pass: CheckCircle2, fail: XCircle, warn: AlertTriangle };
            const SIcon = statusIcon[status.s];
            return (
              <div key={rule.id}
                className={`border rounded-xl p-4 cursor-pointer transition-all hover:border-opacity-60 ${statusColor[status.s]}`}
                onClick={() => setExpanded(isExpanded ? null : rule.id)}>
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold font-mono text-[var(--color-text-primary)]">{rule.ref}</span>
                      <SIcon size={14} className={status.s === 'pass' ? 'text-emerald-400' : status.s === 'fail' ? 'text-red-400' : 'text-amber-400'} />
                    </div>
                    <h4 className="text-sm font-medium mt-0.5">{rule.title}</h4>
                  </div>
                  <span className="text-lg font-bold tabular-nums" style={{ color: status.sc > 70 ? '#10b981' : status.sc > 40 ? '#f59e0b' : '#ef4444' }}>
                    {status.sc}%
                  </span>
                </div>
                <p className="text-xs text-[var(--color-text-muted)] leading-relaxed">{rule.meaning}</p>
                <div className="flex items-center justify-between mt-2 text-[10px] text-[var(--color-text-muted)]">
                  <span>Penalty: {rule.penalty}</span>
                  <span>{status.fail.length}/{status.total} resources affected</span>
                </div>
                <AnimatePresence>
                  {isExpanded && status.fail.length > 0 && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                      className="mt-3 pt-3 border-t border-[var(--color-border)] overflow-hidden">
                      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-2">Failing Resources</div>
                      {status.fail.map((r, i) => (
                        <div key={i} className="flex items-center gap-2 py-1">
                          <XCircle size={11} className="text-red-400" />
                          <span className="text-xs font-mono text-[var(--color-text-secondary)]">{r}</span>
                        </div>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// PAGE: REMEDIATION QUEUE
// ============================================================
function RemediationPage() {
  const { activeScenario } = useScenario();
  const remediations = getRemediations(activeScenario);
  const [selectedRem, setSelectedRem] = useState(null);
  const [bayesThreshold, setBayesThreshold] = useState(0.9);

  const columns = [
    { key: 'drafted', label: 'Drafted', color: 'border-blue-500/50', bg: 'bg-blue-500' },
    { key: 'verified', label: 'Verified', color: 'border-purple-500/50', bg: 'bg-purple-500' },
    { key: 'approved', label: 'Approved', color: 'border-amber-500/50', bg: 'bg-amber-500' },
    { key: 'applied', label: 'Applied', color: 'border-emerald-500/50', bg: 'bg-emerald-500' },
  ];

  const grouped = useMemo(() => {
    const g = { drafted: [], verified: [], approved: [], applied: [] };
    remediations.forEach(r => g[r.status]?.push(r));
    return g;
  }, [remediations]);

  return (
    <div className="h-full flex flex-col">
      {/* Controls */}
      <div className="px-5 py-3 border-b border-[var(--color-border)] flex items-center gap-4">
        <h2 className="text-sm font-semibold">Remediation Queue</h2>
        <div className="ml-auto flex items-center gap-3">
          <span className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">Bayes-cost threshold</span>
          <input type="range" min="0.5" max="0.99" step="0.01" value={bayesThreshold}
            onChange={e => setBayesThreshold(parseFloat(e.target.value))}
            className="w-32 accent-amber-500" />
          <span className="text-xs font-mono text-amber-400 w-10">{bayesThreshold.toFixed(2)}</span>
          <span className="text-[10px] text-[var(--color-text-muted)]">
            ({remediations.filter(r => r.conf >= bayesThreshold).length} auto-eligible)
          </span>
        </div>
      </div>

      {/* Kanban board */}
      <div className="flex-1 overflow-x-auto p-5">
        <div className="flex gap-4 h-full min-w-[900px]">
          {columns.map(col => (
            <div key={col.key} className="flex-1 flex flex-col min-w-[220px]">
              <div className={`flex items-center gap-2 pb-3 border-b-2 ${col.color} mb-3`}>
                <div className={`w-2 h-2 rounded-full ${col.bg}`} />
                <span className="text-xs font-semibold uppercase tracking-wider">{col.label}</span>
                <span className="ml-auto text-xs text-[var(--color-text-muted)] tabular-nums">{grouped[col.key].length}</span>
              </div>
              <div className="space-y-3 flex-1 overflow-y-auto">
                {grouped[col.key].map(r => (
                  <motion.div key={r.id} layout onClick={() => setSelectedRem(selectedRem === r.id ? null : r.id)}
                    className={`bg-[var(--color-bg-card)] border rounded-xl p-3.5 cursor-pointer transition-all hover:border-[var(--color-text-muted)] ${
                      r.sev === 'critical' ? 'border-red-500/20' : 'border-[var(--color-border)]'
                    }`}>
                    <div className="flex items-start justify-between mb-2">
                      <SeverityBadge severity={r.sev} />
                      {r.conf >= bayesThreshold && (
                        <span className="text-[9px] bg-emerald-500/15 text-emerald-400 px-1.5 py-0.5 rounded font-medium">AUTO</span>
                      )}
                    </div>
                    <h4 className="text-sm font-medium mb-1">{r.title}</h4>
                    <p className="text-xs font-mono text-[var(--color-text-muted)] mb-2">{r.resource}</p>
                    
                    {/* Risk delta */}
                    <div className="flex items-center gap-2 text-xs mb-2">
                      <span className="text-red-400 tabular-nums">{r.rBefore}</span>
                      <ArrowRight size={10} className="text-[var(--color-text-muted)]" />
                      <span className="text-emerald-400 tabular-nums">{r.rAfter}</span>
                      <span className="text-[var(--color-text-muted)]">risk</span>
                    </div>

                    {/* Verification checks */}
                    <div className="flex items-center gap-2 text-[10px]">
                      <span className={r.checks.gen ? 'text-emerald-400' : 'text-red-400'}>{r.checks.gen ? '✓' : '✗'} Policy</span>
                      <span className={r.checks.dpdp ? 'text-emerald-400' : 'text-red-400'}>{r.checks.dpdp ? '✓' : '✗'} DPDP</span>
                      <span className={r.checks.risk ? 'text-emerald-400' : 'text-red-400'}>{r.checks.risk ? '✓' : '✗'} Risk↓</span>
                    </div>

                    {/* DPDP rules satisfied */}
                    {r.dpdp.length > 0 && (
                      <div className="flex gap-1.5 mt-2">
                        {r.dpdp.map(d => (
                          <span key={d} className="text-[9px] bg-cyan-500/15 text-cyan-400 px-1.5 py-0.5 rounded font-mono">{d}</span>
                        ))}
                      </div>
                    )}

                    {/* Expanded diff */}
                    <AnimatePresence>
                      {selectedRem === r.id && (
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                          className="mt-3 pt-3 border-t border-[var(--color-border)] overflow-hidden">
                          <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-2">Infrastructure Diff</div>
                          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                            <div className="bg-red-500/5 rounded-lg p-2 border border-red-500/10">
                              <div className="text-[9px] text-red-400 mb-1">BEFORE</div>
                              <pre className="text-red-300/80 whitespace-pre-wrap text-[10px] leading-relaxed">{r.before}</pre>
                            </div>
                            <div className="bg-emerald-500/5 rounded-lg p-2 border border-emerald-500/10">
                              <div className="text-[9px] text-emerald-400 mb-1">AFTER</div>
                              <pre className="text-emerald-300/80 whitespace-pre-wrap text-[10px] leading-relaxed">{r.after}</pre>
                            </div>
                          </div>
                          <p className="text-xs text-[var(--color-text-secondary)] mt-2 leading-relaxed">{r.explanation}</p>
                          {r.status === 'verified' && (
                            <button className="mt-3 w-full bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold py-2 rounded-lg transition-colors flex items-center justify-center gap-2">
                              <Check size={14} /> Approve & Apply
                            </button>
                          )}
                        </motion.div>
                      )}
                    </AnimatePresence>
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
  return (
    <div className="p-6 overflow-y-auto h-full">
      <h2 className="text-lg font-semibold mb-6">System Configuration</h2>
      <div className="max-w-2xl space-y-6">
        {[
          { title: 'Cartography Ingestion', items: ['Source: AWS (IAM, EC2, S3, VPC, RDS, Lambda)', 'Schedule: Every 15 minutes', 'Last run: 2 min ago · 47 resources ingested', 'Graph store: Neo4j Community 5.x'] },
          { title: 'Risk Engine', items: ['Algorithm: Personalized PageRank (damping c=0.85)', 'Edge weights: CIS Benchmark severity heuristics', 'Entry nodes: Public-facing resources (EC2 with public IP)', 'GNN layer: Not enabled (Stretch goal)'] },
          { title: 'Stackelberg Game', items: ['Solver: PuLP (CBC backend)', 'Budget B: 3 remediations per cycle', 'Payoff source: PageRank risk scores', 'Solve time: <50ms'] },
          { title: 'Remediation Pipeline', items: ['LLM: Claude Sonnet (structured JSON output)', 'RAG context: CIS controls + DPDP rule text + fix templates', 'Output format: Terraform HCL patch (schema-validated)', 'Fallback: Structured escalation (never free-form)'] },
          { title: 'Verification Gate', items: ['Policy engine: Open Policy Agent + Rego', 'Libraries: Generic (CIS-style) + DPDP (Rule 6/7/8/15)', 'Risk regression: Full PageRank re-run on simulated graph', 'Bayes-cost threshold: Configurable (default 0.90)'] },
        ].map(section => (
          <div key={section.title} className="bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Settings size={14} className="text-[var(--color-text-muted)]" />
              {section.title}
            </h3>
            <div className="space-y-1.5">
              {section.items.map((item, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <Minus size={10} className="text-[var(--color-text-muted)] mt-1 flex-shrink-0" />
                  <span className="text-[var(--color-text-secondary)]">{item}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================
// CHAT PANEL
// ============================================================
function ChatPanel({ isOpen, onClose }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', text: 'I\'m ARGUS. Ask me about your security posture, DPDP compliance status, attack paths, or remediation priorities.' }
  ]);
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = (q) => {
    const question = q || input;
    if (!question.trim()) return;
    setMessages(prev => [...prev, { role: 'user', text: question }]);
    setInput('');
    setTyping(true);
    setTimeout(() => {
      setMessages(prev => [...prev, { role: 'assistant', text: getChatReply(question) }]);
      setTyping(false);
    }, 800 + Math.random() * 600);
  };

  if (!isOpen) return null;

  return (
    <motion.div initial={{ x: 400, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 400, opacity: 0 }}
      className="w-96 border-l border-[var(--color-border)] bg-[var(--color-bg-secondary)] flex flex-col h-full">
      {/* Header */}
      <div className="h-14 border-b border-[var(--color-border)] flex items-center justify-between px-4">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center">
            <Bot size={14} className="text-white" />
          </div>
          <span className="text-sm font-semibold">Ask ARGUS</span>
        </div>
        <button onClick={onClose} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"><X size={16} /></button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((m, i) => (
          <div key={i} className={`flex gap-2.5 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 ${
              m.role === 'user' ? 'bg-[var(--color-bg-elevated)]' : 'bg-gradient-to-br from-violet-500 to-purple-600'
            }`}>
              {m.role === 'user' ? <User size={12} /> : <Bot size={12} className="text-white" />}
            </div>
            <div className={`max-w-[280px] rounded-xl px-3.5 py-2.5 text-[13px] leading-relaxed ${
              m.role === 'user'
                ? 'bg-[var(--color-bg-elevated)] text-[var(--color-text-primary)]'
                : 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]'
            }`}>
              {m.text.split('\n').map((line, j) => {
                if (line.startsWith('**') && line.endsWith('**')) return <p key={j} className="font-semibold text-[var(--color-text-primary)]">{line.replace(/\*\*/g, '')}</p>;
                if (line.startsWith('• ')) return <p key={j} className="ml-2">• {line.slice(2)}</p>;
                if (line.startsWith('`') && line.endsWith('`')) return <code key={j} className="bg-[var(--color-bg-primary)] px-1.5 py-0.5 rounded text-xs font-mono">{line.replace(/`/g, '')}</code>;
                return <p key={j}>{line || '\u00A0'}</p>;
              })}
            </div>
          </div>
        ))}
        {typing && (
          <div className="flex gap-2.5">
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center flex-shrink-0">
              <Bot size={12} className="text-white" />
            </div>
            <div className="bg-[var(--color-bg-tertiary)] rounded-xl px-3.5 py-2.5">
              <div className="flex gap-1">
                {[0, 1, 2].map(i => (
                  <motion.div key={i} className="w-1.5 h-1.5 rounded-full bg-[var(--color-text-muted)]"
                    animate={{ opacity: [0.3, 1, 0.3] }} transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.2 }} />
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Suggestions */}
      <div className="px-4 pb-2">
        <div className="flex flex-wrap gap-1.5">
          {CHAT_SUGGESTIONS.slice(0, 3).map(s => (
            <button key={s} onClick={() => send(s)}
              className="text-[10px] bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-[var(--color-text-muted)] px-2 py-1 rounded-lg hover:text-[var(--color-text-secondary)] hover:border-[var(--color-text-muted)] transition-colors">
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Input */}
      <div className="p-3 border-t border-[var(--color-border)]">
        <div className="flex items-center gap-2 bg-[var(--color-bg-tertiary)] rounded-xl px-3 py-2 border border-[var(--color-border)] focus-within:border-[var(--color-text-muted)]">
          <input type="text" value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && send()}
            placeholder="Ask about your security posture..."
            className="flex-1 bg-transparent text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none" />
          <button onClick={() => send()} className="text-amber-400 hover:text-amber-300 transition-colors">
            <Send size={16} />
          </button>
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
    graph: AttackGraphPage,
    dpdp: DPDPCompliancePage,
    remediation: RemediationPage,
    settings: SettingsPage,
  };
  const PageComponent = pages[activePage] || OverviewPage;

  return (
    <div className="flex h-full w-full">
      <Sidebar active={activePage} onNav={setActivePage} collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar scenarioId={activeScenario} onScenarioChange={setActiveScenario} />
        <div className="flex-1 flex min-h-0">
          <div className="flex-1 min-w-0 overflow-hidden">
            <AnimatePresence mode="wait">
              <motion.div key={activePage + activeScenario}
                initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.2 }} className="h-full">
                <PageComponent />
              </motion.div>
            </AnimatePresence>
          </div>
          <AnimatePresence>
            {chatOpen && <ChatPanel isOpen={chatOpen} onClose={() => setChatOpen(false)} />}
          </AnimatePresence>
        </div>
      </div>

      {/* Chat FAB */}
      {!chatOpen && (
        <button onClick={() => setChatOpen(true)}
          className="fixed bottom-6 right-6 w-12 h-12 rounded-full bg-gradient-to-br from-violet-500 to-purple-600 text-white shadow-lg shadow-purple-500/25 flex items-center justify-center hover:shadow-purple-500/40 hover:scale-105 transition-all z-50">
          <MessageSquare size={20} />
        </button>
      )}
    </div>
  );
}

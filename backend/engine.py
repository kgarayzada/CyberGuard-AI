"""Transparent scoring and scanner-result normalization; no finding fixtures."""
import hashlib, re
from datetime import datetime, timezone

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
REMEDIATION = {
 'Credential Exposure': 'Remove the credential from source, rotate it if real, load it from environment configuration or a secret manager, and review repository history for copies.',
 'SQL Injection': 'Use parameterized queries instead of concatenating input into SQL. Validate input as defense in depth.',
 'Cross-Site Scripting': 'Use context-aware output escaping and safe template rendering. Avoid inserting untrusted input into HTML.',
 'Weak Cryptography': 'Use SHA-256 or stronger for integrity; use a dedicated password hashing algorithm for passwords. Review compatibility before replacing cryptographic primitives.',
 'Command Injection': 'Avoid shell command construction. Use fixed executables with explicit argument arrays and validate allowed input.',
 'Path Traversal': 'Resolve paths against an allowed directory, verify containment, and reject traversal or absolute input paths.',
 'Vulnerable Dependency': 'Upgrade to a non-vulnerable version using the advisory, review compatibility and changelog, then retest.'
}
def now(): return datetime.now(timezone.utc).isoformat()
def normalize(assessment, scanner, rule, title, severity, category, file_path=None, start_line=None, end_line=None, description=None, confidence=None, cwe=None, cve=None, package=None, vulnerable_version=None, fixed_version=None, references=None, remediation=None, **unused):
    severity = severity.upper() if severity and severity.upper() in SEVERITIES else 'UNKNOWN'
    factors = [{'label': severity.title() + ' scanner severity baseline', 'value': {'CRITICAL':75,'HIGH':60,'MEDIUM':35,'LOW':15,'UNKNOWN':25}[severity], 'source':'Scanner-derived'}]
    if confidence == 'HIGH': factors.append({'label':'High-confidence detection','value':5,'source':'Scanner-derived'})
    if category == 'Credential Exposure': factors.append({'label':'Secret-detection rule matched (validity not tested)','value':15,'source':'Scanner-derived'})
    if category == 'Vulnerable Dependency': factors.append({'label':'Known affected package version','value':5,'source':'Scanner-derived'})
    if assessment.get('environment') == 'Production': factors.append({'label':'Production environment','value':3,'source':'User-provided'})
    bonus = {'Low':0,'Medium':2,'High':5,'Critical':8}.get(assessment.get('criticality'), 0)
    if bonus: factors.append({'label':assessment['criticality']+' business criticality','value':bonus,'source':'User-provided'})
    fingerprint = hashlib.sha256('|'.join(str(x or '') for x in (scanner, rule, file_path, start_line, package, vulnerable_version)).encode()).hexdigest()
    # Deliberately do not retain source snippets, scanner match strings or secret values.
    return dict(id=assessment['id']+'-'+fingerprint[:16], assessment_id=assessment['id'],scanner=scanner,scanner_rule_id=rule,title=title[:500],description=(description or title)[:8000],severity=severity,category=category,confidence=confidence,cwe=cwe,cve=cve,package=package,vulnerable_version=vulnerable_version,fixed_version=fixed_version,file_path=file_path,start_line=start_line,end_line=end_line,evidence='[REDACTED: source text withheld to prevent credential disclosure]',remediation=remediation or REMEDIATION.get(category,'Review the scanner rule documentation, replace the unsafe operation with a safe API, and rescan the corrected code.'),references=[u for u in references or [] if isinstance(u,str) and re.match(r'^https://[^\s/@]+(?:/|$)',u)][:10],fingerprint=fingerprint,created_at=now(),status='OPEN',contextual_risk_score=min(100,sum(f['value'] for f in factors)),risk_factors=factors)

def security_score(findings):
    if not findings: return 100
    risks = [f['contextual_risk_score'] for f in findings]
    return max(0, min(100, round(100 - .65 * max(risks) - min(35, sum((r/100)**2*8 for r in risks)))))

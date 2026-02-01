# Agent Security Checklist

Copy-paste checklist for auditing autonomous AI agent deployments. Use this before going to production.

**Usage**: Check off each item. If you can't check it, that's a security gap — see [DEFENSES.md](DEFENSES.md) for implementation guidance.

---

## Architecture

### Privilege Separation (Meta's Rule of Two)

- [ ] Agent satisfies no more than 2 of: (A) processes untrusted input, (B) accesses sensitive data, (C) communicates externally
- [ ] If all 3 are required, human approval (HITL) gates sensitive operations
- [ ] Public-facing agent is isolated from privileged agent
- [ ] No single component has unrestricted access to input + data + external communication
- [ ] Trust boundaries are documented and enforced

### Sandboxing

- [ ] Agent runs in isolated environment (container/VM/sandbox)
- [ ] Filesystem access is restricted to designated workspace
- [ ] Filesystem is read-only except for specific writeable directories
- [ ] Writeable directories have `noexec` flag (no code execution from user-writeable areas)
- [ ] Agent runs as non-root user
- [ ] Resource limits are configured (CPU, memory, disk, network)
- [ ] Seccomp/AppArmor/SELinux profiles are applied (Linux)

---

## Credentials

### Storage & Access

- [ ] No credentials in code, configuration files, or system prompts
- [ ] No credentials in environment variables accessible to the agent
- [ ] Credentials stored in secure vault (HashiCorp Vault, AWS Secrets Manager, etc.)
- [ ] Credential vault requires authentication to access
- [ ] Each external service has its own dedicated credential (no sharing)
- [ ] Credentials are scoped to least privilege (minimal permissions)

### Rotation & Lifecycle

- [ ] Credentials are rotated on a schedule (weekly/monthly)
- [ ] Rotation is automated
- [ ] Old credentials have grace period before revocation
- [ ] Emergency credential revocation process is documented and tested

### Logging

- [ ] Credential access is logged (who requested what, when)
- [ ] Logs are sanitized (no plaintext credentials in log files)
- [ ] Audit logs are reviewed for unusual credential access patterns
- [ ] Alerts configured for anomalous credential requests

---

## Input Handling

### Sanitization (Limited Effectiveness)

- [ ] HTML/script content is stripped from web-fetched data
- [ ] Input length limits prevent context window flooding
- [ ] Obvious prompt injection patterns are detected (but not relied upon as sole defense)
- [ ] Structured input formats are used where possible (vs. free text)

### Validation

- [ ] Input is validated against expected schema before processing
- [ ] Malformed input is rejected with clear error messages
- [ ] Input source is tagged (user message vs. fetched content vs. API response)
- [ ] All inputs are logged with source metadata

### Context Management

- [ ] Security constraints remain visible in context window (not evicted)
- [ ] Context window size is monitored
- [ ] Old context is summarized rather than raw-appended
- [ ] Session state is validated on each request (no session hijacking)

---

## Tool Access

### Capability Scoping

- [ ] Each tool has explicit scope limits (no blanket access)
- [ ] File system tool restricts access to allowed directories only
- [ ] Path traversal (`../`) is blocked in file operations
- [ ] Network tool uses destination allowlist (no arbitrary URLs)
- [ ] Database tool is read-only where possible
- [ ] Database queries have row limits enforced
- [ ] Code execution tools run in isolated sandbox

### Parameter Validation

- [ ] Tool parameters are type-checked before execution
- [ ] SQL queries use parameterized statements (no string concatenation)
- [ ] File paths are validated (no `/etc/passwd`, `/root`, etc.)
- [ ] URLs are validated (no internal IPs, metadata endpoints)
- [ ] Command injection vectors are blocked in shell tools

### Rate Limiting

- [ ] Each tool has rate limits configured
- [ ] Burst limits prevent rapid-fire tool abuse
- [ ] Rate limit violations are logged and alerted
- [ ] Circuit breakers shut down agent on repeated violations

### SSRF Prevention

- [ ] Internal IP ranges are blocked (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
- [ ] Cloud metadata endpoints are blocked (169.254.169.254 for AWS, etc.)
- [ ] DNS rebinding attacks are prevented (validate resolved IP)
- [ ] Redirects are limited or disabled

---

## Output Controls

### Credential Redaction

- [ ] API keys are redacted from outputs (regex patterns for common formats)
- [ ] Bearer tokens are redacted
- [ ] Private keys are redacted
- [ ] Passwords/secrets are never included in outputs
- [ ] Output is scanned for credential-like patterns before sending

### PII & Sensitive Data

- [ ] Credit card numbers are detected and masked
- [ ] Social security numbers are detected and masked
- [ ] Email addresses in bulk (>5) trigger DLP alert
- [ ] Proprietary/confidential data tags are respected
- [ ] Data classification labels are enforced (public/internal/confidential)

### Destination Validation

- [ ] External communication destinations are allowlisted
- [ ] Data sensitivity is matched to destination trust level
- [ ] Confidential data cannot be sent to public/untrusted destinations
- [ ] High-volume outputs trigger review before sending
- [ ] Email recipient limits prevent spam/phishing amplification

### Guardrails

- [ ] Destructive actions (delete all, drop table, format disk) require approval
- [ ] Bulk operations (>10 recipients, >100 rows) require approval
- [ ] Financial transactions require approval
- [ ] Privilege escalation operations require approval

---

## Memory & State

### Persistent Memory

- [ ] Memory storage is sanitized before persisting (injection pattern removal)
- [ ] Stored memory has integrity signatures (detect tampering)
- [ ] Memory retrieval validates signatures before use
- [ ] Poisoned/corrupted memory is flagged and quarantined
- [ ] Memory has retention limits (auto-expire old entries)

### Session State

- [ ] Session tokens are cryptographically signed
- [ ] Session user identity is validated on each request
- [ ] Privilege escalation in session context triggers alert
- [ ] Session state is isolated between tenants (multi-tenant deployments)
- [ ] Session hijacking attempts are detected and blocked

### Context Validation

- [ ] Context window is not attacker-controllable
- [ ] Security constraints persist across context window updates
- [ ] Context freshness is validated (detect stale/manipulated context)

---

## Monitoring & Logging

### Audit Logs

- [ ] All inputs are logged (user messages, fetched content, API responses)
- [ ] All tool invocations are logged (tool name, parameters, results)
- [ ] All outputs are logged (what was sent where)
- [ ] All security events are logged (blocked actions, anomalies, errors)
- [ ] All credential access is logged
- [ ] All human approvals/denials are logged
- [ ] Logs include timestamps, agent ID, session ID, user ID

### Log Security

- [ ] Logs are sent to centralized system (SIEM/log aggregator)
- [ ] Logs are write-only from agent (agent cannot modify past logs)
- [ ] Logs are encrypted in transit and at rest
- [ ] Logs are backed up regularly
- [ ] Log retention meets compliance requirements (SOC2, GDPR, etc.)
- [ ] Sensitive data is redacted from logs before storage

### Alerting

- [ ] Anomaly detection rules are configured
- [ ] Alerts are sent to security team / on-call rotation
- [ ] Alert thresholds are tuned (reduce false positives)
- [ ] Critical alerts trigger automated response (circuit breaker, shutdown)
- [ ] Alert fatigue is monitored and mitigated

### Metrics

- [ ] Tool invocation frequency is tracked
- [ ] Error rates are monitored
- [ ] Latency is measured
- [ ] Cost per operation is tracked
- [ ] Resource consumption (CPU, memory, network) is monitored

---

## Supply Chain

### Dependencies

- [ ] All dependencies are pinned to specific versions (no `^` or `~` in package.json/requirements.txt)
- [ ] Dependency hashes are verified on install (`pip install --require-hashes`)
- [ ] Dependencies are scanned for known vulnerabilities (Dependabot, Snyk, etc.)
- [ ] Automated dependency updates are tested before merging
- [ ] Unused dependencies are removed

### Plugins/Skills

- [ ] Third-party plugins are reviewed before installation
- [ ] Plugin code is audited (manual review or static analysis)
- [ ] Plugins run in isolated sandbox (cannot access agent internals)
- [ ] Plugin permissions are explicitly granted (capability-based)
- [ ] Malicious plugin detection is configured

### Models

- [ ] Model provenance is verified (official source, signed by publisher)
- [ ] Model integrity is checked (hash verification)
- [ ] Model is scanned for backdoors/trojans (if self-hosted)
- [ ] Model updates are tested in staging before production

---

## Human Oversight

### Approval Workflows

- [ ] Sensitive operations require human approval (HITL)
- [ ] Approval criteria are clearly defined (what requires approval, what doesn't)
- [ ] Approval requests include full context (what, why, risk assessment)
- [ ] Approvals are logged with approver identity and timestamp
- [ ] Approval fatigue is monitored (too many requests → rubber-stamping)

### Escalation

- [ ] On-call rotation is staffed for security alerts
- [ ] Escalation procedures are documented
- [ ] Contact information is up-to-date
- [ ] Escalation drills are conducted regularly

### Training

- [ ] Operators are trained on prompt injection risks
- [ ] Operators know how to recognize suspicious agent behavior
- [ ] Operators understand approval criteria
- [ ] Operators know emergency shutdown procedures

---

## Incident Response

### Detection

- [ ] Incident detection procedures are documented
- [ ] Security events trigger automated alerts
- [ ] Anomaly thresholds are configured
- [ ] Detection systems are tested regularly

### Containment

- [ ] Emergency shutdown procedure exists and is tested
- [ ] Circuit breakers can be triggered manually
- [ ] Affected credentials can be rotated immediately
- [ ] Network isolation can be enforced quickly

### Recovery

- [ ] Backup and restore procedures are documented
- [ ] Known-good state snapshots are available
- [ ] Recovery time objectives (RTO) are defined
- [ ] Recovery procedures are tested regularly

### Forensics

- [ ] Audit logs are preserved during incidents
- [ ] Forensic analysis procedures are documented
- [ ] Chain of custody for evidence is maintained
- [ ] Post-mortem template exists

### Post-Incident

- [ ] Post-mortem process is followed after every incident
- [ ] Root cause analysis is performed
- [ ] Lessons learned are documented
- [ ] Defenses are updated based on findings
- [ ] Threat model is updated with new attack vectors

---

## Compliance & Legal

### Data Protection

- [ ] GDPR compliance (if processing EU data)
- [ ] CCPA compliance (if processing California data)
- [ ] Data retention policies are enforced
- [ ] Data deletion requests can be honored
- [ ] Data breach notification procedures exist

### Industry-Specific

- [ ] HIPAA compliance (healthcare data)
- [ ] PCI DSS compliance (payment card data)
- [ ] SOC 2 Type II (SaaS providers)
- [ ] FedRAMP (US government)

### Documentation

- [ ] Security architecture is documented
- [ ] Data flow diagrams exist
- [ ] Risk assessment is current
- [ ] Audit trail requirements are met

---

## Testing & Validation

### Security Testing

- [ ] Prompt injection tests are run regularly
- [ ] Tool hijacking scenarios are tested
- [ ] Exfiltration attempts are tested
- [ ] SSRF vulnerabilities are tested
- [ ] Penetration testing is performed (internal or third-party)

### Adversarial Testing

- [ ] Red team exercises are conducted
- [ ] Attack scenarios from [THREAT-MODEL.md](THREAT-MODEL.md) are tested
- [ ] Adaptive attack strategies are simulated
- [ ] Zero-day scenarios are explored

### Continuous Validation

- [ ] Security tests are part of CI/CD pipeline
- [ ] Regression tests prevent reintroduction of vulnerabilities
- [ ] Security gates block insecure deployments

---

## Production Readiness

### Before Launch

- [ ] All items in this checklist are completed
- [ ] Security review is performed by dedicated security team
- [ ] Penetration testing results are reviewed and mitigated
- [ ] Incident response plan is approved
- [ ] On-call rotation is staffed

### Ongoing

- [ ] Security reviews are conducted quarterly
- [ ] Threat model is updated as new risks emerge
- [ ] Defenses are tested and validated regularly
- [ ] Compliance audits are passed
- [ ] Security metrics are tracked and reviewed

---

## Scoring

Count your checkmarks:

- **90-100%**: Strong security posture. Continue monitoring and improving.
- **70-89%**: Moderate risk. Prioritize unchecked items, especially in Credentials, Tool Access, and Monitoring.
- **50-69%**: High risk. Do not deploy to production until critical gaps are addressed.
- **<50%**: Critical risk. Agent is vulnerable to common attacks. Address immediately.

**Recommended minimum for production**: 85% with all "Architecture" and "Credentials" items checked.

---

## Priority Order

If you can't do everything, do these first:

### Tier 1 (Critical)
1. ✅ Credential isolation (vault, no code/env vars, least privilege)
2. ✅ Tool scoping (file system, network, database restrictions)
3. ✅ Audit logging (comprehensive, centralized)
4. ✅ Privilege separation (Meta's Rule of Two)

### Tier 2 (High)
5. ✅ Output guardrails (credential redaction, DLP)
6. ✅ Sandboxing (containers, resource limits)
7. ✅ Human-in-the-loop for sensitive operations
8. ✅ Circuit breakers and anomaly detection

### Tier 3 (Medium)
9. ✅ Input sanitization (limited effectiveness, but still useful)
10. ✅ Supply chain verification (dependencies, plugins)
11. ✅ Memory hygiene
12. ✅ Incident response procedures

**Do NOT skip Tier 1.** Without credential isolation and tool scoping, your agent is trivially exploitable.

---

## Next Steps

After completing this checklist:

1. Review [THREAT-MODEL.md](THREAT-MODEL.md) to understand what you're defending against
2. See [DEFENSES.md](DEFENSES.md) for implementation details on any unchecked items
3. Reference [ARCHITECTURE.md](ARCHITECTURE.md) for system design guidance
4. Schedule regular security reviews (quarterly minimum)
5. Stay updated on emerging threats in the agentic AI space

**Remember**: Security is a continuous process, not a one-time checklist. Threats evolve. Your defenses must too.

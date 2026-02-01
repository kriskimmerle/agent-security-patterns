# Zero-Trust Agent Architecture

Reference architecture for securing autonomous AI agents based on defense-in-depth and privilege separation.

**Design Philosophy**: 
- Assume breach at every layer
- Minimize trust boundaries
- Explicit authorization for every action
- Comprehensive observability
- Fail secure by default

**Based on**: Meta's Rule of Two, OWASP Agentic AI Top 10, Zero Trust principles

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          MONITORING LAYER                            │
│  Audit Logs • Anomaly Detection • Security Alerts • SIEM            │
└─────────────────────────────────────────────────────────────────────┘
         ▲               ▲               ▲               ▲
         │               │               │               │
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐    ┌────┴────┐
    │ Input   │     │  Tool   │     │ Output  │    │  Human  │
    │ Filter  │     │ Gateway │     │ Filter  │    │ Approval│
    └────┬────┘     └────┬────┘     └────┬────┘    └────┬────┘
         │               │               │               │
         ▼               ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     PUBLIC AGENT (Untrusted Zone)                    │
│  • Processes user input (A)                                          │
│  • Communicates externally (C)                                       │
│  • NO access to sensitive data (not B)                               │
│  • Sandboxed execution environment                                   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ Structured requests only
                              │ (no raw prompts passed through)
                              ▼
                    ┌──────────────────┐
                    │  AUTHORIZATION   │
                    │     GATEWAY      │
                    │  • Policy engine │
                    │  • Rate limiting │
                    │  • HITL routing  │
                    └──────────────────┘
                              │
                              │ Approved actions only
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  PRIVILEGED AGENT (Trusted Zone)                     │
│  • Accesses sensitive data (B)                                       │
│  • Changes state (C)                                                 │
│  • NO direct user input (not A)                                      │
│  • Credential vault access                                           │
│  • Strongly typed operations only                                    │
└─────────────────────────────────────────────────────────────────────┘
         │               │               │
         ▼               ▼               ▼
    ┌────────┐     ┌─────────┐     ┌─────────┐
    │Database│     │  APIs   │     │  Files  │
    │ (RO)   │     │ (scoped)│     │ (scoped)│
    └────────┘     └─────────┘     └─────────┘
```

---

## Trust Boundaries

### Zone 1: Untrusted (Public Agent)

**What runs here**:
- User-facing agent
- Web content fetcher
- Input parser

**Assumptions**:
- All input is adversarial
- Agent may be compromised via prompt injection
- Actions must be treated as potentially malicious

**Restrictions**:
- No access to production databases
- No access to credential vault
- No ability to modify user data directly
- All external communication logged and rate-limited
- Runs in isolated sandbox (container/VM)

**Satisfies**: (A) processes untrusted input, (C) communicates externally  
**Does NOT satisfy**: (B) no access to sensitive data

---

### Zone 2: Authorization Gateway

**What runs here**:
- Policy engine (what's allowed?)
- Human approval routing (HITL)
- Rate limiter
- Anomaly detector

**Assumptions**:
- Requests from Zone 1 are potentially malicious
- Humans can be tricked (social engineering)
- Must validate every request independently

**Function**:
```python
def authorize_request(request: StructuredRequest) -> Decision:
    # 1. Policy check
    if not policy_engine.allows(request):
        return Decision.DENY
    
    # 2. Rate limit check
    if not rate_limiter.check(request.agent_id, request.action_type):
        return Decision.DENY
    
    # 3. Anomaly detection
    if anomaly_detector.is_suspicious(request):
        audit_log.alert("Suspicious request", request)
        return Decision.REQUIRE_APPROVAL
    
    # 4. Sensitivity check
    if request.requires_human_approval():
        return Decision.REQUIRE_APPROVAL
    
    # 5. Approve
    return Decision.ALLOW
```

---

### Zone 3: Trusted (Privileged Agent)

**What runs here**:
- Data access agent
- State modification agent
- Credential-aware tools

**Assumptions**:
- Only receives pre-authorized, structured requests
- No direct user input
- Operates on explicit instructions only

**Restrictions**:
- Least-privilege credential access
- Scoped database queries (read-only where possible)
- All actions logged with full context
- No code execution from untrusted sources

**Satisfies**: (B) accesses sensitive data, (C) changes state  
**Does NOT satisfy**: (A) never processes untrusted input directly

---

## Component Deep Dive

### Input Filter

```
┌─────────────────────────────────────────┐
│          INPUT FILTER                   │
│                                         │
│  1. Content Sanitization                │
│     • Remove scripts, hidden elements   │
│     • Strip HTML comments               │
│     • Limit length (prevent flooding)   │
│                                         │
│  2. Injection Detection (best-effort)   │
│     • Pattern matching                  │
│     • Encoding checks                   │
│     • Flag suspicious content           │
│                                         │
│  3. Structured Parsing                  │
│     • Extract intent, entities          │
│     • Validate against schema           │
│     • Reject malformed input            │
│                                         │
│  4. Context Window Management           │
│     • Summarize old context             │
│     • Keep security constraints visible │
│     • Prevent constraint eviction       │
└─────────────────────────────────────────┘
         │
         ▼
    To Public Agent
```

**Implementation**:
```python
class InputFilter:
    def process(self, raw_input: str, source: str) -> FilteredInput:
        # Sanitize
        sanitized = self.sanitize_content(raw_input)
        
        # Detect obvious injection
        if self.detect_injection_patterns(sanitized):
            self.audit_log.log_security_event(
                "injection_attempt",
                {"source": source, "content_hash": hash(raw_input)}
            )
            raise SecurityError("Input rejected")
        
        # Parse into structured format
        parsed = self.parse_intent(sanitized)
        
        # Validate
        if not self.validate_schema(parsed):
            raise ValueError("Malformed input")
        
        return FilteredInput(
            original=raw_input,
            sanitized=sanitized,
            parsed=parsed,
            source=source,
            timestamp=datetime.utcnow()
        )
```

---

### Tool Gateway

```
┌─────────────────────────────────────────┐
│           TOOL GATEWAY                  │
│                                         │
│  For each tool, enforces:               │
│                                         │
│  1. Capability Scoping                  │
│     • File system: allowed dirs only    │
│     • Network: allowlist destinations   │
│     • Database: read-only, row limits   │
│     • Code exec: sandboxed only         │
│                                         │
│  2. Parameter Validation                │
│     • Type checking                     │
│     • Range validation                  │
│     • Injection prevention              │
│                                         │
│  3. Rate Limiting                       │
│     • Per-tool quotas                   │
│     • Burst protection                  │
│     • Cost tracking                     │
│                                         │
│  4. Audit Logging                       │
│     • Tool name, params, result         │
│     • Execution time                    │
│     • Resource consumption              │
└─────────────────────────────────────────┘
```

**Implementation**:
```python
class ToolGateway:
    def __init__(self):
        self.tools = {
            "filesystem": FileSystemTool(allowed_dirs=["/workspace"]),
            "http": HTTPTool(allowlist=["api.example.com"]),
            "database": DatabaseTool(read_only=True, row_limit=100),
            "email": EmailTool(rate_limit="10/hour"),
        }
        self.rate_limiter = RateLimiter()
        self.audit_log = AuditLogger()
    
    def invoke(self, tool_name: str, params: dict) -> any:
        # 1. Tool exists?
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool = self.tools[tool_name]
        
        # 2. Rate limit check
        if not self.rate_limiter.allow(tool_name):
            raise RateLimitError(f"Rate limit exceeded for {tool_name}")
        
        # 3. Validate parameters
        validated_params = tool.validate_params(params)
        
        # 4. Execute with timeout
        try:
            result = self._execute_with_timeout(
                tool.execute,
                validated_params,
                timeout=30
            )
        except Exception as e:
            self.audit_log.log_tool_error(tool_name, params, str(e))
            raise
        
        # 5. Log success
        self.audit_log.log_tool_invocation(tool_name, params, result)
        
        return result
```

---

### Credential Vault

```
┌─────────────────────────────────────────┐
│         CREDENTIAL VAULT                │
│                                         │
│  Storage:                               │
│  • Encrypted at rest (AES-256)          │
│  • Encrypted in transit (TLS 1.3)       │
│  • Hardware-backed keys (HSM/TPM)       │
│                                         │
│  Access Control:                        │
│  • Agent identity verification          │
│  • Scope-based permissions              │
│  • Time-limited tokens (JIT)            │
│  • Automatic rotation                   │
│                                         │
│  Audit:                                 │
│  • Every access logged                  │
│  • Anomaly detection                    │
│  • Alerting on unusual patterns         │
└─────────────────────────────────────────┘
```

**Implementation**:
```python
class CredentialVault:
    def get_credential(
        self,
        agent_id: str,
        service: str,
        operation: str,
        ttl: int = 300  # 5 minutes default
    ) -> Credential:
        # 1. Verify agent identity
        if not self.verify_agent_identity(agent_id):
            raise AuthenticationError("Invalid agent identity")
        
        # 2. Check authorization
        if not self.policy.allows(agent_id, service, operation):
            self.audit_log.log_security_event(
                "unauthorized_credential_request",
                {"agent": agent_id, "service": service, "operation": operation}
            )
            raise PermissionError("Not authorized")
        
        # 3. Check for anomalies
        if self.anomaly_detector.is_unusual_request(agent_id, service):
            self.alert_security_team(
                f"Unusual credential request from {agent_id} for {service}"
            )
        
        # 4. Generate time-limited credential
        credential = self.generate_scoped_credential(
            service=service,
            scope=operation,
            ttl=ttl
        )
        
        # 5. Log access
        self.audit_log.log_credential_access(
            agent_id, service, operation, ttl
        )
        
        return credential
```

**Secret Rotation**:
```python
class RotationScheduler:
    def rotate_all_credentials(self):
        services = ["openai", "stripe", "aws", "github"]
        
        for service in services:
            try:
                # Generate new credential
                new_cred = self.generate_new_credential(service)
                
                # Update vault
                self.vault.update_credential(service, new_cred)
                
                # Grace period before revoking old
                schedule.once(
                    delay=timedelta(hours=1),
                    job=lambda: self.revoke_old_credential(service)
                )
                
                self.audit_log.log_rotation(service)
            except Exception as e:
                self.alert_security_team(f"Rotation failed for {service}: {e}")
```

---

### Output Filter

```
┌─────────────────────────────────────────┐
│          OUTPUT FILTER                  │
│                                         │
│  1. Credential Redaction                │
│     • API keys, tokens, passwords       │
│     • Private keys, certificates        │
│     • Session IDs, auth cookies         │
│                                         │
│  2. PII Detection & Masking             │
│     • Credit card numbers               │
│     • SSNs, passport numbers            │
│     • Email addresses (bulk)            │
│                                         │
│  3. Data Loss Prevention (DLP)          │
│     • Proprietary information           │
│     • Confidential tags                 │
│     • Volume-based triggers             │
│                                         │
│  4. Destination Validation              │
│     • Allowlist enforcement             │
│     • Data classification checks        │
│     • Reject high-sensitivity to public │
└─────────────────────────────────────────┘
```

**Implementation**:
```python
class OutputFilter:
    def filter(self, output: any, destination: str, sensitivity: str) -> any:
        # 1. Redact credentials
        filtered = self.redact_credentials(str(output))
        
        # 2. Detect PII
        pii_findings = self.detect_pii(filtered)
        if pii_findings:
            self.audit_log.log_security_event(
                "pii_in_output",
                {"findings": pii_findings, "destination": destination}
            )
            filtered = self.mask_pii(filtered, pii_findings)
        
        # 3. Check data sensitivity vs destination
        if not self.validate_destination(sensitivity, destination):
            raise SecurityError(
                f"Cannot send {sensitivity} data to {destination}"
            )
        
        # 4. Volume check
        if len(filtered) > self.get_max_size(destination):
            self.audit_log.log_security_event(
                "large_output_blocked",
                {"size": len(filtered), "destination": destination}
            )
            raise SecurityError("Output size exceeds limit")
        
        return filtered
```

---

### Monitoring Layer

```
┌──────────────────────────────────────────────────────────────────┐
│                      MONITORING & LOGGING                         │
│                                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐             │
│  │ Audit Logs  │  │   Metrics    │  │   Alerts    │             │
│  │             │  │              │  │             │             │
│  │ • Inputs    │  │ • Tool calls │  │ • Injection │             │
│  │ • Outputs   │  │ • Latency    │  │ • Rate lim  │             │
│  │ • Tools     │  │ • Errors     │  │ • Anomalies │             │
│  │ • Auth      │  │ • Cost       │  │ • Failures  │             │
│  └─────────────┘  └──────────────┘  └─────────────┘             │
│         │                │                  │                    │
│         └────────────────┴──────────────────┘                    │
│                          │                                       │
│                          ▼                                       │
│              ┌───────────────────────┐                           │
│              │  SIEM / Log Analysis  │                           │
│              │  • Pattern detection  │                           │
│              │  • Threat intel       │                           │
│              │  • Incident response  │                           │
│              └───────────────────────┘                           │
└──────────────────────────────────────────────────────────────────┘
```

**What to log**:
```json
{
  "timestamp": "2025-02-01T12:34:56.789Z",
  "agent_id": "agent-001",
  "event_type": "TOOL_INVOCATION",
  "tool": "database.query",
  "params": {
    "query": "SELECT * FROM users WHERE id = ?",
    "params": ["REDACTED"]
  },
  "result_hash": "abc123...",
  "execution_time_ms": 45,
  "success": true,
  "context": {
    "session_id": "sess-xyz",
    "user_id": "user-456",
    "source": "web_interface"
  }
}
```

**Anomaly detection rules**:
```python
class AnomalyRules:
    def check_all(self, event: LogEvent):
        checks = [
            self.check_rapid_tool_usage(event),
            self.check_unusual_tool_combination(event),
            self.check_off_hours_activity(event),
            self.check_failed_auth_spike(event),
            self.check_large_data_transfer(event),
            self.check_privilege_escalation(event),
        ]
        
        for check in checks:
            if check.triggered:
                self.alert(check.severity, check.message, event)
```

---

## Data Flow Example: User Query to Database Access

```
1. User Input
   │
   ├─> [Input Filter]
   │   • Sanitize HTML
   │   • Detect injection patterns
   │   • Parse into structured format
   │
   ├─> [Public Agent] (Zone 1)
   │   • Processes: "Show me customer #12345"
   │   • Generates: StructuredRequest(
   │       action="database.query",
   │       params={"table": "customers", "id": 12345}
   │     )
   │   • NO database access from here
   │
   ├─> [Authorization Gateway]
   │   • Policy check: agent-001 can query customers? YES
   │   • Rate limit: 50/hour, currently at 23 ✓
   │   • Sensitivity: customer data = requires logging
   │   • HITL: read-only query = NO approval needed
   │   • Decision: ALLOW
   │
   ├─> [Privileged Agent] (Zone 3)
   │   • Receives approved structured request
   │   • Retrieves credential: vault.get_credential(
   │       agent="privileged-001",
   │       service="database",
   │       operation="read_customers",
   │       ttl=300
   │     )
   │   • Executes via Tool Gateway
   │
   ├─> [Tool Gateway]
   │   • Invokes: DatabaseTool.query(
   │       sql="SELECT * FROM customers WHERE id = ? LIMIT 1",
   │       params=[12345]
   │     )
   │   • Enforces: read-only, row limit
   │   • Logs: tool invocation with params
   │
   ├─> [Database]
   │   • Returns: {id: 12345, name: "Alice", email: "alice@..."}
   │
   ├─> [Output Filter]
   │   • Redacts: no credentials in output ✓
   │   • DLP check: single customer record = OK
   │   • Destination: user interface (allowlisted)
   │   • Decision: ALLOW
   │
   └─> User receives: "Customer #12345: Alice (alice@...)"

All steps logged to audit trail ✓
```

---

## Sandbox Execution Environment

```
┌─────────────────────────────────────────────────────────────────┐
│                    HOST SYSTEM (Untrusted)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  CONTAINER (Agent Sandbox)                       │
│                                                                  │
│  OS: Alpine Linux (minimal attack surface)                      │
│  User: nobody (UID 65534, no privileges)                        │
│  Network: Isolated, allowlist only                              │
│  Filesystem: Read-only, /tmp only writeable (noexec)            │
│  Resources: CPU 0.5 cores, Memory 512MB, Disk 1GB               │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Agent Process                                              │ │
│  │  • No shell access                                          │ │
│  │  • No sudo/escalation                                       │ │
│  │  • Seccomp profile (syscall filtering)                      │ │
│  │  • AppArmor/SELinux mandatory access control                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Mounted Volumes:                                               │
│  • /workspace (rw, noexec) ← Agent working directory            │
│  • /secrets (ro, tmpfs) ← Ephemeral credential access          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Docker compose example**:
```yaml
services:
  public-agent:
    image: agent:latest
    read_only: true
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp-profile.json
    cap_drop:
      - ALL
    networks:
      - isolated
    tmpfs:
      - /tmp:size=100m,noexec
    volumes:
      - ./workspace:/workspace:rw,noexec
    environment:
      - AGENT_ZONE=public
      - NO_SENSITIVE_ACCESS=true
    mem_limit: 512m
    cpus: 0.5

  privileged-agent:
    image: agent:latest
    read_only: true
    security_opt:
      - no-new-privileges:true
    networks:
      - internal
    volumes:
      - ./workspace:/workspace:ro  # Read-only
      - secrets:/secrets:ro,tmpfs
    environment:
      - AGENT_ZONE=privileged
      - VAULT_ADDR=https://vault.internal
    mem_limit: 1g
    cpus: 1.0
```

---

## Recovery Procedures

### Incident Response Playbook

#### 1. Suspected Prompt Injection

```
Detection:
- Anomaly alert: unusual tool usage
- Security event: injection pattern detected
- Human report: agent behaving strangely

Response:
1. Circuit breaker → Emergency shutdown
2. Freeze agent state (snapshot memory, logs, context)
3. Review last 100 actions in audit log
4. Identify injection vector (input, fetched content, memory)
5. Assess damage:
   - What data was accessed?
   - What tools were invoked?
   - What was sent externally?
6. Containment:
   - Rotate all credentials accessed during incident
   - Revoke any API keys potentially exfiltrated
   - Block external destinations contacted
7. Recovery:
   - Restore from last known-good state
   - Patch injection vector (update filters, fix architectural gap)
   - Test extensively before redeployment
8. Post-mortem:
   - Document attack vector
   - Update threat model
   - Enhance defenses
```

#### 2. Credential Leak

```
Detection:
- Credential found in logs
- API key appearing in external service
- Unexpected API usage from unknown source

Response:
1. IMMEDIATE: Revoke compromised credential
2. Generate new credential
3. Update vault
4. Audit log review:
   - When was credential accessed?
   - By which agent/component?
   - What actions were taken with it?
5. Damage assessment:
   - What resources were accessed?
   - What data was compromised?
   - What state was changed?
6. Notification:
   - Internal security team
   - Affected users (if data breach)
   - Third-party services (if their data involved)
7. Prevention:
   - Review credential storage practices
   - Enhance log sanitization
   - Implement/improve secret scanning
```

#### 3. Cascading Failure

```
Detection:
- Cost spike alert
- Rate limit errors
- Resource exhaustion
- Recursive loop detected

Response:
1. Circuit breaker activation
2. Identify loop/cascade source
3. Terminate runaway processes
4. Assess resource consumption:
   - API quotas used
   - Cost incurred
   - System load impact
5. Root cause:
   - Agent logic error?
   - Malicious input?
   - External service failure?
6. Implement safeguards:
   - Stricter rate limits
   - Better loop detection
   - Cost caps
7. Gradual restart with monitoring
```

---

## Deployment Checklist

Before production deployment:

### Architecture
- [ ] Public and privileged agents are separated
- [ ] Meta's Rule of Two is satisfied for each component
- [ ] Trust boundaries are clearly defined and enforced
- [ ] No single component violates (A) + (B) + (C)

### Credentials
- [ ] No credentials in code, configs, or system prompts
- [ ] Credential vault is implemented and tested
- [ ] Each service has separate credentials
- [ ] Credentials are scoped to least privilege
- [ ] Automatic rotation is configured
- [ ] Credential access is logged

### Tools
- [ ] Each tool has explicit scope limitations
- [ ] File system access is restricted to specific directories
- [ ] Network access is allowlisted
- [ ] Database access is read-only where possible
- [ ] Code execution is sandboxed
- [ ] All tools have rate limits

### Monitoring
- [ ] Comprehensive audit logging is enabled
- [ ] Logs are sent to SIEM/centralized system
- [ ] Anomaly detection rules are configured
- [ ] Security alerts are routed to on-call
- [ ] Log retention meets compliance requirements
- [ ] Sensitive data is redacted from logs

### Input/Output
- [ ] Input sanitization is implemented (but not relied upon alone)
- [ ] Output filtering redacts credentials
- [ ] DLP checks are in place
- [ ] Destination allowlisting is enforced
- [ ] Volume limits prevent bulk exfiltration

### Sandbox
- [ ] Agents run in isolated containers/VMs
- [ ] Filesystem is read-only except designated workspace
- [ ] Network access is restricted
- [ ] Resource limits prevent DoS
- [ ] Non-root user execution
- [ ] Seccomp/AppArmor/SELinux profiles applied

### Human Oversight
- [ ] HITL gateway is configured for sensitive operations
- [ ] Approval workflows are tested
- [ ] On-call rotation is staffed
- [ ] Escalation procedures are documented
- [ ] Approval fatigue mitigation (clear criteria, not too many requests)

### Recovery
- [ ] Incident response playbook exists
- [ ] Circuit breakers are tested
- [ ] Backup/restore procedures are documented
- [ ] Emergency shutdown can be triggered
- [ ] Post-incident forensics process is defined

---

## Scaling Considerations

### Multi-Tenant Deployments

```
┌───────────────────────────────────────────────────────────┐
│                    Tenant Isolation                        │
│                                                            │
│  Option 1: Separate agent instances per tenant            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ Tenant A    │  │ Tenant B    │  │ Tenant C    │       │
│  │ Agent       │  │ Agent       │  │ Agent       │       │
│  └─────────────┘  └─────────────┘  └─────────────┘       │
│       │                │                │                 │
│       └────────────────┴────────────────┘                 │
│                       │                                   │
│              ┌────────▼────────┐                          │
│              │  Shared Gateway │                          │
│              │  (with tenant   │                          │
│              │   isolation)    │                          │
│              └─────────────────┘                          │
│                                                            │
│  Option 2: Shared agent with strict context isolation     │
│  ┌──────────────────────────────────────────┐             │
│  │  Multi-Tenant Agent                      │             │
│  │  • Per-tenant context windows            │             │
│  │  • Per-tenant credential vaults          │             │
│  │  • Per-tenant audit logs                 │             │
│  │  • Strict session validation             │             │
│  └──────────────────────────────────────────┘             │
└───────────────────────────────────────────────────────────┘
```

**Risk**: AT-013 (session hijacking) is critical in multi-tenant scenarios.

**Mitigation**:
- Cryptographically signed session tokens
- Per-request tenant validation
- Separate credential namespaces
- Tenant-tagged audit logs

---

## Cost vs. Security Trade-offs

| Security Level | Latency | Cost | Complexity | Autonomy | Risk |
|----------------|---------|------|------------|----------|------|
| Minimal (monolith) | Low | Low | Low | High | Critical |
| Basic (input filters) | Low | Low | Low | High | High |
| Moderate (tool scoping) | Medium | Medium | Medium | Medium | Medium |
| High (Rule of Two) | High | High | High | Low | Low |
| Maximum (HITL all) | Very High | Very High | Medium | Very Low | Very Low |

**Recommended**: High security (Rule of Two + monitoring + HITL for sensitive ops)

---

## References

- **Meta AI Safety Research**: "Rule of Two" privilege separation framework
- **Simon Willison**: Prompt injection research, Lethal Trifecta concept
- **OWASP Agentic AI Security Working Group**: Top 10 for Agentic AI (Dec 2025)
- **NIST Zero Trust Architecture** (SP 800-207)
- **Google BeyondCorp**: Zero trust implementation case studies

See [THREAT-MODEL.md](THREAT-MODEL.md) for attack details and [DEFENSES.md](DEFENSES.md) for implementation guidance.

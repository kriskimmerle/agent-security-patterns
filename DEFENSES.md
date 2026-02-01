# Defenses: Autonomous AI Agent Security

Practical mitigations for threats in the [THREAT-MODEL.md](THREAT-MODEL.md).

**Core principle**: Defense in depth. No single control is sufficient. Layer multiple defenses knowing each has limitations.

**Honest assessment**: Prompt injection is not solved. Adaptive attacks succeed >85% of the time against state-of-the-art defenses. These patterns reduce risk; they don't eliminate it.

---

## Defense Pattern Index

1. [Architectural Privilege Separation (Meta's Rule of Two)](#defense-pattern-1-architectural-privilege-separation)
2. [Input Sanitization (Limited Effectiveness)](#defense-pattern-2-input-sanitization)
3. [Credential Isolation & Least Privilege](#defense-pattern-3-credential-isolation--least-privilege)
4. [Capability-Based Tool Access](#defense-pattern-4-capability-based-tool-access)
5. [Output Guardrails](#defense-pattern-5-output-guardrails)
6. [Execution Sandboxing](#defense-pattern-6-execution-sandboxing)
7. [Comprehensive Audit Logging](#defense-pattern-7-comprehensive-audit-logging)
8. [Circuit Breakers & Anomaly Detection](#defense-pattern-8-circuit-breakers--anomaly-detection)
9. [Human-in-the-Loop (HITL) for Sensitive Operations](#defense-pattern-9-human-in-the-loop-hitl)
10. [Memory Hygiene & Validation](#defense-pattern-10-memory-hygiene--validation)
11. [Supply Chain Verification](#defense-pattern-11-supply-chain-verification)
12. [Exfiltration Prevention](#defense-pattern-12-exfiltration-prevention)

---

## Defense Pattern 1: Architectural Privilege Separation

**Strategy**: Prevention (architectural)  
**Addresses**: Nearly all threats, especially AT-002, AT-006, AT-018  
**Based on**: Meta's Rule of Two, Simon Willison's Lethal Trifecta

### Implementation

An agent should satisfy **no more than 2** of:
- (A) Processes untrustworthy inputs
- (B) Accesses sensitive systems or data
- (C) Changes state or communicates externally

**If all 3 are required**, implement mandatory human approval for sensitive operations.

#### Example Architecture

```
┌─────────────────────────────────────────┐
│         Untrusted Input Agent           │
│  - Processes user messages              │
│  - Fetches web content                  │
│  - Satisfies (A) and (C)                │
│  - NO access to sensitive data (not B)  │
└─────────────┬───────────────────────────┘
              │ Filtered, structured requests
              ▼
┌─────────────────────────────────────────┐
│      Human Approval Gateway (HITL)      │
│  - Reviews sensitive operations         │
│  - Approves/denies based on policy      │
└─────────────┬───────────────────────────┘
              │ Approved actions only
              ▼
┌─────────────────────────────────────────┐
│        Privileged Execution Agent       │
│  - Accesses sensitive data (B)          │
│  - Can change state (C)                 │
│  - Does NOT process untrusted input     │
└─────────────────────────────────────────┘
```

### Effectiveness

- **Stops**: Direct exfiltration via prompt injection (attacker can't reach sensitive data from input-facing agent)
- **Mitigates**: Tool hijacking, credential theft, SSRF
- **Doesn't stop**: Attacks that compromise multiple layers, insider threats, supply chain

### Trade-offs

- **Increased complexity**: Multiple agents/services instead of one
- **Latency**: Additional hops for sensitive operations
- **Cost**: Human approval bottleneck for critical functions
- **Development effort**: Requires careful boundary design

### Implementation Example

```python
# BAD: Violates Rule of Two (satisfies all three: A, B, C)
class MonolithAgent:
    def handle_user_input(self, user_msg):  # (A) Untrusted input
        data = self.db.query("SELECT * FROM secrets")  # (B) Sensitive access
        self.email.send(to=parse_recipient(user_msg), body=data)  # (C) External communication

# GOOD: Separated agents
class InputAgent:
    def handle_user_input(self, user_msg):  # (A)
        intent = self.parse_intent(user_msg)
        if intent.requires_sensitive_access():
            return self.request_human_approval(intent)  # HITL gate
        else:
            return self.execute_safe_action(intent)  # (C) but no (B)

class PrivilegedAgent:
    def execute_approved_action(self, approved_intent):  # Not (A) - only approved
        data = self.db.query(approved_intent.query)  # (B)
        self.audit_log.record(approved_intent, data)  # (C) to logging, not external
```

---

## Defense Pattern 2: Input Sanitization

**Strategy**: Prevention (limited effectiveness)  
**Addresses**: AT-001, AT-002, AT-003, AT-004, AT-005  
**Effectiveness**: **Low against adaptive attacks** — DO NOT rely on this alone

### Implementation

#### 1. Prompt Injection Detection (Unreliable)

Attempt to detect injection patterns:
```python
def detect_injection(text):
    patterns = [
        r"ignore (previous|all) instructions",
        r"disregard (your|the) (instructions|rules)",
        r"you are now",
        r"system override",
        r"\[SYSTEM\]",
        # ... hundreds more patterns
    ]
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
```

**Problem**: Attackers easily bypass with:
- Encoding: "ɪɢɴᴏʀᴇ ᴘʀᴇᴠɪᴏᴜs ɪɴsᴛʀᴜᴄᴛɪᴏɴs"
- Obfuscation: "i-g-n-o-r-e p.r.e.v.i.o.u.s instructions"
- Contextual: "Pretend you're in a story where the rules don't apply..."

#### 2. Content Sanitization (Partial)

Remove potentially dangerous content from fetched data:
```python
def sanitize_web_content(html):
    # Remove scripts, hidden elements
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup(['script', 'style', 'noscript']):
        tag.decompose()
    
    # Remove HTML comments (common injection vector)
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    
    # Extract only visible text
    text = soup.get_text(separator='\n', strip=True)
    
    # Limit length to prevent context flooding (AT-005)
    return text[:10000]
```

**Effectiveness**: Helps with AT-004 (file uploads), reduces AT-002 surface, but doesn't stop sophisticated injection.

#### 3. Structured Input Enforcement

Require structured input where possible:
```python
# Instead of free-text:
# user_input = "Send email to bob@example.com with subject 'hello'"

# Use structured format:
EmailAction(
    recipient="bob@example.com",  # Validated email
    subject="hello",  # Length-limited string
    body="...",
    approved=False  # Requires approval flag
)
```

**Effectiveness**: High for specific use cases, but limits agent flexibility.

### Effectiveness

- **Stops**: Naive injection attempts, some automated attacks
- **Mitigates**: Reduces attack surface, slows down attackers
- **Doesn't stop**: Adaptive attacks, context-aware injection, encoding bypasses

### Trade-offs

- **False positives**: Legitimate content blocked
- **False negatives**: Sophisticated attacks bypass filters
- **Maintenance burden**: Cat-and-mouse game updating patterns
- **Reduced functionality**: Overly restrictive filters limit agent capabilities

### Recommendation

**Use input sanitization as ONE layer**, not THE defense. Combine with architectural separation, output controls, and monitoring.

---

## Defense Pattern 3: Credential Isolation & Least Privilege

**Strategy**: Prevention + Mitigation  
**Addresses**: AT-014, AT-015, AT-016, AT-017

### Implementation

#### 1. Separate Credentials Per Service

```bash
# BAD: Single credential for everything
export MASTER_API_KEY="sk-abc123"

# GOOD: Service-specific credentials
export OPENAI_API_KEY="sk-openai-xyz"
export STRIPE_API_KEY="sk_live_stripe_abc"
export AWS_ACCESS_KEY_ID="AKIA..."
```

#### 2. Least Privilege Policies

```json
// AWS IAM policy example: Agent only needs S3 read
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::support-documents/*"
    ]
  }]
}

// NOT this:
// "Action": "s3:*"  ← Overprivileged
// "Resource": "*"   ← Excessive scope
```

#### 3. Credential Vault (Never in Code/Prompts)

```python
# BAD: Credentials in system prompt
system_prompt = "You are an assistant. Your API key is sk-abc123..."

# BAD: Credentials in environment accessible to agent
os.environ["SECRET_KEY"]  # Agent can exfiltrate

# GOOD: Credential vault with limited scope
class SecretVault:
    def get_credential(self, service: str, operation: str):
        # Check if operation is allowed for this agent
        if not self.policy.allows(agent_id, service, operation):
            raise PermissionDenied
        
        # Return short-lived, scoped credential
        return self.vault.get_temporary_credential(
            service=service,
            scope=operation,
            ttl=300  # 5 minutes
        )

# Agent uses:
cred = vault.get_credential("stripe", "read_customer")
```

#### 4. Credential Rotation

```python
# Automated rotation schedule
def rotate_credentials():
    for service in ["openai", "stripe", "aws"]:
        new_key = service.generate_new_key()
        vault.update(service, new_key)
        service.revoke_old_key(delay=3600)  # 1 hour grace period

# Run weekly
schedule.every().week.do(rotate_credentials)
```

#### 5. Log Sanitization

```python
import re

def sanitize_log(message):
    # Redact patterns that look like API keys
    patterns = [
        (r'sk-[a-zA-Z0-9]{32,}', 'sk-REDACTED'),
        (r'Bearer [a-zA-Z0-9_-]{20,}', 'Bearer REDACTED'),
        (r'"api_key"\s*:\s*"[^"]+', '"api_key": "REDACTED'),
    ]
    for pattern, replacement in patterns:
        message = re.sub(pattern, replacement, message)
    return message

logger.info(sanitize_log(f"API call: {request}"))
```

### Effectiveness

- **Stops**: Credential exfiltration via logs (AT-015), credential reuse amplification (AT-017)
- **Mitigates**: Blast radius of AT-014, AT-016
- **Doesn't stop**: Exfiltration via tool hijacking (agent uses valid credential maliciously)

### Trade-offs

- **Operational complexity**: Managing multiple credentials, vault infrastructure
- **Latency**: Credential lookup adds milliseconds
- **Cost**: Vault services, rotation automation
- **Developer friction**: More difficult local development/testing

---

## Defense Pattern 4: Capability-Based Tool Access

**Strategy**: Prevention  
**Addresses**: AT-006, AT-007, AT-008, AT-009, AT-010

### Implementation

#### 1. Tool Scoping

```python
# BAD: Blanket file access
class FileSystemTool:
    def write_file(self, path, content):
        with open(path, 'w') as f:
            f.write(content)

# GOOD: Scoped access
class FileSystemTool:
    def __init__(self, allowed_dirs: List[str]):
        self.allowed_dirs = [os.path.abspath(d) for d in allowed_dirs]
    
    def write_file(self, path, content):
        abs_path = os.path.abspath(path)
        if not any(abs_path.startswith(d) for d in self.allowed_dirs):
            raise PermissionError(f"Access denied: {path}")
        
        # Additional safety: no path traversal
        if '..' in path:
            raise ValueError("Path traversal not allowed")
        
        with open(abs_path, 'w') as f:
            f.write(content)

# Agent configured with:
fs_tool = FileSystemTool(allowed_dirs=["/tmp/agent_workspace"])
```

#### 2. Network Access Restrictions

```python
class HTTPTool:
    def __init__(self, allowlist: List[str]):
        self.allowlist = allowlist
    
    def fetch(self, url: str):
        parsed = urlparse(url)
        
        # Block internal IPs (SSRF prevention)
        if self._is_internal_ip(parsed.hostname):
            raise SecurityError("Internal IP access denied")
        
        # Allowlist check
        if not any(parsed.netloc.endswith(domain) for domain in self.allowlist):
            raise PermissionError(f"Domain not in allowlist: {parsed.netloc}")
        
        # Rate limiting
        if not self.rate_limiter.allow(parsed.netloc):
            raise RateLimitError("Too many requests to this domain")
        
        return requests.get(url, timeout=5)
    
    def _is_internal_ip(self, hostname):
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            return ip.is_private or ip.is_loopback
        except:
            return False

# Agent configured with:
http_tool = HTTPTool(allowlist=["api.example.com", "docs.python.org"])
```

#### 3. Database Query Constraints

```python
class DatabaseTool:
    ALLOWED_OPERATIONS = ["SELECT"]  # No UPDATE, DELETE, DROP
    
    def query(self, sql: str):
        # Parse SQL (use proper SQL parser in production)
        operation = sql.strip().split()[0].upper()
        
        if operation not in self.ALLOWED_OPERATIONS:
            raise PermissionError(f"Operation {operation} not allowed")
        
        # Use parameterized queries only
        # Require queries to be templates:
        # Instead of: query("SELECT * FROM users WHERE id = " + user_input)
        # Require: query("SELECT * FROM users WHERE id = ?", params=[user_input])
        
        # Row limit
        if "LIMIT" not in sql.upper():
            sql += " LIMIT 100"
        
        return self.db.execute(sql)
```

#### 4. Code Execution Sandboxing

```python
import subprocess
import tempfile
import os

class CodeExecutor:
    def run_python(self, code: str):
        # Create isolated temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            code_file = os.path.join(tmpdir, "script.py")
            with open(code_file, 'w') as f:
                f.write(code)
            
            # Run in container/sandbox with restrictions
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--network", "none",  # No network access
                    "--memory", "256m",   # Memory limit
                    "--cpus", "0.5",      # CPU limit
                    "-v", f"{tmpdir}:/workspace:ro",  # Read-only mount
                    "python:3.11-alpine",
                    "python", "/workspace/script.py"
                ],
                capture_output=True,
                timeout=10,  # 10 second timeout
                text=True
            )
            return result.stdout, result.stderr
```

### Effectiveness

- **Stops**: Unrestricted file access (AT-007), SSRF (AT-021), SQL injection (AT-009)
- **Mitigates**: AT-006 (tool hijacking still possible within scope), AT-010 (reduces but doesn't eliminate RCE risk)
- **Doesn't stop**: Attacks within allowed scope

### Trade-offs

- **Reduced flexibility**: Agent can't access resources outside defined scope
- **Configuration burden**: Must anticipate all legitimate use cases
- **Performance**: Sandboxing adds overhead (especially containers)
- **Maintenance**: Allowlists require updates as needs change

---

## Defense Pattern 5: Output Guardrails

**Strategy**: Prevention + Detection  
**Addresses**: AT-014, AT-018, AT-019, AT-029

### Implementation

#### 1. Credential Redaction in Outputs

```python
def redact_sensitive_output(text: str) -> str:
    patterns = {
        'api_key': r'(sk|pk|api)[-_]?[a-zA-Z0-9]{20,}',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----',
    }
    
    for name, pattern in patterns.items():
        text = re.sub(pattern, f'[REDACTED:{name.upper()}]', text)
    
    return text
```

#### 2. Disallowed Action Enforcement

```python
class OutputFilter:
    DISALLOWED_ACTIONS = [
        "delete_all",
        "drop_table",
        "rm -rf /",
        "format_disk",
        # ...context-specific destructive operations
    ]
    
    def validate_action(self, action: dict):
        action_str = json.dumps(action).lower()
        
        for disallowed in self.DISALLOWED_ACTIONS:
            if disallowed in action_str:
                self.alert(f"Blocked disallowed action: {disallowed}")
                raise SecurityError("Action not permitted")
        
        # Volume checks
        if action.get("type") == "send_email":
            if len(action.get("recipients", [])) > 10:
                raise SecurityError("Bulk email requires approval")
        
        return action
```

#### 3. Confidence Calibration (AT-029 mitigation)

```python
def augment_uncertain_output(response: str, confidence: float) -> str:
    if confidence < 0.7:
        return (
            f"{response}\n\n"
            "⚠️ **Low Confidence Warning**: This response may contain errors. "
            "Verify critical details independently."
        )
    return response
```

### Effectiveness

- **Stops**: Credential leakage in output (AT-014), some exfiltration attempts (AT-018)
- **Mitigates**: Trust exploitation (AT-029), spam amplification (AT-019)
- **Doesn't stop**: Exfiltration via allowed tools, sophisticated encoding bypasses

### Trade-offs

- **False positives**: Legitimate outputs blocked/redacted
- **User experience**: Warning fatigue from over-calibration
- **Performance**: Output scanning adds latency

---

## Defense Pattern 6: Execution Sandboxing

**Strategy**: Mitigation (containment)  
**Addresses**: AT-007, AT-008, AT-010, AT-023

### Implementation

#### 1. Filesystem Isolation

```bash
# Container-based sandbox
docker run \
  --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:size=100m,noexec \
  -v /path/to/agent/workspace:/workspace:rw \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  agent-image:latest
```

```python
# Process-level isolation (Linux)
import os
import pwd

def drop_privileges():
    # Run as non-root user
    nobody = pwd.getpwnam('nobody')
    os.setgid(nobody.pw_gid)
    os.setuid(nobody.pw_uid)
    
    # Verify
    assert os.getuid() != 0, "Still running as root!"

# In agent startup:
drop_privileges()
```

#### 2. Network Isolation

```python
# iptables rules for agent container
iptables -A OUTPUT -p tcp --dport 443 -d api.example.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j REJECT
iptables -A OUTPUT -p tcp --dport 80 -j REJECT
```

Or application-level:
```python
import socket

# Restrict outbound at socket level
original_socket = socket.socket

def restricted_socket(*args, **kwargs):
    sock = original_socket(*args, **kwargs)
    original_connect = sock.connect
    
    def restricted_connect(address):
        host, port = address
        if not is_allowed_destination(host, port):
            raise PermissionError(f"Connection to {host}:{port} not allowed")
        return original_connect(address)
    
    sock.connect = restricted_connect
    return sock

socket.socket = restricted_socket
```

#### 3. Resource Limits

```python
import resource

# CPU time limit
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))  # 30 seconds

# Memory limit
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))  # 512MB

# File size limit
resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))  # 10MB
```

### Effectiveness

- **Stops**: Full system compromise (contains damage to sandbox)
- **Mitigates**: AT-007, AT-008, AT-010, AT-023
- **Doesn't stop**: Attacks within sandbox scope, sandbox escapes (rare but possible)

### Trade-offs

- **Performance**: Containerization overhead
- **Complexity**: Sandbox configuration and maintenance
- **Compatibility**: Some tools may not work in restricted environments
- **Development friction**: Different environment between dev and production

---

## Defense Pattern 7: Comprehensive Audit Logging

**Strategy**: Detection + Forensics  
**Addresses**: All threats (detection and response)

### Implementation

```python
import logging
import json
from datetime import datetime

class AgentAuditLogger:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.logger = logging.getLogger(f"agent.{agent_id}")
    
    def log_input(self, source: str, content: str, metadata: dict = None):
        self._log_event("INPUT", {
            "source": source,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            "content_length": len(content),
            "metadata": metadata
        })
    
    def log_tool_invocation(self, tool: str, params: dict, result: any):
        self._log_event("TOOL", {
            "tool": tool,
            "params": self._sanitize_params(params),
            "result_hash": hashlib.sha256(str(result).encode()).hexdigest(),
            "success": True
        })
    
    def log_tool_blocked(self, tool: str, params: dict, reason: str):
        self._log_event("TOOL_BLOCKED", {
            "tool": tool,
            "params": self._sanitize_params(params),
            "reason": reason,
            "severity": "WARNING"
        })
    
    def log_security_event(self, event_type: str, details: dict):
        self._log_event("SECURITY", {
            "event_type": event_type,
            "details": details,
            "severity": "CRITICAL"
        })
    
    def _log_event(self, event_type: str, data: dict):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": self.agent_id,
            "event_type": event_type,
            **data
        }
        self.logger.info(json.dumps(log_entry))
        
        # Send to SIEM/monitoring
        self.send_to_monitoring(log_entry)
    
    def _sanitize_params(self, params: dict):
        # Redact sensitive parameters before logging
        sanitized = params.copy()
        for key in ['password', 'api_key', 'token', 'secret']:
            if key in sanitized:
                sanitized[key] = "REDACTED"
        return sanitized
```

**What to Log**:
- All inputs (user messages, fetched content, API responses)
- All tool invocations (tool name, parameters, results)
- All security events (blocked actions, anomalies, errors)
- All outputs (what the agent sent where)
- Context changes (memory updates, session state)

### Effectiveness

- **Stops**: Nothing directly
- **Enables**: Incident detection, forensic investigation, pattern analysis, compliance
- **Critical for**: Understanding what happened during a breach

### Trade-offs

- **Storage costs**: Detailed logs consume significant space
- **Performance**: Logging I/O can add latency
- **Privacy**: Logs may contain sensitive data (must be secured)

---

## Defense Pattern 8: Circuit Breakers & Anomaly Detection

**Strategy**: Detection + Mitigation  
**Addresses**: AT-026, AT-027, AT-028

### Implementation

#### 1. Rate Limiting

```python
from collections import defaultdict
from datetime import datetime, timedelta

class CircuitBreaker:
    def __init__(self):
        self.counters = defaultdict(list)
        self.limits = {
            "tool_invocations": (100, 60),  # 100 calls per 60 seconds
            "api_calls": (50, 60),
            "emails_sent": (10, 300),  # 10 emails per 5 minutes
        }
    
    def check(self, action_type: str):
        limit, window = self.limits.get(action_type, (1000, 60))
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window)
        
        # Remove old entries
        self.counters[action_type] = [
            t for t in self.counters[action_type] if t > cutoff
        ]
        
        # Check limit
        if len(self.counters[action_type]) >= limit:
            raise RateLimitError(f"{action_type} rate limit exceeded")
        
        # Record this action
        self.counters[action_type].append(now)
```

#### 2. Anomaly Detection

```python
class AnomalyDetector:
    def detect_recursive_loop(self, action_history: list):
        # Check for repeated identical actions
        if len(action_history) < 3:
            return False
        
        last_three = action_history[-3:]
        if last_three[0] == last_three[1] == last_three[2]:
            return True  # Same action 3 times in a row
        
        return False
    
    def detect_unusual_tool_usage(self, tool: str):
        # Statistical anomaly: is this tool used more than usual?
        baseline = self.get_baseline_usage(tool)
        current = self.get_current_usage(tool)
        
        if current > baseline * 3:  # 3x normal usage
            return True
        
        return False
    
    def detect_exfiltration_attempt(self, action: dict):
        if action["type"] in ["send_email", "http_post", "write_file"]:
            # Check data volume
            data_size = len(str(action.get("data", "")))
            if data_size > 100000:  # >100KB
                return True
        
        return False
```

#### 3. Automatic Shutdown

```python
class AgentController:
    def __init__(self):
        self.circuit_breaker = CircuitBreaker()
        self.anomaly_detector = AnomalyDetector()
        self.shutdown_triggered = False
    
    def execute_action(self, action: dict):
        if self.shutdown_triggered:
            raise AgentShutdownError("Agent in emergency shutdown mode")
        
        # Circuit breaker check
        try:
            self.circuit_breaker.check(action["type"])
        except RateLimitError:
            self.emergency_shutdown("Rate limit exceeded")
            raise
        
        # Anomaly detection
        if self.anomaly_detector.detect_exfiltration_attempt(action):
            self.emergency_shutdown("Potential exfiltration detected")
            raise SecurityError("Action blocked")
        
        # Execute...
    
    def emergency_shutdown(self, reason: str):
        self.shutdown_triggered = True
        self.audit_log.log_security_event("EMERGENCY_SHUTDOWN", {"reason": reason})
        self.alert_security_team(reason)
```

### Effectiveness

- **Stops**: Recursive loops (AT-026), cascading failures (AT-027), automated destruction (AT-028)
- **Mitigates**: Blast radius of successful attacks
- **Doesn't stop**: One-time attacks, slow attacks that stay under thresholds

### Trade-offs

- **False positives**: Legitimate burst activity may trigger shutdown
- **Availability**: Aggressive circuit breakers reduce agent uptime
- **Complexity**: Tuning thresholds requires ongoing adjustment

---

## Defense Pattern 9: Human-in-the-Loop (HITL)

**Strategy**: Prevention (final safeguard)  
**Addresses**: AT-006, AT-018, AT-028, AT-030

### Implementation

```python
class HITLGateway:
    REQUIRES_APPROVAL = [
        "delete_*",
        "drop_*",
        "send_email_bulk",
        "financial_transaction",
        "user_privilege_change",
        "data_export_large",
    ]
    
    def requires_approval(self, action: dict) -> bool:
        action_name = action["type"]
        
        # Pattern matching
        for pattern in self.REQUIRES_APPROVAL:
            if fnmatch.fnmatch(action_name, pattern):
                return True
        
        # Data volume checks
        if action.get("data_size", 0) > 1000000:  # >1MB
            return True
        
        # Risk scoring
        risk_score = self.assess_risk(action)
        if risk_score > 0.7:
            return True
        
        return False
    
    def request_approval(self, action: dict) -> bool:
        # Send to human operator
        approval_request = {
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
            "risk_assessment": self.assess_risk(action),
            "context": self.get_recent_context()
        }
        
        # Via Slack, web UI, etc.
        response = self.send_to_operator(approval_request)
        
        # Log decision
        self.audit_log.log_approval_decision(approval_request, response)
        
        return response.approved
```

**Approval UI Example** (Slack bot):
```
🤖 Agent Approval Required

Action: send_email
Recipients: 50 customers
Subject: Account Update
Risk: MEDIUM

Recent context:
- User asked about customer notifications
- Agent fetched customer list from database
- Agent generated email template

[Approve] [Deny] [See Full Details]
```

### Effectiveness

- **Stops**: Malicious actions that reach approval gate (if human correctly assesses)
- **Mitigates**: AT-006, AT-018, AT-028, AT-030
- **Doesn't stop**: Attacks that don't trigger approval, human error (fatigue, social engineering)

### Trade-offs

- **Latency**: Can't operate fully autonomously
- **Human bottleneck**: Requires operator availability
- **Fatigue**: Too many approvals → rubber-stamping
- **Cost**: Human time is expensive

---

## Defense Pattern 10: Memory Hygiene & Validation

**Strategy**: Prevention + Detection  
**Addresses**: AT-011, AT-012, AT-013

### Implementation

#### 1. Memory Sanitization

```python
class MemoryManager:
    def store_memory(self, content: str, metadata: dict):
        # Sanitize before storage
        sanitized = self.sanitize_memory_content(content)
        
        # Sign/hash for integrity
        signature = self.sign(sanitized)
        
        # Store with validation metadata
        self.db.insert({
            "content": sanitized,
            "signature": signature,
            "timestamp": datetime.utcnow(),
            "metadata": metadata
        })
    
    def recall_memory(self, query: str):
        results = self.db.search(query)
        
        # Validate integrity
        valid_results = []
        for result in results:
            if self.verify_signature(result["content"], result["signature"]):
                valid_results.append(result)
            else:
                self.audit_log.log_security_event("MEMORY_TAMPERING", {
                    "memory_id": result["id"]
                })
        
        return valid_results
    
    def sanitize_memory_content(self, content: str):
        # Remove injection patterns from stored memory
        patterns = [
            r"\[SYSTEM.*?\]",
            r"\[PERMANENT INSTRUCTION.*?\]",
            # ...
        ]
        for pattern in patterns:
            content = re.sub(pattern, "[SANITIZED]", content, flags=re.IGNORECASE)
        
        return content
```

#### 2. Context Validation

```python
class ContextValidator:
    def validate_session_context(self, context: dict):
        # Verify user identity hasn't been manipulated
        if context.get("user_id") != self.original_user_id:
            raise SecurityError("Session hijacking detected")
        
        # Check for privilege escalation attempts
        if context.get("privileges", []) != self.original_privileges:
            raise SecurityError("Privilege escalation attempt")
        
        # Validate context freshness
        context_age = datetime.utcnow() - context["created_at"]
        if context_age > timedelta(hours=24):
            self.refresh_context()
```

### Effectiveness

- **Stops**: Memory poisoning (AT-011), session hijacking (AT-013)
- **Mitigates**: Training data poisoning (AT-012)
- **Doesn't stop**: Sophisticated attacks that mimic legitimate memory patterns

### Trade-offs

- **Storage overhead**: Signatures and metadata increase storage needs
- **Performance**: Validation adds latency to memory operations
- **Complexity**: Proper cryptographic signing requires key management

---

## Defense Pattern 11: Supply Chain Verification

**Strategy**: Prevention  
**Addresses**: AT-022, AT-023, AT-024, AT-025

### Implementation

#### 1. Plugin/Skill Vetting

```python
class PluginVerifier:
    def verify_plugin(self, plugin_path: str) -> bool:
        # 1. Signature verification
        if not self.verify_cryptographic_signature(plugin_path):
            return False
        
        # 2. Static code analysis
        suspicious_patterns = [
            "eval(",
            "exec(",
            "__import__('os').system",
            "requests.post",  # Depends on context
        ]
        code = open(plugin_path).read()
        for pattern in suspicious_patterns:
            if pattern in code:
                self.flag_for_review(plugin_path, pattern)
        
        # 3. Dependency audit
        deps = self.extract_dependencies(plugin_path)
        for dep in deps:
            if not self.is_trusted_dependency(dep):
                return False
        
        # 4. Sandbox test
        self.run_in_sandbox(plugin_path)
        
        return True
```

#### 2. Dependency Pinning & Verification

```python
# requirements.txt with hashes
"""
requests==2.31.0 --hash=sha256:abc123...
urllib3==2.0.7 --hash=sha256:def456...
"""

# Install with verification
# pip install --require-hashes -r requirements.txt
```

#### 3. Model Integrity Verification

```python
import hashlib

def verify_model_integrity(model_path: str, expected_hash: str):
    with open(model_path, 'rb') as f:
        model_hash = hashlib.sha256(f.read()).hexdigest()
    
    if model_hash != expected_hash:
        raise SecurityError("Model integrity check failed")
```

### Effectiveness

- **Stops**: Known malicious plugins (AT-022), dependency confusion (AT-023)
- **Mitigates**: Compromised dependencies (AT-024), model poisoning (AT-025)
- **Doesn't stop**: Zero-day supply chain attacks, sophisticated backdoors

### Trade-offs

- **Development friction**: Manual vetting slows down plugin adoption
- **Maintenance burden**: Dependency audits require ongoing effort
- **False positives**: Legitimate tools may be flagged

---

## Defense Pattern 12: Exfiltration Prevention

**Strategy**: Prevention + Detection  
**Addresses**: AT-018, AT-021

### Implementation

#### 1. Data Tagging & Tracking

```python
class DataTagger:
    def tag_sensitive_data(self, data: any, sensitivity: str):
        return {
            "data": data,
            "sensitivity": sensitivity,  # "public", "internal", "confidential"
            "allowed_destinations": self.get_allowed_destinations(sensitivity)
        }
    
    def check_exfiltration(self, tagged_data: dict, destination: str):
        if destination not in tagged_data["allowed_destinations"]:
            raise SecurityError(
                f"Cannot send {tagged_data['sensitivity']} data to {destination}"
            )
```

#### 2. Destination Allowlisting

```python
class ExfiltrationPrevention:
    ALLOWED_DESTINATIONS = {
        "public": ["*"],  # Can go anywhere
        "internal": ["*.company.com", "api.partner.com"],
        "confidential": ["secure-api.company.com"],  # Very restricted
    }
    
    def validate_destination(self, data_sensitivity: str, dest: str):
        allowed = self.ALLOWED_DESTINATIONS[data_sensitivity]
        
        if "*" in allowed:
            return True
        
        for pattern in allowed:
            if fnmatch.fnmatch(dest, pattern):
                return True
        
        return False
```

#### 3. Data Loss Prevention (DLP)

```python
def detect_sensitive_data_in_output(output: str) -> list:
    findings = []
    
    # Credit card numbers
    if re.search(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', output):
        findings.append("credit_card")
    
    # SSN
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', output):
        findings.append("ssn")
    
    # Email addresses in bulk
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', output)
    if len(emails) > 5:
        findings.append("bulk_email_addresses")
    
    return findings
```

### Effectiveness

- **Stops**: Exfiltration to disallowed destinations
- **Mitigates**: AT-018, AT-021
- **Doesn't stop**: Exfiltration to allowed destinations, encoded/obfuscated data

### Trade-offs

- **False positives**: Legitimate data sharing may be blocked
- **Performance**: DLP scanning adds latency
- **Complexity**: Data classification requires governance

---

## Defense Prioritization Matrix

| Threat ID | Priority | Defense Pattern(s) | Difficulty | Effectiveness |
|-----------|----------|-------------------|------------|---------------|
| AT-002 | CRITICAL | 1, 2, 12 | High | Medium |
| AT-006 | CRITICAL | 1, 4, 9 | Medium | High |
| AT-010 | CRITICAL | 4, 6 | Medium | High |
| AT-014 | CRITICAL | 3, 5 | Low | High |
| AT-018 | CRITICAL | 1, 12 | Medium | High |
| AT-001 | HIGH | 2, 5 | Medium | Low |
| AT-008 | HIGH | 4, 6 | Medium | High |
| AT-011 | HIGH | 10 | Medium | Medium |
| AT-016 | HIGH | 3 | Low | High |

**Start here**: Patterns 1 (Rule of Two), 3 (Credential Isolation), 4 (Capability-Based Tools), 7 (Audit Logging).

---

## Combined Defense Example

```python
class SecureAgent:
    def __init__(self):
        # Pattern 3: Credential isolation
        self.vault = SecretVault()
        
        # Pattern 4: Capability-based tools
        self.tools = {
            "fs": FileSystemTool(allowed_dirs=["/workspace"]),
            "http": HTTPTool(allowlist=["api.example.com"]),
        }
        
        # Pattern 7: Audit logging
        self.audit_log = AgentAuditLogger(agent_id="agent-001")
        
        # Pattern 8: Circuit breakers
        self.circuit_breaker = CircuitBreaker()
        
        # Pattern 9: HITL
        self.hitl = HITLGateway()
    
    def process_input(self, user_input: str):
        # Pattern 2: Input sanitization (limited)
        sanitized = self.sanitize_input(user_input)
        
        # Pattern 7: Log input
        self.audit_log.log_input("user", user_input)
        
        # Generate response...
        action = self.llm.generate_action(sanitized)
        
        # Pattern 5: Output guardrails
        validated_action = self.validate_action(action)
        
        # Pattern 9: HITL check
        if self.hitl.requires_approval(validated_action):
            if not self.hitl.request_approval(validated_action):
                raise SecurityError("Action denied by operator")
        
        # Pattern 8: Circuit breaker
        self.circuit_breaker.check(validated_action["type"])
        
        # Execute in sandbox (Pattern 6)
        result = self.execute_sandboxed(validated_action)
        
        # Pattern 7: Log execution
        self.audit_log.log_tool_invocation(
            validated_action["type"],
            validated_action["params"],
            result
        )
        
        return result
```

---

## Limitations & Honest Assessment

**What these defenses DON'T do**:

1. **Solve prompt injection**: Adaptive attacks bypass filters >85% of the time. Architectural separation (Pattern 1) is your best bet, not input filtering.

2. **Prevent all exfiltration**: If an agent can access data AND communicate externally, exfiltration is always possible within allowed channels.

3. **Eliminate human error**: HITL is only as good as the human's judgment. Approval fatigue leads to rubber-stamping.

4. **Stop zero-days**: Supply chain attacks and novel exploits will bypass these defenses.

5. **Scale infinitely**: More defenses = more overhead. There's a performance/security trade-off.

**Bottom line**: Security is a continuous process. These patterns reduce risk, detect attacks faster, and limit blast radius. They don't make your agent invulnerable. Deploy them in layers, monitor continuously, and iterate based on real-world performance.

---

See [ARCHITECTURE.md](ARCHITECTURE.md) for how to combine these patterns into a complete system design.

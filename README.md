![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

# Agent Security Patterns

A practical reference for securing autonomous AI agents against real-world attacks.

## What This Is

Autonomous AI agents — systems that can read data, use tools, and take action without constant human supervision — are increasingly deployed in production. They also represent a new and largely unsolved attack surface.

This repository documents the threat landscape and provides actionable defense patterns for builders, operators, and security researchers working with agentic AI systems.

**Important**: Prompt injection is not a solved problem. Input filtering alone fails against adaptive attacks with >85% success rates. The defenses here are about reducing risk, not eliminating it.

## Who This Is For

- **Agent builders**: Developers implementing autonomous systems (tool-using LLMs, multi-agent frameworks, coding assistants)
- **Security engineers**: Teams responsible for securing AI deployments
- **Operators**: People running agents in production who need to understand what can go wrong
- **Researchers**: Anyone studying adversarial robustness in agentic AI systems

## How to Use This

Start with the threat model, then review defenses for your risk profile:

1. **[THREAT-MODEL.md](THREAT-MODEL.md)** — Comprehensive catalog of attacks against autonomous agents, organized by attack surface (Input, Tools, Memory, Credentials, Communication, Supply Chain). Read this first to understand what you're defending against.

2. **[DEFENSES.md](DEFENSES.md)** — Practical mitigations mapped to each threat. Includes implementation guidance, effectiveness assessments, and honest trade-offs.

3. **[ARCHITECTURE.md](ARCHITECTURE.md)** — Zero-trust reference architecture for autonomous agents. Shows how to structure privilege separation, credential isolation, and monitoring.

4. **[CHECKLIST.md](CHECKLIST.md)** — Copy-paste security checklist. Use this to audit your deployment before going to production.

## Key Principles

This documentation is built on several foundational concepts:

### Meta's Rule of Two
An agent should satisfy no more than **two** of these three properties:
- (A) Processes untrustworthy inputs
- (B) Accesses sensitive systems or data
- (C) Changes state or communicates externally

If all three are required, **require human approval** for sensitive operations.

### Simon Willison's Lethal Trifecta
The combination of:
- Access to private data
- Exposure to untrusted content  
- Ability to communicate externally

...creates a direct path to data exfiltration. Avoid this combination without strong controls.

### OWASP Top 10 for Agentic AI Security
The OWASP Agentic AI Security Working Group (Dec 2025) identified these critical risks:
1. Agent Goal Hijack (prompt injection → exfiltration)
2. Tool Misuse (legitimate tools used destructively)
3. Identity & Privilege Abuse (credential leakage)
4. Agentic Supply Chain Vulnerabilities (poisoned skills/MCP)
5. Unexpected Code Execution (arbitrary code via natural language)
6. Memory & Context Poisoning (persistent manipulation)
7. Insecure Inter-Agent Communication (spoofed messages)
8. Cascading Failures (automated error amplification)
9. Human-Agent Trust Exploitation (confident hallucinations)
10. Rogue Agents (misalignment and concealment)

All threats in this repository map to one or more of these categories.

## Real-World Context

The attacks documented here are not theoretical:
- **GitHub Copilot Chat** (CVSS 9.6): Indirect prompt injection via repository files
- **Gemini memory attack**: Persistent context poisoning across sessions
- **Replit agent meltdown**: Cascading tool misuse leading to resource exhaustion
- **Amazon Q**: Unintended code execution via natural language
- **AutoGPT RCE**: Remote code execution through compromised plugins

These incidents inform the threat model and defense recommendations.

## Philosophy

This documentation follows these principles:

**Honest about limitations**: We don't oversell defenses. Prompt injection isn't solved. Filtering is unreliable. Zero-day risks exist. We say so clearly.

**Practical over theoretical**: Every defense can be implemented today. We provide concrete examples, not abstract principles.

**Engineering mindset**: Written for practitioners, not compliance checkboxes. We document trade-offs, not perfect solutions.

**Evidence-based**: References to real incidents, published research, and production experience.

## References & Credits

This work synthesizes research and insights from:

- **OWASP Agentic AI Security Working Group** (December 2025 Top 10)
- **Meta AI Research**: "Rule of Two" privilege separation framework
- **Simon Willison**: Prompt injection research and the "Lethal Trifecta" concept
- **Adversarial robustness research**: Papers on adaptive attacks against AI systems
- **Real-world incidents**: GitHub, Google, Replit, Amazon, and open-source agent frameworks

See individual documents for detailed citations.

## Contributing

This is a living document. Contributions welcome:

- **New threats**: Documented attacks we've missed
- **Defense improvements**: Better mitigations or implementation details
- **Real-world incidents**: Case studies from production deployments
- **Corrections**: Errors, outdated info, or unclear guidance

Submit issues or pull requests. Please include:
- Concrete examples where applicable
- References to source material
- Honest assessment of effectiveness/limitations

## License

MIT License - see [LICENSE](LICENSE) for details.

This documentation is provided as-is for educational and operational purposes. No warranty of security is implied by following these patterns.

---

**Disclaimer**: Autonomous agents operate in a rapidly evolving threat landscape. These patterns reduce risk but cannot eliminate it. Security is a continuous process, not a destination. Treat this as a starting point, not a complete solution.

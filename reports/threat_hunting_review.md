# Threat Hunting Review

- Generated: 2026-10-17 09:25:31 UTC
- Source: https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/

## Pipeline Summary

1. Input
2. Safe Extraction
3. Evidence Normalization
4. Optional Enrichment
5. Analysis Engine
6. Report Generation
7. Human Review
8. Git Publish

## Extracted Evidence

- IPs: None detected
- Domains: None detected
- URLs: None detected
- Hashes: 1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d, 7489a0f93c67fa5cdaeb4b921d90594d, 79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186, ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec
- Files: None detected
- Processes: PowerShell
- Timestamps: None detected

## Optional Enrichment

- Status: Skipped
- Details: Set VT_API_KEY to enable reputation enrichment.

## ATT&CK Mapping

- Credential Access, Execution, Privilege Escalation, Defense Evasion, Collection, Exfiltration

## Human Review Checklist

- Validate all claims and indicators against host telemetry.
- Check whether the source is trusted and whether the content is complete.
- Confirm whether evidence requires additional source correlation.
- Review privacy and data-handling constraints before publishing.

## Source Preview

The raw page text has been sanitized to remove embedded script and style noise before analysis.

```text
Threat Brief: NetScaler Zero Days CVE-2026-88771 and CVE-2026-88772 Exploited in the Wild (Updated September 30) Menu Tools ATOMs Security Consulting About Us Under Attack? English English Japanese Threat Research Center High Profile Threats Vulnerabilities Vulnerabilities Threat Brief: NetScaler Zero Days CVE-2026-88771 and CVE-2026-88772 Exploited in the Wild (Updated September 30) 9 min read Related Products Advanced DNS Security Advanced IP Defense Advanced Threat Prevention Advanced URL Filtering Cloud-Delivered Security Services Cortex Cortex Xpanse Next-Generation Firewall Unit 42 Incident Response By: Unit 42 Published: September 30, 2026 Categories: High Profile Threats Vulnerabilities Tags: Citrix CVE-2026-88771 CVE-2026-88772 Denial of service Remote Code Execution Zero-day Share Executive Summary Unit 42 is aware of possible zero-day activity against NetScaler devices. In a Citrix report that details several CVEs , they noted that CVE-2026-88771 and CVE-2026-88772 have been exploited in the wild. The threat actors exploited these vulnerabilities to deliver web shells and establish their initial access and persistence into organizations. Analysis is ongoing to determine any post-compromise activity. 27, 2026, Palo Alto Networks Cortex Xpanse has identified 50,277 exposed instances that could potentially be vulnerable to these CVEs based on our telemetry.
```
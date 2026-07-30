/* ==========================================================================
   ai-data.js — dummy data for the AI Security Assistant module
   (app/ai-dashboard.html, chat.html, incident-summary.html,
   recommendations.html, risk-analysis.html)
   ========================================================================== */

   const SUGGESTED_QUESTIONS = [
    "Summarize today's critical alerts",
    "Which assets have the highest risk score?",
    "What's driving our false positive rate?",
    "Show me open incidents assigned to me",
    "Explain the latest ransomware detection",
    "What should we patch first this week?",
  ];
  
  const AI_CONVERSATIONS_DATA = [
    {
      id: "CONV-01", title: "Critical alert triage — July 24", updatedAt: "2026-07-24T09:40:00Z",
      messages: [
        { role: "user", text: "Summarize today's critical alerts", ts: "2026-07-24T09:38:00Z" },
        { role: "assistant", text: "There are 2 critical alerts open today: a suspected ransomware encryption pattern on FIN-WK-014, and an outbound connection to a known C2 IP blocked on WEB-PROD-03. Both are assigned to Aria Reyes and currently in the 'investigating' stage. Would you like remediation recommendations for either?", ts: "2026-07-24T09:38:20Z" },
      ],
    },
    {
      id: "CONV-02", title: "Patch prioritization discussion", updatedAt: "2026-07-23T15:12:00Z",
      messages: [
        { role: "user", text: "What should we patch first this week?", ts: "2026-07-23T15:10:00Z" },
        { role: "assistant", text: "Based on CVSS score and exposure, prioritize CVE-2026-7618 (Apache path traversal, CVSS 9.8) affecting 4 hosts including AD-DC-01, and CVE-2026-4021 (privilege escalation) on internet-facing web tier assets. Both have public exploit activity reported this month.", ts: "2026-07-23T15:10:25Z" },
      ],
    },
    {
      id: "CONV-03", title: "False positive tuning", updatedAt: "2026-07-21T11:05:00Z",
      messages: [
        { role: "user", text: "What's driving our false positive rate?", ts: "2026-07-21T11:03:00Z" },
        { role: "assistant", text: "The largest contributor is the 'Port scan detected from internal host' rule, with a 32% false positive rate — mostly triggered by scheduled vulnerability scans from SIEM-COLLECT-01. Consider adding a scanner exclusion or tuning the threshold.", ts: "2026-07-21T11:03:18Z" },
      ],
    },
  ];
  
  const CANNED_RESPONSES = [
    { match: ["critical alert", "critical alerts"], text: "There are 2 critical alerts open today: a suspected ransomware encryption pattern on FIN-WK-014, and an outbound connection to a known C2 IP blocked on WEB-PROD-03. Both are assigned to Aria Reyes and currently in the 'investigating' stage." },
    { match: ["risk score", "highest risk"], text: "FIN-WK-014, AD-DC-01, and BACKUP-SRV-01 currently carry the highest composite risk scores, driven by a mix of open critical vulnerabilities and recent detection activity. I'd recommend prioritizing FIN-WK-014 given its ransomware-adjacent findings this week." },
    { match: ["false positive"], text: "The largest contributor is the 'Port scan detected from internal host' rule, with a 32% false positive rate — mostly triggered by scheduled vulnerability scans. Tuning the source exclusion list should reduce noise significantly." },
    { match: ["open incidents", "assigned to me"], text: "You currently have 3 open incidents assigned: a phishing campaign investigation, an account compromise case, and a cloud misconfiguration review. The phishing case is nearing its SLA deadline." },
    { match: ["ransomware"], text: "The latest ransomware detection triggered on FIN-WK-014 based on mass file encryption patterns matching known ransomware behavior. The host has been isolated automatically per the active response playbook, and forensic evidence collection is in progress." },
    { match: ["patch", "vulnerabilit"], text: "Prioritize CVE-2026-7618 (Apache path traversal, CVSS 9.8, 4 affected hosts) and CVE-2026-4021 (privilege escalation on internet-facing assets). Both have public exploit activity reported this month." },
  ];
  const DEFAULT_RESPONSE = "I don't have enough context from the current dataset to answer that precisely, but I can help you look into alerts, incidents, vulnerabilities, or risk scores — try asking about one of those directly.";
  
  const AI_INSIGHTS_DATA = [
    { id: "INS-01", type: "warning", title: "Ransomware pattern isolated on FIN-WK-014", text: "Auto-isolation triggered based on mass encryption behavior. Evidence collection in progress.", confidence: 92, ts: "2026-07-24T09:12:00Z" },
    { id: "INS-02", type: "info", title: "Detection coverage gap identified", text: "Cloud Misconfiguration category has the lowest active-rule coverage relative to observed incident volume.", confidence: 78, ts: "2026-07-24T07:40:00Z" },
    { id: "INS-03", type: "success", title: "False positive rate trending down", text: "Overall FP rate improved 6 points after last week's rule tuning pass.", confidence: 85, ts: "2026-07-23T18:05:00Z" },
    { id: "INS-04", type: "warning", title: "Unusual after-hours access pattern", text: "A privileged account signed in outside normal hours from a new geolocation. Flagged for analyst review.", confidence: 71, ts: "2026-07-23T02:20:00Z" },
  ];
  
  const RECOMMENDATIONS_DATA = [
    { id: "REC-01", title: "Patch CVE-2026-7618 on affected hosts", category: "Vulnerability Management", priority: "critical", impact: "High", status: "new", description: "Apache HTTP Server path traversal vulnerability affects 4 hosts including a domain controller. Public exploit activity has been reported.", generatedAt: "2026-07-24T08:00:00Z" },
    { id: "REC-02", title: "Tune port scan detection rule for scanner traffic", category: "Detection Engineering", priority: "medium", impact: "Medium", status: "new", description: "32% false positive rate on internal port scan rule traced to scheduled vulnerability scans from SIEM-COLLECT-01.", generatedAt: "2026-07-23T11:00:00Z" },
    { id: "REC-03", title: "Enable MFA enforcement for all admin accounts", category: "Identity Security", priority: "high", impact: "High", status: "in_progress", description: "3 administrative accounts do not currently have MFA enforced, increasing account compromise risk.", generatedAt: "2026-07-22T14:20:00Z" },
    { id: "REC-04", title: "Expand detection coverage for cloud misconfiguration", category: "Detection Engineering", priority: "medium", impact: "Medium", status: "new", description: "Recent incidents in this category outpace current active rule coverage relative to other categories.", generatedAt: "2026-07-21T09:15:00Z" },
    { id: "REC-05", title: "Rotate credentials for exposed service account", category: "Incident Response", priority: "high", impact: "High", status: "applied", description: "Service account credentials were found in a historical exposed configuration file and have since been rotated.", generatedAt: "2026-07-18T10:00:00Z" },
    { id: "REC-06", title: "Review firewall rules on VPN gateway segment", category: "Network Security", priority: "low", impact: "Low", status: "dismissed", description: "Minor rule redundancy identified; no material risk change expected.", generatedAt: "2026-07-16T09:30:00Z" },
  ];
  
  const RISK_FACTORS_DATA = [
    { name: "Open Critical Vulnerabilities", score: 82, trend: "up", description: "16 critical vulnerabilities remain unpatched across monitored assets." },
    { name: "Detection Coverage Gaps", score: 46, trend: "down", description: "Most MITRE categories have adequate active rule coverage; cloud misconfiguration lags." },
    { name: "Identity & Access Exposure", score: 58, trend: "flat", description: "A subset of administrative accounts lack MFA enforcement." },
    { name: "Incident Response Readiness", score: 30, trend: "down", description: "Average resolution time has improved and playbook coverage is strong." },
    { name: "Third-Party / Supply Chain", score: 64, trend: "up", description: "Recent campaign activity has targeted vendor portal credentials." },
  ];
  
  const RISK_TREND_14D = [58,60,59,62,63,61,64,66,65,67,69,68,70,71];
  
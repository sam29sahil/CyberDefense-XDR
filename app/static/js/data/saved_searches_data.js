/* ==========================================================================
   saved-searches-data.js — dummy saved-search definitions for the SIEM
   module (app/saved-searches.html, app/log-explorer.html).
   ========================================================================== */

   const SAVED_SEARCHES_DATA = [
    {
      id: "SRCH-01", name: "Critical alerts — last 24h",
      query: 'sev:critical AND ts:[now-24h TO now]',
      owner: "Aria Reyes", scope: "Team", pinned: true,
      alerting: true, lastRun: "2 min ago", hits: 6,
      description: "All critical-severity events across every source in the last 24 hours."
    },
    {
      id: "SRCH-02", name: "Failed admin logins",
      query: 'message:"login" AND result:failure AND user:admin*',
      owner: "Marcus Lee", scope: "Team", pinned: true,
      alerting: true, lastRun: "14 min ago", hits: 23,
      description: "Failed authentication attempts against administrative accounts."
    },
    {
      id: "SRCH-03", name: "PowerShell encoded commands",
      query: 'source:"CrowdStrike EDR" AND message:"PowerShell" AND message:"encoded"',
      owner: "Priya Nair", scope: "Private", pinned: false,
      alerting: true, lastRun: "1h ago", hits: 4,
      description: "Suspicious obfuscated PowerShell execution across endpoints."
    },
    {
      id: "SRCH-04", name: "Outbound to new external domains",
      query: 'category:Network AND action:alert AND tags:external',
      owner: "Aria Reyes", scope: "Team", pinned: false,
      alerting: false, lastRun: "3h ago", hits: 41,
      description: "Traffic flagged toward domains not previously seen on the network."
    },
    {
      id: "SRCH-05", name: "AWS CloudTrail — IAM changes",
      query: 'source:"AWS CloudTrail" AND eventName:(CreateUser OR AssumeRole OR DeleteBucket)',
      owner: "J. Chen", scope: "Team", pinned: false,
      alerting: false, lastRun: "6h ago", hits: 12,
      description: "Sensitive identity and access management activity in AWS."
    },
    {
      id: "SRCH-06", name: "VPN logins outside business hours",
      query: 'source:"VPN Gateway" AND result:success AND hour:[19 TO 6]',
      owner: "D. Okafor", scope: "Private", pinned: false,
      alerting: false, lastRun: "Yesterday", hits: 9,
      description: "Successful VPN connections between 7 PM and 6 AM local time."
    },
    {
      id: "SRCH-07", name: "TLS certificates expiring soon",
      query: 'message:"certificate" AND message:"expiring"',
      owner: "Marcus Lee", scope: "Team", pinned: false,
      alerting: false, lastRun: "2 days ago", hits: 3,
      description: "Certificates nearing expiration across monitored hosts."
    },
    {
      id: "SRCH-08", name: "Correlation engine misses",
      query: 'source:"SIEM Correlation Engine" AND message:"no match"',
      owner: "R. Singh", scope: "Private", pinned: false,
      alerting: false, lastRun: "3 days ago", hits: 58,
      description: "Baseline noise from rules evaluated with no correlation match."
    }
  ];
  
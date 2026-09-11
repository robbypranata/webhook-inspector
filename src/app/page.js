'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowRight, RefreshCw, Plus, History, Trash2, Globe, Sliders, ShieldCheck, Terminal } from 'lucide-react';
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
    
    saveToHistory(uuid, 'Auto-generated Endpoint');
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

    saveToHistory(cleanedId, 'Custom Endpoint');
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
      <div className={styles.content}>
        {/* Header */}
        <header className={styles.header}>
          <div className={styles.tagPill}>
            <Terminal size={13} />
            <span>Developer HTTP Inspector</span>
          </div>

          <h1 className={styles.title}>
            Webhook Inspector
          </h1>

          <p className={styles.subtitle}>
            Capture, inspect, and analyze incoming HTTP requests and webhook callbacks in real time with zero setup.
          </p>
        </header>

        {/* Action Card */}
        <main className={`${styles.card} animate-fade-in`}>
          <div className={styles.actionSection}>
            <button 
              onClick={handleGenerateRandom} 
              disabled={isLoading}
              className={`btn-primary ${styles.generateBtn}`}
            >
              {isLoading ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  <span>Creating Endpoint...</span>
                </>
              ) : (
                <>
                  <Plus size={16} />
                  <span>Create New Endpoint</span>
                </>
              )}
            </button>
          </div>

          <div className={styles.divider}>or use a custom path</div>

          <div className={styles.actionSection}>
            <form onSubmit={handleCreateCustom} className={styles.inputGroup}>
              <div className={styles.inputPrefix}>/api/r/</div>
              <input 
                type="text" 
                placeholder="custom-endpoint-name"
                value={customId}
                onChange={(e) => setCustomId(e.target.value)}
                disabled={isLoading}
                maxLength={40}
                className={styles.inputWithPrefix} 
              />
              <button 
                type="submit" 
                disabled={isLoading || !customId.trim()}
                className={styles.submitBtn}
                title="Open custom endpoint"
              >
                <ArrowRight size={16} />
              </button>
            </form>
          </div>

          {/* History List */}
          {history.length > 0 && (
            <div className={styles.historySection}>
              <h3 className={styles.historyTitle}>
                <History size={13} />
                Recent Endpoints
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
                    <div className={styles.historyActions}>
                      <button 
                        onClick={(e) => handleDeleteHistoryItem(e, item.id)}
                        className={styles.deleteBtn}
                        title="Delete from history"
                      >
                        <Trash2 size={13} />
                      </button>
                      <ArrowRight size={14} className={styles.historyLink} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        {/* Feature Highlights */}
        <footer className={styles.featuresGrid}>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <Globe size={16} />
            </div>
            <h4 className={styles.featureTitle}>Request Inspection</h4>
            <p className={styles.featureDesc}>
              Inspect complete HTTP headers, query parameters, client IP, and raw request bodies with instant live updates.
            </p>
          </div>

          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <Sliders size={16} />
            </div>
            <h4 className={styles.featureTitle}>Mock Responses</h4>
            <p className={styles.featureDesc}>
              Customize HTTP status codes, headers, and mock JSON/XML response payloads returned to callers.
            </p>
          </div>

          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <ShieldCheck size={16} />
            </div>
            <h4 className={styles.featureTitle}>Security Diagnostics</h4>
            <p className={styles.featureDesc}>
              Built-in blind callback listeners, SSRF encoding helpers, vulnerability payloads, and Nuclei integrations.
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}


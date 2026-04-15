import { useState, useEffect } from 'react';
import type { TerminalLog } from '../components/LiveScannerTerminal';

const API_URL = 'http://localhost:3001/api/ui/stream';

export const useSentinelStream = () => {
  const [logs, setLogs] = useState<TerminalLog[]>([]);
  const [confidence, setConfidence] = useState<number | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [activeRepoId, setActiveRepoId] = useState<number | null>(null);

  useEffect(() => {
    const eventSource = new EventSource(API_URL);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.action === 'scan-log') {
          setIsScanning(true);
          setActiveRepoId(data.repoId);
          setConfidence(data.confidenceScore);
          setLogs(prev => [...prev, data.log].slice(-100)); // Keep last 100
        }

        if (data.action === 'scan-done') {
          setIsScanning(false);
          // Don't clear logs immediately so user can read final report
        }

        // Custom UI intents
        if (data.action === 'repo' || data.action === 'navigate') {
            window.dispatchEvent(new CustomEvent('sentinel-intent', { detail: data }));
        }

      } catch (e) {
        console.error("Failed to parse SSE data", e);
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE Connection Error:", err);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, []);

  const clearLogs = () => {
    setLogs([]);
    setConfidence(null);
    setActiveRepoId(null);
  };

  return { logs, confidence, isScanning, activeRepoId, clearLogs };
};

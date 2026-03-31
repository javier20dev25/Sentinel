import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Clock, GitBranch, BrainCircuit, Loader2, Bot, Play, X, Check, Star, RefreshCcw } from 'lucide-react';
import axios from 'axios';
import { ThreatFlowMap } from './ThreatFlowMap';

const API = 'http://localhost:3001';

interface ThreatLogProps {
  repos: any[];
}

export const ThreatLog: React.FC<ThreatLogProps> = ({ repos }) => {
  const [selectedRepo, setSelectedRepo] = useState<string>('all');
  const [showPinned, setShowPinned] = useState<boolean>(false);
  const [logs, setLogs] = useState<any[]>([]);
  const [loadingLogs, setLoadingLogs] = useState<boolean>(true);
  const [rescanning, setRescanning] = useState<boolean>(false);

  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [aiResponses, setAiResponses] = useState<Record<string, any>>({});
  const [fixState, setFixState] = useState<{ logId: string, cmd: string } | null>(null);
  const [fixingId, setFixingId] = useState<string | null>(null);
  const [fixResult, setFixResult] = useState<{ success: boolean, message: string } | null>(null);

  const fetchLogs = async () => {
    setLoadingLogs(true);
    try {
      const { data } = await axios.get(`${API}/api/repositories/${selectedRepo}/logs?pinned=${showPinned}`);
      // map repo names for display
      const mappedLogs = data.map((log: any) => {
        const r = repos.find(r => r.id === log.repo_id);
        return { ...log, repoName: r ? r.github_full_name : 'Unknown Repo' };
      });
      // Sort pinned elements to appear first (preserving native API date sorting otherwise)
      mappedLogs.sort((a: any, b: any) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0));
      setLogs(mappedLogs);
    } catch (e) {
      console.error("Failed to fetch logs", e);
    } finally {
      setLoadingLogs(false);
    }
  };

  useEffect(() => {
    if (repos.length > 0) {
      fetchLogs();
    }
  }, [selectedRepo, showPinned, repos]);

  // Handle SSE intents for direct navigation
  useEffect(() => {
    const handleIntent = (e: any) => {
      const intent = e.detail;
      if (intent.action === 'repo' && intent.target) {
        // Find repo ID from Name
        const targetRepo = repos.find(r => r.github_full_name.includes(intent.target));
        if (targetRepo) {
          setSelectedRepo(targetRepo.id.toString());
        }
      }
    };

    window.addEventListener('sentinel-intent', handleIntent);
    return () => window.removeEventListener('sentinel-intent', handleIntent);
  }, [repos]);

  const handleTogglePin = async (logId: number, currentPinned: boolean) => {
    try {
      await axios.put(`${API}/api/logs/${logId}/pin`, { pinned: !currentPinned });
      fetchLogs();
    } catch (e) {
      console.error("Failed to pin log", e);
    }
  };

  const handleRescan = async () => {
    if (selectedRepo === 'all') return;
    setRescanning(true);
    
    // Non-blocking background scan
    axios.post(`${API}/api/repositories/${selectedRepo}/scan`).then(res => {
      new Notification("Sentinel Re-scan Complete", {
        body: `Scanned completed for the repository. Found ${res.data.threats_found} threats.`,
        icon: 'warning'
      });
      fetchLogs();
    }).catch(err => {
      new Notification("Sentinel Scan Error", {
        body: `Failed to re-scan: ${err.message}`
      });
    }).finally(() => {
      setRescanning(false);
    });
  };

  const SYSTEM_PROMPT = `Eres Sentinel AI, un experto mundial en ciberseguridad de supply-chain, malware en repositorios GitHub y ataques a desarrolladores.

Tu única misión es analizar código o diffs de Pull Requests y detectar amenazas reales con máxima precisión y cero alucinaciones.

REGLAS OBLIGATORIAS (nunca las rompas):
- Solo analizas el código o diff que te proporciono.
- Nunca inventes código que no esté presente.
- Nunca des falso positivo ni falso negativo por "precaución".
- Usa Chain-of-Thought internamente pero NUNCA lo muestres en la respuesta final.
- Siempre responde EXACTAMENTE en el formato JSON que se te indica.

CONTEXTO DEL ANÁLISIS:
- El código puede venir de un PR, un archivo modificado, un package.json, requirements.txt, Cargo.toml, etc.
- Busca específicamente: Caracteres Unicode invisibles, Scripts de ciclo de vida maliciosos, Ofuscación, Exfiltración de datos, Secrets leak, Time-bombs, Inyecciones en dependencias.

FORMATO DE RESPUESTA OBLIGATORIO (JSON válido, nada más):
{
  "risk_level": 10,
  "threat_type": "string",
  "short_explanation": "Máximo 15 palabras en español",
  "detailed_analysis": "Máximo 2-3 oraciones técnicas",
  "recommended_action": "BLOCK | REVIEW | IGNORE | FIX_AUTOMATICALLY",
  "remediation_suggestion": "Comando o paso concreto"
}

Nunca añadas texto fuera del JSON. Nunca uses markdown. Nunca des explicaciones extras.`;

  const analyzeThreat = async (log: any) => {
    setAnalyzingId(log.id);
    try {
      const provider = localStorage.getItem('sentinel_ai_provider') || 'openai';
      const key = localStorage.getItem('sentinel_ai_key') || '';
      const model = localStorage.getItem('sentinel_ai_model') || 'gpt-4o-mini';

      const userMessage = `Analiza esta amenaza detectada en ${log.repoName}:\nRegla: ${log.event_type}\nDescripción: ${log.description}`;

      let answer = '';

      switch (provider) {
        case 'ollama': {
          const res = await fetch('http://localhost:11434/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model, system: SYSTEM_PROMPT, prompt: userMessage, stream: false, format: 'json' })
          });
          const data = await res.json();
          answer = data.response;
          break;
        }
        case 'anthropic': {
          if (!key) throw new Error('Anthropic API Key missing.');
          const res = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': key,
              'anthropic-version': '2023-06-01',
              'anthropic-dangerous-direct-browser-access': 'true'
            },
            body: JSON.stringify({
              model: model || 'claude-3-5-sonnet-20241022',
              max_tokens: 1024,
              system: SYSTEM_PROMPT,
              messages: [{ role: 'user', content: userMessage }]
            })
          });
          const data = await res.json();
          if (data.error) throw new Error(data.error.message);
          answer = data.content?.[0]?.text || '';
          break;
        }
        case 'gemini': {
          if (!key) throw new Error('Gemini API Key missing.');
          const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model || 'gemini-1.5-pro'}:generateContent?key=${key}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: `System: ${SYSTEM_PROMPT}\n\nUser: ${userMessage}` }] }],
              generationConfig: { responseMimeType: 'application/json' }
            })
          });
          const data = await res.json();
          if (data.error) throw new Error(data.error.message);
          answer = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          break;
        }
        case 'deepseek':
        case 'openai':
        default: {
          if (!key) throw new Error(`${provider === 'deepseek' ? 'DeepSeek' : 'OpenAI'} API Key missing.`);
          const baseUrl = provider === 'deepseek' ? 'https://api.deepseek.com/chat/completions' : 'https://api.openai.com/v1/chat/completions';
          const defaultModel = provider === 'deepseek' ? 'deepseek-coder' : 'gpt-4o-mini';

          const reqBody: any = {
            model: model || defaultModel,
            messages: [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user', content: userMessage }
            ]
          };

          if (provider === 'openai') {
            reqBody.response_format = { type: 'json_object' };
          }

          const res = await fetch(baseUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${key}`
            },
            body: JSON.stringify(reqBody)
          });
          const data = await res.json();
          if (data.error) throw new Error(data.error.message);
          answer = data.choices[0].message.content;
          break;
        }
      }

      // Cleanup and Parse JSON
      let parsedJson;
      try {
        const cleanedAnswer = answer.replace(/[\u0000-\u001F\u007F-\u009F]/g, ""); // strip controls
        const jsonMatch = cleanedAnswer.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsedJson = JSON.parse(jsonMatch[0]);
        } else {
          parsedJson = JSON.parse(cleanedAnswer);
        }
      } catch (e) {
        throw new Error("AI did not return valid JSON. Raw output: " + answer.substring(0, 50) + "...");
      }

      setAiResponses(prev => ({ ...prev, [log.id]: parsedJson }));
    } catch (e: any) {
      setAiResponses(prev => ({ ...prev, [log.id]: { error: true, message: `Analysis failed: ${e.message}` } }));
    } finally {
      setAnalyzingId(null);
    }
  };

  const handleApplyFix = async () => {
    if (!fixState) return;
    setFixingId(fixState.logId);
    
    try {
      const { data } = await axios.post(`${API}/api/action/fix`, { command: fixState.cmd });
      setFixResult({ success: true, message: data.message });
      // Update local AI response to indicate it was fixed
      setAiResponses(prev => {
        const current = prev[fixState.logId];
        if (!current) return prev;
        return { ...prev, [fixState.logId]: { ...current, _fixed: true } };
      });
    } catch (e: any) {
      setFixResult({ success: false, message: e.response?.data?.error || e.message });
    } finally {
      setFixingId(null);
      setTimeout(() => {
        setFixState(null);
        setFixResult(null);
      }, 5000);
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters and Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 glass rounded-3xl p-4 border border-white/5 mb-6">
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <select 
            className="w-full sm:w-auto appearance-none bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50 outline-none"
            value={selectedRepo}
            onChange={(e) => setSelectedRepo(e.target.value)}
          >
            <option value="all">All Repositories</option>
            {repos.map(r => (
              <option key={r.id} value={r.id}>{r.github_full_name}</option>
            ))}
          </select>
          
          <button 
            onClick={() => setShowPinned(!showPinned)}
            className={`px-4 py-2 rounded-xl text-sm font-bold flex items-center justify-center gap-2 transition-all whitespace-nowrap ${
              showPinned 
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' 
                : 'bg-white/5 text-zinc-400 border border-white/10 hover:bg-white/10'
            }`}
          >
            <Star className={`w-4 h-4 shrink-0 ${showPinned ? 'fill-amber-400' : ''}`} />
            {showPinned ? `Show All (${logs.length} pinned)` : 'Pinned Only'}
          </button>
        </div>

        {selectedRepo !== 'all' && (
          <button
            onClick={handleRescan}
            disabled={rescanning}
            className="w-full sm:w-auto px-4 py-2 rounded-xl text-sm font-bold bg-blue-500 hover:bg-blue-400 text-white transition-all flex items-center justify-center gap-2 opacity-90 hover:opacity-100 disabled:opacity-50"
          >
            {rescanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCcw className="w-4 h-4" />}
            {rescanning ? 'Re-scanning...' : 'Re-scan Now'}
          </button>
        )}
      </div>

      {loadingLogs ? (
         <div className="flex justify-center p-10"><Loader2 className="w-6 h-6 animate-spin text-zinc-500" /></div>
      ) : logs.length === 0 ? (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col items-center justify-center py-20 glass rounded-[32px] border border-white/5"
        >
          <div className="w-20 h-20 rounded-3xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mb-6">
            <ShieldCheck className="w-9 h-9 text-emerald-400/60" />
          </div>
          <h3 className="text-xl font-bold text-white mb-2">No Threats Detected</h3>
          <p className="text-sm text-zinc-500 text-center max-w-xs leading-relaxed">
            All scanned repositories are clean. Sentinel will alert you the moment a suspicious pattern is found.
          </p>
        </motion.div>
      ) : (
        logs.map((log: any, i: number) => {
          const isCritical = log.risk_level >= 8;
          return (
            <motion.div
              key={log.id}
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
              className={`glass rounded-[24px] p-5 border flex flex-col gap-4 relative ${
                isCritical ? 'border-red-500/20 bg-red-500/5' : 'border-amber-500/20 bg-amber-500/5'
              }`}
            >
              <button 
                onClick={() => handleTogglePin(log.id, !!log.pinned)}
                className="absolute top-4 right-4 p-2 text-zinc-500 hover:text-amber-400 transition-colors rounded-lg hover:bg-white/5"
              >
                <Star className={`w-5 h-5 ${log.pinned ? 'fill-amber-400 text-amber-400' : ''}`} />
              </button>

              <div className="flex items-start gap-4">
                <div className={`w-10 h-10 rounded-2xl flex items-center justify-center shrink-0 mt-1 ${
                  isCritical ? 'bg-red-500/15 border border-red-500/20' : 'bg-amber-500/15 border border-amber-500/20'
                }`}>
                  <ShieldAlert className={`w-5 h-5 ${isCritical ? 'text-red-400' : 'text-amber-400'}`} />
                </div>
                
                <div className="flex-1 min-w-0 pr-10">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full border ${
                      isCritical
                        ? 'text-red-400 bg-red-500/10 border-red-500/20'
                        : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                    }`}>
                      Risk {log.risk_level}/10
                    </span>
                    <span className="text-[10px] text-zinc-600 font-bold">{log.event_type}</span>
                  </div>
                  <p className="text-sm text-zinc-300 leading-relaxed mt-1 break-words">{log.description}</p>
                  
                  <div className="flex flex-wrap items-center gap-4 mt-3 text-[10px] text-zinc-500 font-bold">
                    <span className="flex items-center gap-1.5 bg-black/20 px-2 py-1 rounded-md">
                      <GitBranch className="w-3 h-3" />
                      {log.repoName}
                    </span>
                    <span className="flex items-center gap-1.5 bg-black/20 px-2 py-1 rounded-md">
                      <Clock className="w-3 h-3" />
                      {new Date(log.created_at).toLocaleString()}
                    </span>
                    
                    <button
                      onClick={() => analyzeThreat(log)}
                      disabled={analyzingId === log.id}
                      className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 transition-colors border border-indigo-500/20"
                    >
                      {analyzingId === log.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <BrainCircuit className="w-3 h-3" />}
                      Ask AI
                    </button>
                  </div>
                  
                  <ThreatFlowMap eventType={log.event_type} />

                  <AnimatePresence>
                    {aiResponses[log.id] && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-4 p-5 rounded-[20px] bg-indigo-500/10 border border-indigo-500/20 overflow-hidden"
                      >
                        <div className="flex items-start gap-3">
                          <div className="p-2 rounded-xl bg-indigo-500/20 shrink-0">
                            <Bot className="w-5 h-5 text-indigo-400" />
                          </div>
                          
                          {aiResponses[log.id].error ? (
                            <div className="text-sm text-red-400 font-medium pt-1">
                              {aiResponses[log.id].message}
                            </div>
                          ) : (
                            <div className="flex-1 min-w-0 space-y-3">
                              <div className="flex items-start justify-between">
                                <div className="space-y-1">
                                    <h4 className="text-white font-bold text-sm tracking-wide">
                                      {aiResponses[log.id].threat_type}
                                    </h4>
                                    <p className="text-indigo-200/80 text-xs">
                                      {aiResponses[log.id].short_explanation}
                                    </p>
                                </div>
                                <div className={`px-2.5 py-1 rounded-lg border text-[10px] font-black tracking-widest uppercase ${
                                  aiResponses[log.id].recommended_action === 'BLOCK' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                  aiResponses[log.id].recommended_action === 'IGNORE' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' :
                                  'bg-amber-500/20 text-amber-400 border-amber-500/30'
                                }`}>
                                  {aiResponses[log.id].recommended_action}
                                </div>
                              </div>

                              <div className="bg-black/20 rounded-xl p-3 border border-white/5">
                                <p className="text-zinc-300 text-xs leading-relaxed">
                                  {aiResponses[log.id].detailed_analysis}
                                </p>
                              </div>

                              <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/5 border border-emerald-500/10 p-3 rounded-xl justify-between">
                                  <div className="flex items-center gap-2 truncate">
                                    <span className="font-bold shrink-0">{'>'} Fix:</span>
                                    <span className="truncate">{aiResponses[log.id].remediation_suggestion}</span>
                                  </div>
                                  
                                  <button
                                    onClick={() => setFixState({ logId: log.id, cmd: aiResponses[log.id].remediation_suggestion })}
                                    disabled={aiResponses[log.id]._fixed}
                                    className={`shrink-0 ml-4 px-3 py-1.5 rounded-lg flex items-center gap-1.5 font-bold transition-all ${
                                      aiResponses[log.id]._fixed 
                                        ? 'bg-emerald-500/20 text-emerald-400 cursor-not-allowed' 
                                        : 'bg-emerald-500 text-white hover:bg-emerald-400'
                                    }`}
                                  >
                                    {aiResponses[log.id]._fixed ? <Check className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                                    {aiResponses[log.id]._fixed ? 'APPLIED' : 'APPLY FIX'}
                                  </button>
                              </div>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </motion.div>
          );
        })
      )}

      {/* Double Opt-In Execution Modal */}
      <AnimatePresence>
        {fixState && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="max-w-md w-full glass rounded-3xl border border-red-500/20 p-6 overflow-hidden relative shadow-2xl"
            >
              <div className="absolute top-0 right-0 w-64 h-64 bg-red-500/10 blur-[60px] pointer-events-none" />
              
              <div className="flex justify-between items-start mb-5 relative z-10">
                <div className="w-12 h-12 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                </div>
                {!fixingId && !fixResult && (
                  <button onClick={() => setFixState(null)} className="p-2 text-zinc-500 hover:text-white transition-colors">
                    <X className="w-5 h-5" />
                  </button>
                )}
              </div>

              <h3 className="text-xl font-bold text-white mb-2 relative z-10">Restricted Execution</h3>
              <p className="text-sm text-zinc-400 mb-4 relative z-10 leading-relaxed">
                Sentinel is requesting permission to execute the following remediation command directly on your machine.
              </p>

              <div className="bg-black/40 border border-white/10 rounded-xl p-4 mb-6 relative z-10 font-mono text-xs text-amber-400 break-all">
                {fixState.cmd}
              </div>

              {fixResult ? (
                <div className={`p-4 rounded-xl text-sm font-bold relative z-10 flex items-start gap-3 ${
                  fixResult.success ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'
                }`}>
                  {fixResult.success ? <Check className="w-5 h-5 shrink-0" /> : <X className="w-5 h-5 shrink-0" />}
                  <span className="leading-relaxed">{fixResult.message}</span>
                </div>
              ) : (
                <div className="flex gap-3 relative z-10 mt-2">
                  <button
                    onClick={() => setFixState(null)}
                    disabled={fixingId !== null}
                    className="flex-1 py-3 px-4 rounded-xl font-bold text-sm bg-white/5 hover:bg-white/10 text-white transition-colors border border-white/10"
                  >
                    Abort
                  </button>
                  <button
                    onClick={handleApplyFix}
                    disabled={fixingId !== null}
                    className="flex-1 py-3 px-4 rounded-xl font-bold text-sm bg-red-500 hover:bg-red-400 text-white transition-colors flex items-center justify-center gap-2"
                  >
                    {fixingId ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    {fixingId ? 'Executing...' : 'Authorize Execution'}
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

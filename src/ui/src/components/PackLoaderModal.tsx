import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Upload, ShieldCheck, AlertTriangle, FileJson, CheckCircle, Package, Trash2, Power } from 'lucide-react';
import axios from 'axios';

interface PackLoaderModalProps {
  isOpen: boolean;
  onClose: () => void;
  repoId: number;
  onUpdated: () => void;
}

export const PackLoaderModal: React.FC<PackLoaderModalProps> = ({ isOpen, onClose, repoId, onUpdated }) => {
  const [activeTab, setActiveTab] = useState<'load' | 'manage'>('load');
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [acceptedRisk, setAcceptedRisk] = useState(false);
  
  // Management state
  const [installedPacks, setInstalledPacks] = useState<any[]>([]);

  useEffect(() => {
    if (isOpen) {
      resetState();
      fetchPacks();
    }
  }, [isOpen, repoId]);

  const resetState = () => {
    setFileContent(null);
    setScanResult(null);
    setError('');
    setAcceptedRisk(false);
  }

  const fetchPacks = async () => {
    try {
      const { data } = await axios.get(`http://localhost:3001/api/repositories/${repoId}/packs`);
      setInstalledPacks(data);
    } catch (e: any) {
      console.error(e);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    resetState();
    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result as string;
      setFileContent(content);
      
      setLoading(true);
      try {
        const { data } = await axios.post(`http://localhost:3001/api/repositories/${repoId}/packs/scan`, {
          fileContent: content
        });
        setScanResult(data);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Error scanning pack');
      } finally {
        setLoading(false);
      }
    };
    reader.readAsText(file);
  };

  const verifyAndInstall = async () => {
    if (scanResult && (!scanResult.isOfficial && !acceptedRisk)) return;
    
    setLoading(true);
    try {
      await axios.post(`http://localhost:3001/api/repositories/${repoId}/packs/install`, {
        packData: scanResult.packData,
        isOfficial: scanResult.isOfficial
      });
      onUpdated();
      setActiveTab('manage');
      fetchPacks();
      resetState();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Install failed');
    } finally {
      setLoading(false);
    }
  };

  const togglePack = async (packId: number, active: boolean) => {
    try {
      await axios.put(`http://localhost:3001/api/repositories/${repoId}/packs/${packId}/toggle`, { active });
      fetchPacks();
      onUpdated();
    } catch (e) {
      console.error(e);
    }
  };

  const deletePack = async (packId: number) => {
    if (!confirm('¿Seguro que deseas eliminar este pack permanentemente?')) return;
    try {
      await axios.delete(`http://localhost:3001/api/repositories/${repoId}/packs/${packId}`);
      fetchPacks();
      onUpdated();
    } catch (e) {
      console.error(e);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/70 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="w-full max-w-2xl bg-[#0d0d0f] border border-[#2a2a30] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#2a2a30] bg-[#111114]">
            <div className="flex gap-4">
              <button 
                onClick={() => setActiveTab('load')}
                className={`text-[11px] font-mono font-bold tracking-widest uppercase transition-colors ${activeTab === 'load' ? 'text-amber-400' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                Cargar Pack
              </button>
              <button 
                onClick={() => setActiveTab('manage')}
                className={`text-[11px] font-mono font-bold tracking-widest uppercase transition-colors ${activeTab === 'manage' ? 'text-amber-400' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                Mis Packs ({installedPacks.length})
              </button>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 text-zinc-500 hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="overflow-y-auto flex-1 p-5">
            {/* TAB: LOAD PACK */}
            {activeTab === 'load' && (
              <div className="space-y-5">
                {!scanResult && !loading && (
                  <div className="border-2 border-dashed border-white/10 rounded-2xl p-10 flex flex-col items-center justify-center text-center bg-white/[0.02] hover:bg-white/[0.04] transition-colors relative">
                    <input 
                      type="file" 
                      accept=".json,.yml,.yaml" 
                      onChange={handleFileUpload} 
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      title="Load Pack File"
                    />
                    <Upload className="w-8 h-8 text-zinc-500 mb-3" />
                    <p className="text-sm font-bold text-white">Haz clic o arrastra un pack de configuración</p>
                    <p className="text-[11px] text-zinc-500 mt-1">Soporta .json y .yml</p>
                  </div>
                )}

                {loading && (
                  <div className="flex flex-col items-center justify-center py-10 opacity-50">
                    <div className="w-8 h-8 rounded-full border-t-2 border-amber-500 animate-spin mb-4" />
                    <p className="text-xs text-white">Procesando pack...</p>
                  </div>
                )}

                {error && (
                  <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl text-xs flex items-center justify-between">
                    <span>{error}</span>
                    <button onClick={resetState} className="underline text-[10px]">Reintentar</button>
                  </div>
                )}

                {scanResult && !loading && (
                  <div className="space-y-4">
                    {/* Header: Verified vs Unverified */}
                    {scanResult.isOfficial ? (
                      <div className="flex items-center gap-3 bg-emerald-500/10 border border-emerald-500/20 px-4 py-3 rounded-xl">
                        <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />
                        <div>
                          <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-widest">Firma Verificada</h4>
                          <p className="text-[11px] text-emerald-500/70">Paquete Oficial de Sentinel Lab cargado con éxito.</p>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-3 bg-red-500/10 border border-red-500/20 px-4 py-3 rounded-xl">
                        <AlertTriangle className="w-6 h-6 text-red-500 shrink-0" />
                        <div>
                          <h4 className="text-xs font-bold text-red-400 uppercase tracking-widest">Paquete No Verificado</h4>
                          <p className="text-[11px] text-red-500/70">La firma digital es inválida o no existe. Este paquete podría ser peligroso.</p>
                        </div>
                      </div>
                    )}

                    {/* Metadata */}
                    <div className="bg-[#18181b] border border-[#2a2a30] rounded-xl p-4">
                      <h4 className="text-[14px] font-bold text-white flex items-center gap-2 mb-1">
                        <Package className="w-4 h-4 text-zinc-400" />
                        {scanResult.metadata.name || 'Sin Nombre'} <span className="text-[10px] text-zinc-500 bg-black/40 px-2 py-0.5 rounded-full">v{scanResult.metadata.version || '1.0'}</span>
                      </h4>
                      <p className="text-[11px] text-zinc-400">Autor: {scanResult.metadata.author || 'Desconocido'}</p>
                    </div>

                    {/* Alerts (High Risk) */}
                    {scanResult.alerts && scanResult.alerts.length > 0 && (
                      <div className="space-y-2">
                        <h5 className="text-[10px] font-bold uppercase tracking-wider text-red-400">Alertas Críticas Detectadas</h5>
                        {scanResult.alerts.map((al: string, i: number) => (
                          <div key={i} className="text-[11px] bg-red-500/5 border border-red-500/10 text-red-300 p-3 rounded-xl leading-relaxed">
                            {al}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Changes Diff */}
                    <div>
                      <h5 className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 mb-2">Cambios Efectivos</h5>
                      <div className="bg-black/50 border border-white/5 rounded-xl overflow-hidden font-mono text-[11px]">
                        {scanResult.diff.length === 0 ? (
                          <div className="p-3 text-zinc-500">Ningún cambio efectivo. Este pack contiene los mismos valores actuales.</div>
                        ) : (
                          scanResult.diff.map((d: any, i: number) => (
                            <div key={i} className="flex px-3 py-2 border-b last:border-0 border-white/5 items-center justify-between">
                              <span className="text-zinc-300">{d.key}</span>
                              <div className="flex items-center gap-2">
                                <span className="text-zinc-500 line-through">{String(d.old)}</span>
                                <span className="text-zinc-600">→</span>
                                <span className="text-amber-400 font-bold">{String(d.new)}</span>
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>

                    {/* Confirm Form */}
                    <div className="pt-4 border-t border-white/5 mt-4">
                      {!scanResult.isOfficial && (
                        <div className="mb-4">
                          <label className="flex items-start gap-3 cursor-pointer group">
                            <input 
                              type="checkbox" 
                              checked={acceptedRisk} 
                              onChange={(e) => setAcceptedRisk(e.target.checked)} 
                              className="mt-0.5 accent-red-500 w-4 h-4" 
                            />
                            <div className="flex-1">
                              <span className="text-[11px] font-bold text-red-400 group-hover:text-red-300 transition-colors">Entiendo los riesgos y procedo bajo mi responsabilidad.</span>
                              <p className="text-[10px] text-zinc-500 leading-tight mt-1">Sentinel Lab no se hace responsable por paquetes de configuraciones desarrollados por terceros o modificados ilegalmente.</p>
                            </div>
                          </label>
                        </div>
                      )}

                      <div className="flex items-center justify-end gap-3">
                        <button onClick={resetState} className="px-4 py-2 rounded-xl text-[11px] font-bold text-zinc-400 hover:bg-white/5 transition-colors">
                          Cancelar
                        </button>
                        <button 
                          onClick={verifyAndInstall} 
                          disabled={!scanResult.isOfficial && !acceptedRisk}
                          className={`px-5 py-2 rounded-xl text-[11px] font-bold transition-all disabled:opacity-30 disabled:cursor-not-allowed ${
                            scanResult.isOfficial 
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30' 
                              : 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
                          }`}
                        >
                          Instalar Pack
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB: MANAGE PACKS */}
            {activeTab === 'manage' && (
              <div className="space-y-3">
                {installedPacks.length === 0 ? (
                  <div className="text-center py-10 opacity-50">
                    <Package className="w-8 h-8 mx-auto text-zinc-500 mb-3" />
                    <p className="text-xs text-white">No hay packs instalados en este repositorio.</p>
                  </div>
                ) : (
                  installedPacks.map((pack) => (
                    <div key={pack.id} className={`flex items-center justify-between p-4 rounded-xl border transition-colors ${pack.is_active ? 'bg-[#18181b] border-[#2a2a30]' : 'bg-black/30 border-white/5 opacity-60'}`}>
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="text-sm font-bold text-white">{pack.name}</h4>
                          {pack.is_official && (
                            <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wider">Oficial</span>
                          )}
                        </div>
                        <p className="text-[11px] text-zinc-500">v{pack.version} • Autor: {pack.author}</p>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <button 
                          onClick={() => togglePack(pack.id, !pack.is_active)}
                          className={`p-2 rounded-lg transition-colors border ${pack.is_active ? 'bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20' : 'bg-white/5 text-zinc-500 border-white/10 hover:bg-white/10 hover:text-white'}`}
                          title={pack.is_active ? 'Desactivar' : 'Activar'}
                        >
                          <Power className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => deletePack(pack.id)}
                          className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors"
                          title="Eliminar permanentemente"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))
                )}
                
                {installedPacks.length > 0 && (
                  <p className="text-[10px] text-zinc-600 text-center mt-6">
                    Los packs se fusionan de arriba hacia abajo (los últimos instalados sobrescriben a los más viejos en caso de conflicto).
                  </p>
                )}
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

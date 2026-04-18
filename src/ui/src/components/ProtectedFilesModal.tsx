import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Shield, Plus, Trash2, FileWarning, FolderLock } from 'lucide-react';
import axios from 'axios';

interface ProtectedFilesModalProps {
  isOpen: boolean;
  onClose: () => void;
  repoId: number;
}

export const ProtectedFilesModal: React.FC<ProtectedFilesModalProps> = ({ isOpen, onClose, repoId }) => {
  const [protectedFiles, setProtectedFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchProtectedFiles();
    }
  }, [isOpen, repoId]);

  const fetchProtectedFiles = async () => {
    setLoading(true);
    try {
      const { data } = await axios.get(`http://localhost:3001/api/repositories/${repoId}/protected`);
      setProtectedFiles(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const removeFile = async (fileId: number) => {
    try {
      await axios.delete(`http://localhost:3001/api/repositories/${repoId}/protected/${fileId}`);
      fetchProtectedFiles();
    } catch (e) {
      console.error(e);
    }
  };

  const clearAll = async () => {
    if (!confirm('¿Estás seguro de eliminar todos los archivos protegidos?')) return;
    try {
      await axios.delete(`http://localhost:3001/api/repositories/${repoId}/protected`);
      fetchProtectedFiles();
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddFiles = async () => {
    // We use standard HTML input to trigger OS file picker natively
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.onchange = async (e: any) => {
      const files = Array.from(e.target.files);
      const paths = files.map((f: any) => f.path || f.webkitRelativePath || f.name); // f.path depends on environment (works in Electron often)
      
      // En entorno de navegador, webkitRelativePath o name es todo lo que tenemos a menos que se use API File System nativo.
      // Como Sentinel es app local/electron, si estamos en tauri o electron, se puede pasar el path real.
      
      if (paths.length > 0) {
        try {
          await axios.post(`http://localhost:3001/api/repositories/${repoId}/protected`, { files: paths });
          fetchProtectedFiles();
        } catch (err) {
          console.error(err);
        }
      }
    };
    input.click();
  };

  // En Electron, podemos usar una API especial si la hubiéramos expuesto, pero asumiremos que el HTML input tiene f.path.

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/70 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="w-full max-w-lg bg-[#0d0d0f] border border-[#2a2a30] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#2a2a30] bg-[#111114]">
            <div className="flex items-center gap-3 text-amber-400">
              <FolderLock className="w-5 h-5" />
              <h2 className="text-sm font-bold uppercase tracking-widest">Archivos Protegidos</h2>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 text-zinc-500 hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-5 flex-1 overflow-y-auto">
            <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400/80 p-3 rounded-xl text-[11px] leading-relaxed mb-5 flex gap-3">
              <FileWarning className="w-5 h-5 shrink-0 text-amber-500 mt-0.5" />
              <p>
                Los archivos que añadas aquí serán bloqueados de subirse a tu repositorio por Sentinel de forma automática.
                Si un <i>commit</i> toca estos archivos, Sentinel te alertará e impedirá la subida para evitar la filtración de material sensible (ej. .env locales, documentos personales, certificados).
              </p>
            </div>

            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-widest">Lista Actual ({protectedFiles.length})</h3>
              <div className="flex gap-2">
                {protectedFiles.length > 0 && (
                  <button 
                    onClick={clearAll}
                    className="flex items-center gap-1.5 px-3 py-1.5 hover:bg-red-500/10 text-zinc-500 hover:text-red-400 border border-transparent hover:border-red-500/20 rounded-lg text-[10px] font-bold transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Limpiar todo
                  </button>
                )}
                <button 
                  onClick={handleAddFiles}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 border border-amber-500/30 rounded-lg text-[10px] font-bold transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" /> Agregar Nuevo
                </button>
              </div>
            </div>

            <div className="space-y-2">
              {loading ? (
                <div className="text-center py-6 text-zinc-500 text-xs">Cargando...</div>
              ) : protectedFiles.length === 0 ? (
                <div className="text-center py-10 border border-dashed border-white/10 rounded-xl bg-white/[0.02]">
                  <Shield className="w-8 h-8 mx-auto text-zinc-600 mb-2 opacity-50" />
                  <p className="text-xs text-zinc-500">No hay archivos protegidos configurados.</p>
                </div>
              ) : (
                protectedFiles.map(file => (
                  <div key={file.id} className="flex items-center justify-between p-3 rounded-lg bg-[#18181b] border border-[#2a2a30]">
                    <div className="flex items-center gap-3 truncate">
                      <FolderLock className="w-4 h-4 text-amber-500/70" />
                      <span className="text-[11px] text-zinc-300 font-mono truncate" title={file.file_path}>{file.file_path}</span>
                    </div>
                    <button 
                      onClick={() => removeFile(file.id)}
                      className="p-1.5 rounded-md hover:bg-red-500/20 text-zinc-500 hover:text-red-400 transition-colors shrink-0 ml-3"
                      title="Dejar de proteger"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

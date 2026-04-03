import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  File, Folder, Lock as LockIcon, Unlock as UnlockIcon, Search, CheckCircle, 
  AlertCircle, ChevronRight, ChevronDown, Database, Key, Shield
} from 'lucide-react';

interface AssetGuardViewProps {
  repoId: string;
}

interface FileNode {
  name: string;
  path: string;
  isDir: boolean;
  children?: FileNode[];
  error?: string;
}

const AssetGuardView: React.FC<AssetGuardViewProps> = ({ repoId }) => {
  const [structure, setStructure] = useState<FileNode | null>(null);
  const [prohibitedPaths, setProhibitedPaths] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const fetchStructure = async () => {
    if (repoId === 'all') return;
    setLoading(true);
    try {
      const [{ data: struct }, { data: prohibited }] = await Promise.all([
        axios.get(`http://localhost:3001/api/shield/structure/${repoId}`),
        axios.get(`http://localhost:3001/api/shield/prohibited/${repoId}`)
      ]);
      setStructure(struct);
      setProhibitedPaths(prohibited.map((p: any) => p.path));
    } catch (e) {
      console.error("Failed to fetch structure", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStructure();
  }, [repoId]);

  const toggleProhibit = async (path: string, currentlyProhibited: boolean) => {
    try {
      await axios.post('http://localhost:3001/api/shield/prohibit', {
        repoId,
        path,
        prohibited: !currentlyProhibited
      });
      // Optimal local update
      if (currentlyProhibited) {
        setProhibitedPaths(prev => prev.filter(p => p !== path));
      } else {
        setProhibitedPaths(prev => [...prev, path]);
      }
    } catch (e) { }
  };

  const toggleExpand = (path: string) => {
    setExpanded(prev => ({ ...prev, [path]: !prev[path] }));
  };

  const renderTree = (node: FileNode, depth = 0) => {
    const isProhibited = prohibitedPaths.includes(node.path);
    const isOpen = expanded[node.path];

    return (
      <div key={node.path} className="select-none">
        <div 
          className={`flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-white/5 group transition-colors cursor-pointer ${isProhibited ? 'bg-red-500/5' : ''}`}
          style={{ paddingLeft: `${depth * 1.5 + 0.75}rem` }}
        >
          {node.isDir ? (
            <button onClick={() => toggleExpand(node.path)} className="p-1 -ml-1 text-zinc-600 hover:text-white transition-colors">
              {isOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            </button>
          ) : (
            <div className="w-3.5 h-3.5" />
          )}

          {node.isDir ? (
            <Folder className={`w-4 h-4 ${isProhibited ? 'text-red-400' : 'text-blue-400/70'}`} />
          ) : (
            <File className={`w-4 h-4 ${isProhibited ? 'text-red-400' : 'text-zinc-500'}`} />
          )}

          <span className={`text-[13px] flex-1 truncate ${isProhibited ? 'text-red-400 font-bold' : 'text-zinc-300'}`}>
            {node.name}
          </span>

          <button 
            onClick={() => toggleProhibit(node.path, isProhibited)}
            className={`opacity-0 group-hover:opacity-100 p-1.5 rounded-lg border transition-all ${
              isProhibited 
                ? 'bg-red-500/10 border-red-500/20 text-red-400 opacity-100' 
                : 'bg-white/5 border-white/10 text-zinc-500 hover:text-white hover:border-white/20'
            }`}
          >
            {isProhibited ? <LockIcon className="w-3.5 h-3.5" /> : <UnlockIcon className="w-3.5 h-3.5" />}
          </button>
        </div>

        {node.isDir && isOpen && node.children && (
          <div className="mt-1">
            {node.children.map(child => renderTree(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  if (repoId === 'all') {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <Shield className="w-16 h-16 text-zinc-800 mb-6" />
        <h3 className="text-xl font-bold text-white mb-2">Asset Guard</h3>
        <p className="text-sm text-zinc-500 max-w-sm">Select a specific repository to map sensitive files and prevent accidental data leakage.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-lg font-black text-white">Sensitive Assets Map</h2>
          <p className="text-xs text-zinc-500 mt-1 uppercase tracking-widest font-bold font-mono">
            Prohibited Files: <span className="text-red-400">{prohibitedPaths.length}</span>
          </p>
        </div>
        <div className="flex gap-2">
            <div className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-[10px] font-black text-emerald-400 uppercase tracking-widest">
                <CheckCircle className="w-3 h-3" />
                Push Interceptor Active
            </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* File Explorer Tree */}
        <div className="lg:col-span-2 glass rounded-3xl border border-white/5 p-6 h-[600px] overflow-y-auto">
          {loading ? (
            <div className="h-full flex items-center justify-center">
              <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />
            </div>
          ) : structure ? (
            renderTree(structure)
          ) : (
            <p className="text-zinc-600 italic">Could not read repository structure.</p>
          )}
        </div>

        {/* Info & Recommendations */}
        <div className="space-y-6">
          <div className="glass rounded-3xl border border-white/5 p-6 bg-red-500/[0.02]">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                <AlertCircle className="w-5 h-5 text-red-500" />
              </div>
              <h4 className="text-sm font-black text-white uppercase tracking-tight">Active Protection</h4>
            </div>
            <p className="text-xs text-zinc-500 leading-relaxed">
              Files marked with <LockIcon className="inline w-3 h-3 mx-1 text-red-400" /> cannot be pushed to the remote repository. Sentinel will intercept the `git push` command and require triple verification and your master password to proceed if these files are staged.
            </p>
          </div>

          <div className="glass rounded-3xl border border-white/5 p-6">
            <h4 className="text-xs font-black text-zinc-500 uppercase tracking-[0.2em] mb-4">Common Targets</h4>
            <div className="space-y-3">
              {[
                { name: '.env', icon: Key, label: 'Environment Variables' },
                { name: 'id_rsa', icon: Shield, label: 'SSH Private Keys' },
                { name: 'db.sqlite', icon: Database, label: 'Local Databases' },
                { name: 'credentials.json', icon: Key, label: 'Cloud API Keys' }
              ].map(item => (
                <div key={item.name} className="flex items-center gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/5">
                  <item.icon className="w-4 h-4 text-amber-400" />
                  <div>
                    <p className="text-[11px] font-bold text-white">{item.name}</p>
                    <p className="text-[9px] text-zinc-600 uppercase font-black">{item.label}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AssetGuardView;

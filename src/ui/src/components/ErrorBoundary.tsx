import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { Shield, RefreshCcw } from 'lucide-react';
import { motion } from 'framer-motion';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  private handleReset = () => {
    localStorage.removeItem('sentinel_jwt'); // Clear potential corrupt state
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="h-screen flex items-center justify-center p-8 bg-[#09090b] relative overflow-hidden">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-red-500/10 blur-[100px] rounded-full" />
          
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="max-w-md w-full glass rounded-[32px] border border-red-500/20 p-10 text-center relative z-10"
          >
            <div className="w-20 h-20 mx-auto rounded-[24px] bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-6">
              <Shield className="w-10 h-10 text-red-500" />
            </div>
            <h2 className="text-2xl font-black text-white mb-2">Interface Corrupted</h2>
            <p className="text-sm text-zinc-400 mb-6 leading-relaxed">
              Sentinel encountered a critical UI error. This is often caused by browser extensions interfering with the security dashboard.
            </p>
            <div className="bg-black/30 text-red-400 text-[10px] font-mono p-3 rounded-xl border border-red-500/10 mb-8 overflow-hidden text-ellipsis whitespace-nowrap">
              {this.state.error?.message || 'Unknown Runtime Error'}
            </div>
            <button
              onClick={this.handleReset}
              className="w-full px-5 py-4 rounded-2xl bg-red-500 text-white font-bold hover:bg-red-600 transition-colors flex items-center justify-center gap-2"
            >
              <RefreshCcw className="w-4 h-4" />
              Reset & Recover
            </button>
          </motion.div>
        </div>
      );
    }

    return this.props.children;
  }
}

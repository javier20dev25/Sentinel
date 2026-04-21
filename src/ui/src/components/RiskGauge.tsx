import React from 'react';
import { motion } from 'framer-motion';

interface RiskGaugeProps {
  score: number;
  label?: string;
  size?: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, label = "Risk Score", size = 180 }) => {
  const radius = size / 2 - 10;
  const circumference = radius * Math.PI; // Semicircle
  const offset = circumference - (score / 100) * circumference;

  const getRiskColor = (s: number) => {
    if (s < 30) return '#10b981'; // emerald-500
    if (s < 70) return '#f59e0b'; // amber-500
    return '#ef4444'; // red-500
  };

  const color = getRiskColor(score);

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size / 2 + 20 }}>
        <svg width={size} height={size / 2 + 10} viewBox={`0 0 ${size} ${size / 2}`}>
          {/* Background Path */}
          <path
            d={`M 10,${size / 2} A ${radius},${radius} 0 0,1 ${size - 10},${size / 2}`}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="12"
            strokeLinecap="round"
          />
          {/* Risk Path */}
          <motion.path
            d={`M 10,${size / 2} A ${radius},${radius} 0 0,1 ${size - 10},${size / 2}`}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.5, ease: "easeOut" }}
            style={{ filter: `drop-shadow(0 0 8px ${color}66)` }}
          />
        </svg>
        
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-2">
          <motion.span 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-4xl font-black text-white"
          >
            {score}
          </motion.span>
          <span className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-500">{label}</span>
        </div>
      </div>
      
      {/* Risk Level Badge */}
      <motion.div 
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        style={{ backgroundColor: `${color}15`, color: color, borderColor: `${color}30` }}
        className="mt-2 px-4 py-1 rounded-full border text-[10px] font-bold uppercase tracking-widest"
      >
        {score >= 70 ? 'High Risk' : score >= 30 ? 'Elevated' : 'Safe'}
      </motion.div>
    </div>
  );
};

import React from 'react';

interface ScoreRingProps {
  score: number;
  grade?: string;
}

export const ScoreRing: React.FC<ScoreRingProps> = ({ score, grade }) => {
  const radius = 24; // Increased slightly for better visibility
  const stroke = 4;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let colorClass = 'text-emerald-500';
  let glowClass = 'shadow-emerald-500/50';
  
  // Color based on score
  if (score < 50) {
    colorClass = 'text-red-500';
    glowClass = 'shadow-red-500/50';
  } else if (score < 80) {
    colorClass = 'text-yellow-500';
    glowClass = 'shadow-yellow-500/50';
  }

  return (
    <div className="flex items-center gap-3">
      <div className={`relative w-14 h-14 flex items-center justify-center rounded-full shadow-[0_0_15px_rgba(0,0,0,0.5)] ${glowClass}`}>
        <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
          <circle
            stroke="rgba(255,255,255,0.05)"
            fill="transparent"
            strokeWidth={stroke}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
          />
          <circle
            stroke="currentColor"
            fill="transparent"
            strokeWidth={stroke}
            strokeDasharray={circumference + ' ' + circumference}
            style={{ strokeDashoffset, transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)' }}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            className={`${colorClass}`}
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center leading-none">
          <span className={`text-[11px] font-black ${colorClass}`}>{grade || score}</span>
          {grade && <span className="text-[7px] text-zinc-500 font-bold uppercase mt-0.5">{score}%</span>}
        </div>
      </div>
      <div>
        <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Postura</p>
        <p className={`text-xs font-bold ${colorClass}`}>
          {score >= 80 ? 'Healthy' : score >= 50 ? 'Needs Attention' : 'Critical'}
        </p>
      </div>
    </div>
  );
};

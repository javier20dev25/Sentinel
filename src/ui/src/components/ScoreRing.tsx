import React from 'react';

interface ScoreRingProps {
  score: number;
}

export const ScoreRing: React.FC<ScoreRingProps> = ({ score }) => {
  const radius = 20;
  const stroke = 4;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let colorClass = 'text-emerald-500';
  let glowClass = 'shadow-emerald-500/50';
  if (score < 50) {
    colorClass = 'text-red-500';
    glowClass = 'shadow-red-500/50';
  } else if (score < 80) {
    colorClass = 'text-yellow-500';
    glowClass = 'shadow-yellow-500/50';
  }

  return (
    <div className="flex items-center gap-3">
      <div className={`relative w-12 h-12 flex items-center justify-center rounded-full shadow-[0_0_15px_rgba(0,0,0,0.5)] ${glowClass}`}>
        <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
          <circle
            stroke="rgba(255,255,255,0.1)"
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
            style={{ strokeDashoffset, transition: 'stroke-dashoffset 0.5s ease-in-out' }}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            className={`${colorClass}`}
          />
        </svg>
        <span className={`absolute text-[10px] font-black ${colorClass}`}>{score}</span>
      </div>
      <div>
        <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Posture</p>
        <p className={`text-xs font-bold ${colorClass}`}>
          {score >= 80 ? 'Healthy' : score >= 50 ? 'Needs Attention' : 'Critical'}
        </p>
      </div>
    </div>
  );
};

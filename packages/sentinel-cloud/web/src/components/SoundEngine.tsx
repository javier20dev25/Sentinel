'use client';

import React, { useEffect } from 'react';

export default function SoundEngine() {
  useEffect(() => {
    // Only run on client
    if (typeof window === 'undefined') return;

    const playClick = () => {
      // Use standard AudioContext with fallbacks for strict types
      const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      
      if (!AudioContextClass) return;

      const audioCtx = new AudioContextClass();
      const oscillator = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      oscillator.type = 'square';
      oscillator.frequency.setValueAtTime(150, audioCtx.currentTime); 
      
      gainNode.gain.setValueAtTime(0.05, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.1);

      oscillator.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      oscillator.start();
      oscillator.stop(audioCtx.currentTime + 0.1);
      
      // Close context to save resources after play
      setTimeout(() => {
        audioCtx.close().catch(() => {});
      }, 200);
    };

    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (target.closest('button') || target.closest('a')) {
        playClick();
      }
    };

    window.addEventListener('click', handleClick);
    return () => window.removeEventListener('click', handleClick);
  }, []);

  return <div className="scanline-effect" aria-hidden="true" />;
}

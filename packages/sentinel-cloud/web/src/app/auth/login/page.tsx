'use client';

import React from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { createClient } from '@/utils/supabase/client';

export default function LoginPage() {
  const handleLogin = async () => {
    const supabase = createClient();
    
    // FORZADO DE EMERGENCIA: Usamos el dominio que sabemos que funciona
    // Ignoramos el origen dinámico para evitar el bucle hacia el dominio 'nueve'
    const canonicalUrl = 'https://sentinel-psi-nine.vercel.app';
    
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${canonicalUrl}/auth/callback`,
        skipBrowserRedirect: false,
        scopes: 'repo read:user'
      },
    });

    if (error) {
      console.error('Login error:', error.message);
      alert('Error al conectar con GitHub.');
    }
  };

  return (
    <div className="min-h-screen bg-white text-black font-mono flex flex-col items-center justify-center p-8 selection:bg-black selection:text-white" translate="no">
      <div className="w-full max-w-md text-center">
        <Link href="/" className="flex items-center justify-center gap-4 mb-16 hover:opacity-80 transition-opacity">
          <Image 
            src="/brand/logo.png" 
            alt="Sentinel Logo" 
            width={48} 
            height={48} 
            className="object-contain mix-blend-multiply" 
          />
          <div className="text-2xl font-bold tracking-tighter uppercase">SENTINEL</div>
        </Link>
        
        <h1 className="text-4xl font-bold uppercase tracking-tight mb-4 glitch-text">Terminal Access</h1>
        <p className="text-gray-500 text-[10px] mb-12 italic uppercase tracking-widest">Forced Routing to: sentinel-psi-nine.vercel.app</p>

        <button 
          onClick={handleLogin}
          className="w-full bg-black text-white flex items-center justify-center gap-4 py-4 font-bold uppercase text-sm hover:bg-gray-800 transition-all shadow-[8px_8px_0px_0px_rgba(0,0,0,0.1)] active:shadow-none active:translate-x-1 active:translate-y-1"
        >
          Connect with GitHub
        </button>
      </div>
    </div>
  );
}

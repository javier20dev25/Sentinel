'use client';

import React, { useEffect, useState } from 'react';
import { createClient } from '@/utils/supabase/client';
import Dashboard from '@/components/Dashboard';
import LandingPage from '@/components/LandingPage';
import { User } from '@supabase/supabase-js';

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const supabase = createClient();

  useEffect(() => {
    const handleAuth = async () => {
      // 1. Verificar si venimos de un login con código (?code=...)
      const queryParams = new URLSearchParams(window.location.search);
      const code = queryParams.get('code');

      if (code) {
        console.log("Detecting authorization code... Exchanging for session.");
        await supabase.auth.exchangeCodeForSession(code);
        // Limpiamos la URL para que no quede el código ahí pegado
        window.history.replaceState({}, document.title, window.location.pathname);
      }

      // 2. Obtener el usuario actual (ya sea porque ya estaba o porque acabamos de canjear el código)
      const { data: { user: currentUser } } = await supabase.auth.getUser();
      setUser(currentUser);
      setLoading(false);

      // 3. Escuchar cambios en tiempo real
      const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
        setUser(session?.user ?? null);
        setLoading(false);
      });

      return () => subscription.unsubscribe();
    };

    handleAuth();
  }, [supabase]);

  if (loading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center font-mono uppercase tracking-[0.5em] text-[10px]">
        <div className="flex flex-col items-center gap-4">
           <div className="w-12 h-[2px] bg-black animate-pulse"></div>
           <span>Orchestrating_Security_Session...</span>
        </div>
      </div>
    );
  }

  if (user) {
    return <Dashboard user={user} />;
  }

  return <LandingPage />;
}

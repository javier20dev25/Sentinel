'use client';

import React, { useEffect, useState } from 'react';
import { createClient } from '@/utils/supabase/client';
import { User } from '@supabase/supabase-js';
import RepoDetailView from '@/components/RepoDetailView';
import { useParams, useRouter } from 'next/navigation';

export default function RepoPage() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const supabase = createClient();
  const params = useParams();
  const router = useRouter();
  const repoId = params.id as string;

  useEffect(() => {
    const checkAuth = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      setUser(session?.user ?? null);
      setLoading(false);
    };

    checkAuth();
  }, [supabase]);

  if (loading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center font-mono uppercase tracking-[0.5em] text-[10px]">
        <div className="flex flex-col items-center gap-4">
           <div className="w-12 h-[2px] bg-black animate-pulse"></div>
           <span>Authenticating_Elite_Operator...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    // Si no está autenticado, redirigir a inicio
    if (typeof window !== 'undefined') {
       router.push('/');
    }
    return null;
  }

  return <RepoDetailView user={user} repoId={repoId} />;
}

import { createClient } from '@/utils/supabase/server';
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  
  // FORZADO DE EMERGENCIA: Siempre volvemos al dominio que funciona
  const canonicalUrl = 'https://sentinel-psi-nine.vercel.app';

  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    
    if (!error) {
      return NextResponse.redirect(`${canonicalUrl}/`);
    }
  }

  return NextResponse.redirect(`${canonicalUrl}/?error=auth_failed`);
}

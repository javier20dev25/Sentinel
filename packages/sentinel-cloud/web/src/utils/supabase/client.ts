import { createBrowserClient } from "@supabase/ssr";

export const createClient = () => {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  // Si no hay llaves (como en el build de CI), devolvemos un cliente dummy
  // o manejamos el error sin que la app explote.
  if (!supabaseUrl || !supabaseKey) {
    console.warn("Sentinel: Supabase credentials missing. Auth will be disabled in this environment.");
    return createBrowserClient("https://placeholder.supabase.co", "placeholder");
  }

  return createBrowserClient(supabaseUrl, supabaseKey);
};

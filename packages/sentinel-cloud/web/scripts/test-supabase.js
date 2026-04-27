import { createClient } from '@supabase/supabase-js';
import 'dotenv/config';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('Missing Supabase environment variables');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

async function testConnection(): Promise<void> {
  console.log('Testing connection to:', supabaseUrl);
  const { data, error } = await supabase.from('repositories').select('*').limit(1);
  
  if (error) {
    console.error('Connection error:', error.message);
  } else {
    console.log('Connection successful! Found', data?.length || 0, 'repos.');
  }
}

testConnection().catch(console.error);

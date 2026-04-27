import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { decrypt } from '@/lib/crypto';
import { analyze } from '@/lib/scanner/ast_inspector';
import { getFileContent } from '@/lib/github';

export async function POST(request: NextRequest) {
  const supabase = await createClient();
  const { data: { session } } = await supabase.auth.getSession();
  
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { logId, repoFullName, filePath } = await request.json();

  try {
    let codeToAnalyze: string | null = null;

    // 1. If we have a logId, try to get decrypted evidence first
    if (logId) {
      const { data: log } = await supabase
        .from('scan_logs')
        .select('evidence_metadata')
        .eq('id', logId)
        .single();
      
      if (log?.evidence_metadata) {
        const metadata = JSON.parse(log.evidence_metadata);
        if (metadata.encrypted) {
          const decrypted = decrypt(metadata.encrypted);
          codeToAnalyze = typeof decrypted === 'string' ? decrypted : JSON.stringify(decrypted, null, 2);
        }
      }
    }

    // 2. If no code from log, fetch from GitHub
    if (!codeToAnalyze && repoFullName && filePath && session.provider_token) {
      codeToAnalyze = await getFileContent(session.provider_token, repoFullName, filePath);
    }

    if (!codeToAnalyze) {
      return NextResponse.json({ error: 'No content found for analysis' }, { status: 404 });
    }

    // 3. Run AST Analysis
    const results = analyze(codeToAnalyze, filePath || 'remote_file.js');

    return NextResponse.json({ 
      success: true, 
      findings: results,
      stats: {
        riskIndex: results.reduce((max, r) => Math.max(max, r.riskLevel || 0), 0)
      }
    });

  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error("Analysis Error:", error);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

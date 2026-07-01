export interface AdaptiveMetadata {
  intent_signature?: string[];
  diversity?: number;
  composite?: boolean;
  signal_pattern?: string[];
}

export interface ForensicFinding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  riskLevel?: number;
  message: string;
  _file?: string;
  description?: string;
  line_number?: number;
  line?: string;
  evidence?: string;
  impact?: string;
  remediation?: string;
  classification?: string;
  occurrences?: number;
  snippet?: string;
  pr_url?: string;
  source_engine?: 'REGEX' | 'AST' | 'HEURISTIC' | string;
  context?: 'PRODUCTION' | 'TEST_FIXTURE' | 'SANDBOX' | string;
  metadata?: AdaptiveMetadata & Record<string, unknown>;
}

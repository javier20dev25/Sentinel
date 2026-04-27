/**
 * Sentinel: Core Type Definitions
 */

export interface GitHubRepo {
  id: number;
  name: string;
  fullName: string;
  description: string;
  visibility: 'PUBLIC' | 'PRIVATE';
  defaultBranch: string;
  url: string;
  updatedAt: string;
  language?: string;
  openIssues: number;
  hasSecretScanning?: boolean;
}

export interface ScanLog {
  id: string;
  repo_id: string;
  event_type: string;
  risk_level: number;
  description: string;
  created_at: string;
  evidence_metadata?: string;
  repositories?: {
    github_full_name: string;
  };
}

export interface ForensicFinding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  riskLevel?: number;
  message: string;
  evidence?: string;
}

export interface AnalysisStats {
  riskIndex: number;
}

export interface AnalysisResponse {
  success: boolean;
  findings: ForensicFinding[];
  stats: AnalysisStats;
}

export interface GitHubPR {
  number: number;
  title: string;
  user: { login: string };
  base: { ref: string };
  head: { ref: string };
  changed_files: number;
  additions: number;
  deletions: number;
  author_association: string;
}

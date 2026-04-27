/**
 * Sentinel: GitHub API Client
 */

import { GitHubRepo } from '@/types';

const GITHUB_API_URL = 'https://api.github.com';

interface GHRawRepo {
  id: number;
  name: string;
  full_name: string;
  description: string;
  private: boolean;
  default_branch: string;
  html_url: string;
  updated_at: string;
  language?: string;
  open_issues_count: number;
}

/**
 * Lists the repositories for the authenticated user
 */
export async function listUserRepos(token: string): Promise<GitHubRepo[]> {
  const response = await fetch(`${GITHUB_API_URL}/user/repos?sort=updated&per_page=100`, {
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd.github.v3+json',
    },
  });

  if (!response.ok) {
    const error = await response.json() as { message?: string };
    throw new Error(error.message || 'Failed to fetch repositories');
  }

  const data = await response.json() as GHRawRepo[];
  return data.map((repo) => ({
    id: repo.id,
    name: repo.name,
    fullName: repo.full_name,
    description: repo.description,
    visibility: repo.private ? 'PRIVATE' : 'PUBLIC',
    defaultBranch: repo.default_branch,
    url: repo.html_url,
    updatedAt: repo.updated_at,
    language: repo.language,
    openIssues: repo.open_issues_count,
  }));
}

/**
 * Fetches the content of a specific file from a repository
 */
export async function getFileContent(token: string, repoFullName: string, filePath: string): Promise<string> {
  const response = await fetch(`${GITHUB_API_URL}/repos/${repoFullName}/contents/${filePath}`, {
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd.github.v3.raw',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch file content: ${filePath}`);
  }

  return response.text();
}

/**
 * Dispatches a GitHub Actions workflow (The Sentinel Sandbox)
 */
export async function dispatchSandbox(token: string, repoFullName: string, inputs: Record<string, string>): Promise<boolean> {
  const response = await fetch(`${GITHUB_API_URL}/repos/${repoFullName}/actions/workflows/sentinel-sandbox.yml/dispatches`, {
    method: 'POST',
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd.github.v3+json',
    },
    body: JSON.stringify({
      ref: 'master', // or the default branch
      inputs,
    }),
  });

  if (!response.ok) {
    const error = await response.json() as { message?: string };
    throw new Error(error.message || 'Failed to dispatch sandbox');
  }

  return true;
}

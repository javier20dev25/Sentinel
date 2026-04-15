import axios from 'axios';

const API_URL = 'http://localhost:3001';

export const api = axios.create({
  baseURL: API_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// Intercept requests to attach JWT
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_jwt');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Intercept responses to handle auth failures
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Do not trigger logout for the login/setup routes themselves
      if (!error.config.url?.includes('/api/auth/local')) {
          localStorage.removeItem('sentinel_jwt');
          window.dispatchEvent(new Event('sentinel-logout'));
      }
    }
    return Promise.reject(error);
  }
);

/**
 * Sentinel 3.0: Sandbox API Helpers
 */
export const sandboxApi = {
  getTemplate: () => api.get('/api/supply/sandbox/template'),
  checkStatus: (owner: string, repo: string) => api.get(`/api/supply/sandbox/check/${owner}/${repo}`),
  trigger: (ownerRepo: string, branch = 'main') => api.post('/api/supply/sandbox/trigger', { ownerRepo, branch }),
  getRunStatus: (owner: string, repo: string, runId: number) => api.get(`/api/supply/sandbox/status/${owner}/${repo}/${runId}`),
  analyze: (ownerRepo: string, runId: number) => api.post('/api/supply/sandbox/analyze', { ownerRepo, runId })
};

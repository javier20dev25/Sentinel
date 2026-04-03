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

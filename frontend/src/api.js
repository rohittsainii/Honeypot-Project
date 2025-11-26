import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

export const getHealth = () => api.get('/health');
export const getStats = () => api.get('/stats');
export const getRecentAttacks = (limit = 50) => api.get(`/attacks/recent?limit=${limit}`);
export const getAttacksByCountry = () => api.get('/attacks/by-country');
export const getMapData = () => api.get('/attacks/map');
export const getTopCredentials = () => api.get('/attacks/credentials');
export const getTopCommands = () => api.get('/attacks/commands');
export const getTimeline = (days = 7) => api.get(`/attacks/timeline?days=${days}`);
export const importLogs = () => api.post('/import-logs');

export default api;
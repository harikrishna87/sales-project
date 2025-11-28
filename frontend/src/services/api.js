import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

export const studentAPI = {
  register: (data) => api.post('/students/register', data),
  login: (data) => api.post('/students/login', data),
  getProfile: () => api.get('/students/profile'),
  updateProfile: (data) => api.put('/students/profile', data),
  deleteProfile: () => api.delete('/students/profile'),
  logout: () => api.post('/students/logout'),
  getAll: () => api.get('/students/all'),
};

export const teacherAPI = {
  register: (data) => api.post('/teachers/register', data),
  login: (data) => api.post('/teachers/login', data),
  getProfile: () => api.get('/teachers/profile'),
  updateProfile: (data) => api.put('/teachers/profile', data),
  deleteProfile: () => api.delete('/teachers/profile'),
  logout: () => api.post('/teachers/logout'),
  getAll: () => api.get('/teachers/all'),
};

export default api;
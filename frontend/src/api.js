import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
});

export default {
  getTeachers() {
    return api.get('/teachers');
  },
  getCourses() {
    return api.get('/courses');
  }
};
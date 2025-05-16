<template>
  <div class="auth-page">
    <Header />
    <div class="auth-container">
      <h2>Вход</h2>
      <form @submit.prevent="login" class="auth-form">
        <div class="form-group">
          <label for="email">Email</label>
          <input 
            v-model="email" 
            type="email" 
            id="email" 
            required
            :disabled="loading"
          >
        </div>
        <div class="form-group">
          <label for="password">Пароль</label>
          <input 
            v-model="password" 
            type="password" 
            id="password" 
            required
            :disabled="loading"
          >
        </div>
        <button type="submit" class="auth-btn" :disabled="loading">
          {{ loading ? 'Загрузка...' : 'Войти' }}
          <span v-if="loading" class="spinner"></span>
        </button>
      </form>
      <p class="auth-link">
        Нет аккаунта? <router-link to="/register">Зарегистрироваться</router-link>
      </p>
    </div>
    <Footer />
  </div>
</template>

<script>
import Header from '@/components/Header.vue'
import Footer from '@/components/Footer.vue'

export default {
  components: {
    Header,
    Footer
  },
  data() {
    return {
      email: '',
      password: '',
      loading: false
    }
  },
  methods: {
    async login() {
      this.loading = true;

      try {
        const response = await fetch('http://localhost:3001/api/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            email: this.email,
            password: this.password
          })
        });

        const contentType = response.headers.get('content-type');
        let data;

        if (contentType && contentType.includes('application/json')) {
          data = await response.json();
        } else {
          const text = await response.text();
          throw new Error('Ошибка сервера: получены некорректные данные (' + text + ')');
        }

        if (!response.ok) {
          throw new Error(data.message || 'Ошибка входа');
        }

        // Сохраняем токен в localStorage
        localStorage.setItem('token', data.token);

        // Обновляем состояние пользователя в Vuex
        this.$store.dispatch('checkAuth');

        // Перенаправляем на главную страницу
        this.$router.push('/');
      } catch (error) {
        console.error('Ошибка входа:', error);
        alert(error.message || 'Произошла ошибка при входе');
      } finally {
        this.loading = false;
      }
    }
  }
}
</script>

<style scoped>
.auth-page {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.auth-container {
  max-width: 400px;
  margin: 2rem auto;
  padding: 2rem;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  flex-grow: 1;
}

h2 {
  text-align: center;
  margin-bottom: 1.5rem;
  color: #2c3e50;
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

label {
  font-weight: 500;
  color: #2c3e50;
}

input {
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  transition: border-color 0.3s;
}

input:focus {
  border-color: #42b983;
  outline: none;
}

.auth-btn {
  position: relative;
  padding: 0.75rem;
  background-color: #42b983;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  transition: background-color 0.3s;
  display: flex;
  justify-content: center;
  align-items: center;
}

.auth-btn:hover:not(:disabled) {
  background-color: #369f6b;
}

.auth-btn:disabled {
  background-color: #a8d8b9;
  cursor: not-allowed;
}

.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid #fff;
  border-top-color: transparent;
  border-radius: 50%;
  margin-left: 10px;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.auth-link {
  text-align: center;
  margin-top: 1rem;
  color: #666;
}

.auth-link a {
  color: #42b983;
  text-decoration: none;
}

.auth-link a:hover {
  text-decoration: underline;
}
</style>
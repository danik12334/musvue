import './assets/css/global.css' // Подключаем зелёную тему

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import store from './store'

const app = createApp(App)

app.use(router)
app.use(store)

// Запуск проверки авторизации при старте
store.dispatch('checkAuth')

// Глобальная проверка аутентификации
router.beforeEach(async (to, from, next) => {
  const publicPages = ['/login', '/register']
  const authRequired = !publicPages.includes(to.path)
  const token = localStorage.getItem('token')

  if (authRequired && !token) {
    return next('/login')
  }

  if (token) {
    try {
      const response = await fetch('https://musvue.onrender.com/api/me', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (!response.ok) {
        localStorage.removeItem('token')
        store.commit('logout')
        return next('/login')
      }
    } catch (error) {
      console.error('Ошибка проверки токена:', error)
      localStorage.removeItem('token')
      store.commit('logout')
      return next('/login')
    }
  }

  next()
})

app.mount('#app')

console.log('Приложение инициализировано')

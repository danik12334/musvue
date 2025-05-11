<template>
  <header>
    <div class="school-info">
      <h1>Музыкальная школа "Аккорд"</h1>
    </div>
    <nav>
      <!-- Основные ссылки -->
      <div class="left-links">
        <router-link to="/">Главная</router-link>
        <router-link to="/about">О нас</router-link>
        <router-link to="/contacts">Контакты</router-link>
        <router-link to="/teachers">Преподаватели</router-link>
        <router-link to="/courses">Курсы</router-link>
      </div>

      <!-- Правая часть -->
      <div class="right-side">
        <div class="user-info" v-if="user">
          <span>
            {{ user.name }}
          <button @click="logout">Выйти</button>
          </span>
        </div>

        <div class="auth-buttons" v-else>
          <router-link to="/login">Вход</router-link>
          <router-link to="/register">Регистрация</router-link>
        </div>
      </div>
    </nav>
  </header>
</template>

<script>
import { mapState, mapActions } from 'vuex'

export default {
  computed: {
    ...mapState(['user'])
  },
  methods: {
    ...mapActions(['logout'])
  }
}
</script>

<style scoped>
header {
  background-color: var(--secondary-color);
  color: white;
  padding: 1rem;
}

.school-info h1 {
  margin: 0;
  text-align: center;
  font-size: 2rem;
}

nav {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 0;
  flex-wrap: wrap;
}

.left-links {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.right-side {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.user-info span {
  font-size: 0.95rem;
  display: flex;
  align-items: center;
  gap: 0.3rem;
}

.admin-badge {
  font-size: 1.1rem;
  color: gold;
  vertical-align: middle;
}



.auth-buttons a {
  font-size: 0.9rem;
}
</style>
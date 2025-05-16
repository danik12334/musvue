import { createStore } from 'vuex'

export default createStore({
  state: {
    user: null,
    isAdmin: false
  },
  mutations: {
    setUser(state, user) {
      state.user = user
      // Теперь isAdmin берётся напрямую из пользователя
      state.isAdmin = Boolean(user?.isAdmin)
    },
    logout(state) {
      state.user = null
      state.isAdmin = false
    }
  },
  actions: {
    login({ commit }, user) {
      commit('setUser', user)
    },
    async checkAuth({ commit }) {
      const token = localStorage.getItem('token');
      if (!token) return;

      try {
        const response = await fetch('http://localhost:3001/api/me', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });

        if (response.ok) {
          const user = await response.json();
          commit('setUser', user);
        } else {
          commit('logout');
        }
      } catch (error) {
        console.error('Ошибка проверки токена:', error);
        commit('logout');
      }
    },
    logout({ commit }) {
      localStorage.removeItem('token');
      commit('logout');
    }
  }
})
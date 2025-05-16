<template>
  <div class="teacher-view">
    <Header />
    <h2>Просмотр преподавателя</h2>
    
    <div class="teacher-details">
      <div class="detail">
        <span class="label">ID:</span>
        <span class="value">{{ teacher.id }}</span>
      </div>

      <div class="detail">
        <span class="label">Фамилия:</span>
        <span class="value">{{ teacher.last_name }}</span>
      </div>

      <div class="detail">
        <span class="label">Имя:</span>
        <span class="value">{{ teacher.first_name }}</span>
      </div>

      <div class="detail">
        <span class="label">Отчество:</span>
        <span class="value">{{ teacher.patronymic || '-' }}</span>
      </div>

      <div class="detail">
        <span class="label">Предмет:</span>
        <span class="value">{{ teacher.subject }}</span>
      </div>

      <div class="detail">
        <span class="label">Стаж:</span>
        <span class="value">{{ teacher.experience }} лет</span>
      </div>

      <div class="detail">
        <span class="label">Образование:</span>
        <span class="value">{{ teacher.education }}</span>
      </div>

      <div class="detail">
        <span class="label">Телефон:</span>
        <span class="value">{{ teacher.contact_phone }}</span>
      </div>

      <div class="detail">
        <span class="label">Email:</span>
        <span class="value">{{ teacher.email }}</span>
      </div>

      <div class="detail">
        <span class="label">Фото:</span>
        <span class="value">{{ teacher.photo_url || '-' }}</span>
      </div>
    </div>
    
    <div class="actions">
      <button @click="goBack" class="back-btn">Назад к списку</button>
    </div>
    <Footer />
  </div>
</template>

<script>
import Header from '@/components/Header.vue'
import Footer from '@/components/Footer.vue'

export default {
  components: { Header, Footer },
  data() {
    return {
      teacher: {}
    }
  },
  async created() {
    await this.loadTeacher()
  },
  methods: {
    async loadTeacher() {
      try {
        const response = await fetch(`https://musvue.onrender.com/api/teachers/${this.$route.params.id}`)
        this.teacher = await response.json()
      } catch (error) {
        console.error('Ошибка загрузки:', error)
        alert('Не удалось загрузить данные преподавателя')
      }
    },
    goBack() {
      this.$router.push('/teachers')
    }
  }
}
</script>

<style scoped>
.teacher-view {
  padding: 20px;
  max-width: 100%;
  margin: 0 auto;
}

.teacher-details {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  margin-bottom: 20px;
}

.detail {
  margin-bottom: 15px;
}

.label {
  font-weight: bold;
  color: #555;
  display: inline-block;
  width: 150px;
}

.value {
  color: #333;
}

.actions {
  display: flex;
  justify-content: flex-end;
}

.back-btn {
  background-color: #607d8b;
  color: white;
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 16px;
}
</style>

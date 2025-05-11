<template>
  <div class="teacher-form">
    <Header />
    <h2>{{ mode === 'add' ? 'Добавить преподавателя' : 'Редактировать преподавателя' }}</h2>
    
    <form @submit.prevent="handleSubmit" class="form-container">
      <div class="form-row">
        <div class="form-group">
          <label>Фамилия</label>
          <input v-model="form.last_name" required>
        </div>
        <div class="form-group">
          <label>Имя</label>
          <input v-model="form.first_name" required>
        </div>
        <div class="form-group">
          <label>Отчество</label>
          <input v-model="form.patronymic">
        </div>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Предмет</label>
          <input v-model="form.subject" required>
        </div>
        <div class="form-group">
          <label>Стаж (лет)</label>
          <input v-model="form.experience" type="number" required>
        </div>
      </div>

      <div class="form-group">
        <label>Образование</label>
        <input v-model="form.education" required>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Телефон</label>
          <input v-model="form.contact_phone" required>
        </div>
        <div class="form-group">
          <label>Email</label>
          <input v-model="form.email" type="email" required>
        </div>
      </div>

      <div class="form-group">
        <label>Путь к фото</label>
        <input v-model="form.photo_url" placeholder="Например: /images/teacher1.jpg">
      </div>

      <div class="form-actions">
        <button type="submit" class="submit-btn">
          {{ mode === 'add' ? 'Добавить' : 'Сохранить' }}
        </button>
        <button type="button" @click="cancel" class="cancel-btn">
          Отмена
        </button>
      </div>
    </form>
    <Footer />
  </div>
</template>

<script>
import Header from '@/components/Header.vue'
import Footer from '@/components/Footer.vue'

export default {
  components: { Header, Footer },
  props: {
    mode: {
      type: String,
      required: true,
      validator: value => ['add', 'edit'].includes(value)
    }
  },
  data() {
    return {
      form: {
        last_name: '',
        first_name: '',
        patronymic: '',
        subject: '',
        experience: '',
        education: '',
        contact_phone: '',
        email: '',
        photo_url: ''
      }
    }
  },
  async created() {
    if (this.mode === 'edit') {
      await this.loadTeacherData()
    }
  },
  methods: {
    async loadTeacherData() {
      try {
        const response = await fetch(`http://localhost:3001/api/teachers/${this.$route.params.id}`)
        const data = await response.json()
        this.form = data
      } catch (error) {
        console.error('Ошибка загрузки:', error)
        alert('Не удалось загрузить данные преподавателя')
      }
    },
    async handleSubmit() {
      try {
        const url = this.mode === 'add' 
          ? 'http://localhost:3001/api/teachers'
          : `http://localhost:3001/api/teachers/${this.$route.params.id}`
          
        const method = this.mode === 'add' ? 'POST' : 'PUT'
        
        const response = await fetch(url, {
          method,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify(this.form)
        })
        
        if (!response.ok) throw new Error('Ошибка сохранения')
        
        this.$router.push('/teachers')
      } catch (error) {
        console.error('Ошибка:', error)
        alert('Ошибка при сохранении данных')
      }
    },
    cancel() {
      this.$router.push('/teachers')
    }
  }
}
</script>

<style scoped>
.teacher-form {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.form-container {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.form-row {
  display: flex;
  gap: 20px;
  margin-bottom: 15px;
}

.form-group {
  flex: 1;
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
}

.form-group input {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 16px;
}

.form-actions {
  margin-top: 30px;
  display: flex;
  gap: 15px;
  justify-content: flex-end;
}

.submit-btn {
  background-color: #4CAF50;
  color: white;
  padding: 12px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 16px;
}

.cancel-btn {
  background-color: #f44336;
  color: white;
  padding: 12px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 16px;
}
</style>
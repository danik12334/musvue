<template>
  <div class="course-form">
    <Header />
    <h2>{{ mode === 'add' ? 'Добавить курс' : 'Редактировать курс' }}</h2>
    
    <form @submit.prevent="handleSubmit" class="form-container">
      <div class="form-row">
        <div class="form-group">
          <label>ID преподавателя</label>
          <input v-model="form.teacher_id" type="number" required>
        </div>
        <div class="form-group">
          <label>Название курса</label>
          <input v-model="form.course_name" required>
        </div>
      </div>

      <div class="form-group">
        <label>Описание</label>
        <textarea v-model="form.description" required></textarea>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Преподаватель</label>
          <input v-model="form.teacher_full_name" required>
        </div>
        <div class="form-group">
          <label>Цена</label>
          <input v-model="form.price" type="number" step="0.01" required>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Длительность</label>
          <input v-model="form.duration" required>
        </div>
        <div class="form-group">
          <label>Уровень</label>
          <select v-model="form.level" required>
            <option value="beginner">Начинающий</option>
            <option value="intermediate">Средний</option>
            <option value="advanced">Продвинутый</option>
          </select>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Дата начала</label>
          <input v-model="form.start_date" type="date" required>
        </div>
        <div class="form-group">
          <label>Количество записей</label>
          <input v-model="form.enrollment_count" type="number">
        </div>
      </div>

      <div class="form-group">
        <label>Путь к фото</label>
        <input v-model="form.photo_url" placeholder="Например: /images/course1.jpg">
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
        teacher_id: '',
        course_name: '',
        description: '',
        teacher_full_name: '',
        price: '',
        duration: '',
        level: 'beginner',
        start_date: '',
        enrollment_count: 0,
        photo_url: ''
      }
    }
  },
  async created() {
    if (this.mode === 'edit') {
      await this.loadCourseData()
    }
  },
  methods: {
    async loadCourseData() {
      try {
        const response = await fetch(`http://localhost:3001/api/courses/${this.$route.params.id}`)
        const data = await response.json()
        this.form = data
      } catch (error) {
        console.error('Ошибка загрузки:', error)
        alert('Не удалось загрузить данные курса')
      }
    },
    async handleSubmit() {
      try {
        const url = this.mode === 'add' 
          ? 'http://localhost:3001/api/courses'
          : `http://localhost:3001/api/courses/${this.$route.params.id}`
          
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
        
        this.$router.push('/courses')
      } catch (error) {
        console.error('Ошибка:', error)
        alert('Ошибка при сохранении данных')
      }
    },
    cancel() {
      this.$router.push('/courses')
    }
  }
}
</script>

<style scoped>
.course-form {
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

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 16px;
}

.form-group textarea {
  min-height: 100px;
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
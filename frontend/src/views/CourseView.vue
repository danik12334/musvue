<template>
  <div class="course-view">
    <Header />
    <h2>Просмотр курса</h2>
    
    <div class="course-details">
      <div class="detail">
        <span class="label">ID:</span>
        <span class="value">{{ course.id }}</span>
      </div>

      <div class="detail">
        <span class="label">ID преподавателя:</span>
        <span class="value">{{ course.teacher_id }}</span>
      </div>

      <div class="detail">
        <span class="label">Название:</span>
        <span class="value">{{ course.course_name }}</span>
      </div>

      <div class="detail">
        <span class="label">Описание:</span>
        <span class="value">{{ course.description }}</span>
      </div>

      <div class="detail">
        <span class="label">Преподаватель:</span>
        <span class="value">{{ course.teacher_full_name }}</span>
      </div>

      <div class="detail">
        <span class="label">Цена:</span>
        <span class="value">{{ course.price }} руб.</span>
      </div>

      <div class="detail">
        <span class="label">Длительность:</span>
        <span class="value">{{ course.duration }}</span>
      </div>

      <div class="detail">
        <span class="label">Уровень:</span>
        <span class="value">{{ getLevelName(course.level) }}</span>
      </div>

      <div class="detail">
        <span class="label">Дата начала:</span>
        <span class="value">{{ formatDate(course.start_date) }}</span>
      </div>

      <div class="detail">
        <span class="label">Записей:</span>
        <span class="value">{{ course.enrollment_count || 0 }}</span>
      </div>

      <div class="detail">
        <span class="label">Фото:</span>
        <span class="value">{{ course.photo_url || '-' }}</span>
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
      course: {}
    }
  },
  async created() {
    await this.loadCourse()
  },
  methods: {
    async loadCourse() {
      try {
        const response = await fetch(`http://localhost:3001/api/courses/${this.$route.params.id}`)
        this.course = await response.json()
      } catch (error) {
        console.error('Ошибка загрузки:', error)
        alert('Не удалось загрузить данные курса')
      }
    },
    getLevelName(level) {
      const levels = {
        beginner: 'Начинающий',
        intermediate: 'Средний',
        advanced: 'Продвинутый'
      }
      return levels[level] || level
    },
    formatDate(dateString) {
      if (!dateString) return '-'
      const date = new Date(dateString)
      return date.toLocaleDateString('ru-RU')
    },
    goBack() {
      this.$router.push('/courses')
    }
  }
}
</script>

<style scoped>
.course-view {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.course-details {
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
  width: 180px;
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
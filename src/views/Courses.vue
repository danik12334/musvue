<template>
  <div class="courses-page">
    <!-- Шапка -->
    <Header />
    <h2>Курсы</h2>
    <!-- Верхняя панель управления -->
    <div class="control-panel top-panel">
      <div class="search-section">
        <input 
          v-model="searchId" 
          type="number" 
          placeholder="Поиск по ID"
          @input="searchCourse"
          class="search-input"
        >
        <button @click="resetSearch" class="control-btn reset-btn">Сбросить</button>
      </div>
      <div class="view-options">
        <button @click="toggleShowAll" class="control-btn toggle-btn">
          {{ showAll ? 'Скрыть поля' : 'Показать все поля' }}
        </button>
        <button 
          @click="addCourse" 
          class="control-btn add-btn"
          v-if="isUserAdmin()"
        >
          + Добавить
        </button>
      </div>
    </div>
    <!-- Таблица -->
    <div class="table-wrapper">
      <table class="grid-table">
        <thead>
          <tr>
            <th v-for="header in visibleHeaders" :key="header.key">
              {{ header.title }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="course in paginatedCourses" :key="course.id">
            <td v-for="header in visibleHeaders" :key="header.key">
              <template v-if="header.key === 'photo_url'">
                <img v-if="course[header.key]" :src="course[header.key]" class="course-photo">
                <span v-else>-</span>
              </template>
              <template v-else-if="header.key === 'actions'">
                <div class="action-buttons">
                  <button @click="showFullInfo(course)" class="action-btn view-btn">👁️</button>
                  <button 
                    @click="editCourse(course.id)" 
                    class="action-btn edit-btn"
                    v-if="isUserAdmin()"
                  >
                    ✏️
                  </button>
                  <button 
                    @click="confirmDelete(course.id)" 
                    class="action-btn delete-btn"
                    v-if="isUserAdmin()"
                  >
                    🗑️
                  </button>
                </div>
              </template>
              <template v-else>
                {{ course[header.key] || '-' }}
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <!-- Нижняя панель пагинации -->
    <div class="control-panel bottom-panel">
      <div class="pagination-info">
        Показано {{ paginatedCourses.length }} из {{ filteredCourses.length }}
      </div>
      <div class="pagination-controls">
        <button 
          @click="prevPage" 
          :disabled="currentPage === 1" 
          class="control-btn pagination-btn"
        >
          ◀
        </button>
        <div class="page-numbers">
          <span class="current-page">{{ currentPage }}</span>
          <span class="total-pages">из {{ totalPages }}</span>
        </div>
        <button 
          @click="nextPage" 
          :disabled="currentPage === totalPages" 
          class="control-btn pagination-btn"
        >
          ▶
        </button>
      </div>
    </div>
    <!-- Диалог подтверждения удаления -->
    <div v-if="showDeleteDialog" class="dialog-overlay">
      <div class="dialog-box">
        <h3>Подтверждение удаления</h3>
        <p>Вы уверены, что хотите удалить курс с ID {{ courseToDelete }}?</p>
        <div class="dialog-buttons">
          <button @click="deleteCourse" class="dialog-btn confirm-btn">Удалить</button>
          <button @click="cancelDelete" class="dialog-btn cancel-btn">Отмена</button>
        </div>
      </div>
    </div>
    <!-- Подвал -->
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
      courses: [],
      filteredCourses: [],
      showAll: false,
      searchId: null,
      currentPage: 1,
      itemsPerPage: 10,
      showDeleteDialog: false,
      courseToDelete: null,
      currentUserEmail: '',
      adminEmails: ['admin@melody.ru', 'testuser@mail.ru'],
      tableHeaders: [
        { key: 'id', title: 'ID', alwaysVisible: true },
        { key: 'teacher_id', title: 'ID преподавателя', alwaysVisible: true },
        { key: 'course_name', title: 'Название', alwaysVisible: true },
        { key: 'description', title: 'Описание', alwaysVisible: true },
        { key: 'teacher_full_name', title: 'Преподаватель', alwaysVisible: false },
        { key: 'price', title: 'Цена', alwaysVisible: false },
        { key: 'duration', title: 'Длительность', alwaysVisible: false },
        { key: 'level', title: 'Уровень', alwaysVisible: false },
        { key: 'start_date', title: 'Дата начала', alwaysVisible: false },
        { key: 'enrollment_count', title: 'Записей', alwaysVisible: false },
        { key: 'photo_url', title: 'Фото', alwaysVisible: true },
        { key: 'actions', title: 'Действия', alwaysVisible: true }
      ]
    }
  },
  computed: {
    visibleHeaders() {
      return this.tableHeaders.filter(header => 
        header.alwaysVisible || this.showAll
      )
    },
    totalPages() {
      return Math.ceil(this.filteredCourses.length / this.itemsPerPage)
    },
    paginatedCourses() {
      const start = (this.currentPage - 1) * this.itemsPerPage
      const end = start + this.itemsPerPage
      return this.filteredCourses.slice(start, end)
    }
  },
  async created() {
    await this.loadUserData()
    await this.loadCourses()
  },
  methods: {
    async loadUserData() {
      try {
        const token = localStorage.getItem('token')
        if (!token) return
        const response = await fetch('http://localhost:3001/api/me', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
        if (response.ok) {
          const user = await response.json()
          this.currentUserEmail = user.email
          console.log('Текущий пользователь:', this.currentUserEmail)
        }
      } catch (error) {
        console.error('Ошибка загрузки данных пользователя:', error)
      }
    },
    isUserAdmin() {
      return this.adminEmails.includes(this.currentUserEmail)
    },
    async loadCourses() {
      try {
        const response = await fetch('http://localhost:3001/api/courses')
        if (!response.ok) throw new Error('Ошибка загрузки')
        this.courses = await response.json()
        this.filteredCourses = [...this.courses]
      } catch (error) {
        console.error('Ошибка загрузки:', error)
        this.$toast.error('Не удалось загрузить данные курсов')
      }
    },
    toggleShowAll() {
      this.showAll = !this.showAll
    },
    searchCourse() {
      if (!this.searchId) {
        this.filteredCourses = [...this.courses]
        return
      }
      this.filteredCourses = this.courses.filter(
        course => course.id == this.searchId
      )
      this.currentPage = 1
    },
    resetSearch() {
      this.searchId = null
      this.filteredCourses = [...this.courses]
      this.currentPage = 1
    },
    nextPage() {
      if (this.currentPage < this.totalPages) {
        this.currentPage++
      }
    },
    prevPage() {
      if (this.currentPage > 1) {
        this.currentPage--
      }
    },
    showFullInfo(course) {
      this.$router.push(`/courses/view/${course.id}`)
    },
    editCourse(id) {
      this.$router.push(`/courses/edit/${id}`)
    },
    confirmDelete(id) {
      this.courseToDelete = id
      this.showDeleteDialog = true
    },
    cancelDelete() {
      this.showDeleteDialog = false
      this.courseToDelete = null
    },
    async deleteCourse() {
      try {
        const token = localStorage.getItem('token')
        const response = await fetch(`http://localhost:3001/api/courses/${this.courseToDelete}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
        if (!response.ok) throw new Error('Ошибка удаления')
        this.$toast.success('Курс успешно удален')
        await this.loadCourses()
      } catch (error) {
        console.error('Ошибка удаления:', error)
        this.$toast.error('Не удалось удалить курс')
      } finally {
        this.cancelDelete()
      }
    },
    addCourse() {
      this.$router.push('/courses/add')
    }
  }
}
</script>

<style scoped>
.courses-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 20px;
  max-width: 100%;
}
h2 {
  text-align: center;
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
}
.control-panel {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  background-color: #f8f9fa;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
.top-panel {
  margin-bottom: 10px;
}
.bottom-panel {
  margin-top: 10px;
}
.search-section {
  display: flex;
  gap: 10px;
  align-items: center;
}
.search-input {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  min-width: 150px;
}
.view-options {
  display: flex;
  gap: 10px;
}
.control-btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}
.reset-btn {
  background-color: #f1f1f1;
  color: #333;
}
.reset-btn:hover {
  background-color: #e0e0e0;
}
.toggle-btn {
  background-color: #e3f2fd;
  color: #1976d2;
}
.toggle-btn:hover {
  background-color: #bbdefb;
}
.add-btn {
  background-color: #e8f5e9;
  color: #2e7d32;
}
.add-btn:hover {
  background-color: #c8e6c9;
}
.pagination-btn {
  background-color: #f5f5f5;
  color: #333;
  min-width: 40px;
}
.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.pagination-btn:hover:not(:disabled) {
  background-color: #e0e0e0;
}
.table-wrapper {
  width: 100%;
  overflow-x: auto;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
.grid-table {
  width: 100%;
  border-collapse: collapse;
}
.grid-table th, 
.grid-table td {
  padding: 12px 15px;
  text-align: left;
  border: 1px solid #e0e0e0;
}
.grid-table th {
  background-color: #f5f5f5;
  font-weight: 600;
  position: sticky;
  top: 0;
}
.grid-table tr:nth-child(even) {
  background-color: #f9f9f9;
}
.grid-table tr:hover {
  background-color: #f1f1f1;
}
.course-photo {
  width: 100px;
  height: 100px;
  object-fit: cover;
  border-radius: 4px;
}
.action-buttons {
  display: flex;
  gap: 5px;
  justify-content: center;
}
.action-btn {
  padding: 5px 10px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 16px;
  transition: all 0.2s;
}
.view-btn {
  background-color: #e3f2fd;
  color: #1976d2;
}
.view-btn:hover {
  background-color: #bbdefb;
}
.edit-btn {
  background-color: #fff8e1;
  color: #ff8f00;
}
.edit-btn:hover {
  background-color: #ffecb3;
}
.delete-btn {
  background-color: #ffebee;
  color: #d32f2f;
}
.delete-btn:hover {
  background-color: #ffcdd2;
}
.pagination-info {
  font-size: 14px;
  color: #666;
}
.pagination-controls {
  display: flex;
  align-items: center;
  gap: 15px;
}
.page-numbers {
  display: flex;
  flex-direction: column;
  align-items: center;
  line-height: 1.2;
}
.current-page {
  font-weight: bold;
  font-size: 18px;
}
.total-pages {
  font-size: 12px;
  color: #666;
}
@media (max-width: 768px) {
  .control-panel {
    flex-direction: column;
    gap: 10px;
  }
  .search-section, 
  .view-options {
    width: 100%;
  }
  .search-input {
    flex-grow: 1;
  }
  .grid-table th, 
  .grid-table td {
    padding: 8px 10px;
    font-size: 14px;
  }
}
</style>
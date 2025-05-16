<template>
  <div class="teachers-page">
    <!-- Шапка -->
    <Header />
    <h2>Преподаватели</h2>
    <!-- Верхняя панель управления -->
    <div class="control-panel top-panel">
      <div class="search-section">
        <input 
          v-model="searchId" 
          type="number" 
          placeholder="Поиск по ID"
          @input="searchTeacher"
          class="search-input"
        >
        <button @click="resetSearch" class="control-btn reset-btn">Сбросить</button>
      </div>
      <div class="view-options">
        <button @click="toggleShowAll" class="control-btn toggle-btn">
          {{ showAll ? 'Скрыть поля' : 'Показать все поля' }}
        </button>
        <button 
          @click="addTeacher" 
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
          <tr v-for="teacher in paginatedTeachers" :key="teacher.id">
            <td v-for="header in visibleHeaders" :key="header.key">
              <template v-if="header.key === 'photo_url'">
                <img v-if="teacher[header.key]" :src="teacher[header.key]" class="teacher-photo">
                <span v-else>-</span>
              </template>
              <template v-else-if="header.key === 'actions'">
                <div class="action-buttons">
                  <button @click="showFullInfo(teacher)" class="action-btn view-btn">👁️</button>
                  <button 
                    @click="editTeacher(teacher.id)" 
                    class="action-btn edit-btn"
                    v-if="isUserAdmin()"
                  >
                    ✏️
                  </button>
                  <button 
                    @click="confirmDelete(teacher.id)" 
                    class="action-btn delete-btn"
                    v-if="isUserAdmin()"
                  >
                    🗑️
                  </button>
                </div>
              </template>
              <template v-else>
                {{ teacher[header.key] || '-' }}
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <!-- Нижняя панель пагинации -->
    <div class="control-panel bottom-panel">
      <div class="pagination-info">
        Показано {{ paginatedTeachers.length }} из {{ filteredTeachers.length }}
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
        <p>Вы уверены, что хотите удалить преподавателя с ID {{ teacherToDelete }}?</p>
        <div class="dialog-buttons">
          <button @click="deleteTeacher" class="dialog-btn confirm-btn">Удалить</button>
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
      teachers: [],
      filteredTeachers: [],
      showAll: false,
      searchId: null,
      currentPage: 1,
      itemsPerPage: 10,
      showDeleteDialog: false,
      teacherToDelete: null,
      currentUserEmail: '',
      adminEmails: ['admin@melody.ru', 'testuser@mail.ru'], // Жестко прописанные админы
      tableHeaders: [
        { key: 'id', title: 'ID', alwaysVisible: true },
        { key: 'last_name', title: 'Фамилия', alwaysVisible: true },
        { key: 'first_name', title: 'Имя', alwaysVisible: true },
        { key: 'patronymic', title: 'Отчество', alwaysVisible: true },
        { key: 'subject', title: 'Предмет', alwaysVisible: true },
        { key: 'experience', title: 'Стаж', alwaysVisible: false },
        { key: 'education', title: 'Образование', alwaysVisible: false },
        { key: 'contact_phone', title: 'Телефон', alwaysVisible: false },
        { key: 'email', title: 'Email', alwaysVisible: false },
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
      return Math.ceil(this.filteredTeachers.length / this.itemsPerPage)
    },
    paginatedTeachers() {
      const start = (this.currentPage - 1) * this.itemsPerPage
      const end = start + this.itemsPerPage
      return this.filteredTeachers.slice(start, end)
    }
  },
  async created() {
    await this.loadUserData()
    await this.loadTeachers()
  },
  methods: {
    async loadUserData() {
      try {
        const token = localStorage.getItem('token')
        if (!token) return
        const response = await fetch('https://musvue.onrender.com/api/me', {
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
    async loadTeachers() {
      try {
        const response = await fetch('https://musvue.onrender.com/api/teachers')
        if (!response.ok) throw new Error('Ошибка загрузки')
        this.teachers = await response.json()
        this.filteredTeachers = [...this.teachers]
      } catch (error) {
        console.error('Ошибка загрузки:', error)
        this.$toast.error('Не удалось загрузить данные преподавателей')
      }
    },
    toggleShowAll() {
      this.showAll = !this.showAll
    },
    searchTeacher() {
      if (!this.searchId) {
        this.filteredTeachers = [...this.teachers]
        return
      }
      this.filteredTeachers = this.teachers.filter(
        teacher => teacher.id == this.searchId
      )
      this.currentPage = 1
    },
    resetSearch() {
      this.searchId = null
      this.filteredTeachers = [...this.teachers]
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
    showFullInfo(teacher) {
      this.$router.push(`/teachers/view/${teacher.id}`)
    },
    editTeacher(id) {
      this.$router.push(`/teachers/edit/${id}`)
    },
    confirmDelete(id) {
      this.teacherToDelete = id
      this.showDeleteDialog = true
    },
    cancelDelete() {
      this.showDeleteDialog = false
      this.teacherToDelete = null
    },
    async deleteTeacher() {
      try {
        const token = localStorage.getItem('token')
        const response = await fetch(`https://musvue.onrender.com/api/teachers/${this.teacherToDelete}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
        if (!response.ok) throw new Error('Ошибка удаления')
        this.$toast.success('Преподаватель успешно удален')
        await this.loadTeachers()
      } catch (error) {
        console.error('Ошибка удаления:', error)
        this.$toast.error('Не удалось удалить преподавателя')
      } finally {
        this.cancelDelete()
      }
    },
    addTeacher() {
      this.$router.push('/teachers/add')
    }
  }
}
</script>

<style scoped>
.teachers-page {
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
.teacher-photo {
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
.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0,0,0,0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}
.dialog-box {
  background-color: white;
  padding: 20px;
  border-radius: 8px;
  max-width: 400px;
  width: 90%;
}
.dialog-box h3 {
  margin-top: 0;
  color: #d32f2f;
}
.dialog-buttons {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 20px;
}
.dialog-btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
}
.confirm-btn {
  background-color: #d32f2f;
  color: white;
}
.confirm-btn:hover {
  background-color: #b71c1c;
}
.cancel-btn {
  background-color: #f5f5f5;
  color: #333;
}
.cancel-btn:hover {
  background-color: #e0e0e0;
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

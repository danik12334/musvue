<template>
  <div class="contacts">
    <Header />

    <!-- Описание страницы -->
    <section class="page-description">
      <h2>Наши преподаватели</h2>
      <p>
        Наши педагоги — это профессионалы с высшим образованием, большим опытом работы и любовью к музыке.
        Каждый ученик получает индивидуальный подход и поддержку на пути к музыкальной мечте.
      </p>
    </section>

    <!-- Сетка преподавателей -->
    <section class="teachers">
      <div class="teachers-grid">
        <div class="teacher-card" v-for="(teacher, index) in teachers" :key="index">
          <img :src="teacher.photo" :alt="teacher.name">
          <h3>{{ teacher.name }}</h3>
          <p>{{ teacher.instrument }}</p>
          <p>Стаж: {{ teacher.experience }} лет</p>
        </div>
      </div>
    </section>

    <!-- Контактная информация -->
    <section class="contact-info">
      <h2>Свяжитесь с нами</h2>
      <p>
        Хотите задать вопрос или записаться на занятие? Мы всегда на связи и готовы помочь!
      </p>
    </section>

    <Footer />
  </div>
</template>

<script>
// Импортируем фотографии преподавателей
import teacher1 from '@/assets/images/teacher1.jpg'
import teacher2 from '@/assets/images/teacher2.jpg'
import teacher3 from '@/assets/images/teacher3.jpg'
import teacher4 from '@/assets/images/teacher4.jpg'
import teacher5 from '@/assets/images/teacher5.jpg'
import teacher6 from '@/assets/images/teacher6.jpg'

// Импортируем компоненты Header и Footer
import Header from '@/components/Header.vue'
import Footer from '@/components/Footer.vue'

export default {
  components: {
    Header,
    Footer
  },
  data() {
    return {
      teachers: [
        {
          name: 'Иван Петров',
          instrument: 'Гитара',
          experience: 10,
          photo: teacher1
        },
        {
          name: 'Мария Смирнова',
          instrument: 'Фортепиано',
          experience: 12,
          photo: teacher2
        },
        {
          name: 'Алексей Кузнецов',
          instrument: 'Скрипка',
          experience: 8,
          photo: teacher3
        },
        {
          name: 'Екатерина Иванова',
          instrument: 'Вокал',
          experience: 9,
          photo: teacher4
        },
        {
          name: 'Дмитрий Соколов',
          instrument: 'Бас-гитара',
          experience: 7,
          photo: teacher5
        },
        {
          name: 'Ольга Лебедева',
          instrument: 'Флейта',
          experience: 6,
          photo: teacher6
        }
      ]
    }
  }
}
</script>

<style scoped>
.contacts {
  margin: 0;
  padding: 0;
}

/* === Описание страницы === */
.page-description {
  max-width: 900px;
  margin: 2rem auto;
  padding: 0 10%;
  text-align: center;
  line-height: 1.7;
  color: #333;
}

.page-description h2 {
  font-size: 1.8rem;
  margin-bottom: 1rem;
  color: #2e7d32;
}

.page-description p {
  font-size: 1.05rem;
  margin-bottom: 1.2rem;
}

/* === Преподаватели === */
.teachers {
  padding: 0 10%;
  margin-bottom: 2rem;
}

.teachers-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 2rem;
  justify-items: center;
}

.teacher-card {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 1rem;
  background-color: #fafafa;
  text-align: center;
  transition: box-shadow 0.3s ease;
}

.teacher-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.teacher-card img {
  max-width: 100%;
  height: auto;
  border-radius: 50%;
  margin-bottom: 1rem;
}

.teacher-card h3 {
  font-size: 1.1rem;
  margin: 0.5rem 0;
  color: #1b5e20;
}

.teacher-card p {
  font-size: 0.95rem;
  color: #424242;
  margin: 0.3rem 0;
}

/* === Контактная информация === */
.contact-info {
  max-width: 900px;
  margin: 2rem auto;
  padding: 0 10%;
  text-align: center;
  line-height: 1.7;
  border-top: 1px solid #eee;
  color: #333;
}

.contact-info h2 {
  font-size: 1.8rem;
  margin-bottom: 1.2rem;
  color: #2e7d32;
}

.contact-info p {
  margin-bottom: 1rem;
  font-size: 1.05rem;
}
</style>
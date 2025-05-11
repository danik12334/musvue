<template>
  <div class="home">
    <Header />

    <!-- Просто текст приветствия -->
    <h2>Добро пожаловать в музыкальную школу "Аккорд"</h2>

    <!-- Направления обучения -->
    <section class="courses-preview">
      <h3 class="centered">Наши направления</h3>
      <div class="courses-grid">
        <div class="course-card" v-for="(course, index) in courses" :key="index">
          <img :src="course.image" :alt="course.title">
          <h4>{{ course.title }}</h4>
          <p>{{ course.description }}</p>
        </div>
      </div>
    </section>

    <!-- Рандомная информация -->
    <section class="info-section">
      <h1>
        Музыкальная школа "Аккорд" — это место, где рождаются настоящие таланты.
        Мы предлагаем обучение по различным музыкальным направлениям для детей и взрослых,
        независимо от уровня подготовки. Наши преподаватели — профессионалы своего дела,
        имеющие богатый педагогический и творческий опыт.
      </h1>
      <h1>
        В нашей школе вы можете выбрать индивидуальные или групповые занятия,
        а также принять участие в концертах, мастер-классах и открытых уроках.
        Мы верим, что каждый человек может научиться играть на музыкальном инструменте,
        если подходит к этому с душой и желанием развиваться.
      </h1>
      <h1>
        Наша миссия — сделать музыку доступной каждому. Мы не просто учим играть — мы помогаем раскрыть
        талант, развить уверенность и получить удовольствие от процесса. Каждый наш ученик получает
        индивидуальный подход, комфортную обстановку и мотивацию для роста.
      </h1>
      <h1>
        Школа работает уже более 10 лет и за это время выпустила сотни учеников, которые продолжили
        своё обучение в музыкальных колледжах и университетах, а некоторые стали профессиональными музыкантами.
        Мы гордимся каждым своим учеником и стремимся к тому, чтобы музыка оставалась частью их жизни.
      </h1>
    </section>

    <!-- Карта -->
    <section class="map-section">
      <h3>Как нас найти</h3>
      <iframe 
        src="https://yandex.ru/map-widget/v1/?um=constructor%3A1a65df480d749f1e7bce2c3d400e8c71cd69fc144695551641fe5e148280857f&amp;source=constructor" 
        width="100%" 
        height="400" 
        frameborder="0"
      ></iframe>
    </section>

    <Footer />
  </div>
</template>

<script>
// Импортируем изображения
import guitarImage from '@/assets/images/guitar.jpg'
import pianoImage from '@/assets/images/piano.jpg'
import violinImage from '@/assets/images/violin.jpg'

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
      courses: [
        {
          title: 'Гитара',
          description: 'Обучение игре на гитаре для начинающих и продвинутых',
          image: guitarImage
        },
        {
          title: 'Фортепиано',
          description: 'Классическое и современное фортепиано',
          image: pianoImage
        },
        {
          title: 'Скрипка',
          description: 'Индивидуальные уроки игры на скрипке',
          image: violinImage
        }
      ]
    }
  }
}
</script>

<style scoped>
.home {
  margin: 0;
  padding: 0;
  width: 100%;
}

h2 {
  text-align: center;
  margin: 2rem 0 1rem;
  color: #2e7d32;
  font-weight: 600;
  font-size: 1.8rem;
}

.centered {
  text-align: center;
  font-size: 1.5rem;
  font-weight: bold;
  margin-bottom: 2rem;
  color: #1b5e20;
}

/* Сетка курсов */
.courses-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 2rem;
  padding: 0 10%;
  margin-bottom: 2rem;
  justify-items: center;
}

.course-card {
  border: 1px solid #ccc;
  border-radius: 10px;
  padding: 1.2rem;
  background-color: #fafafa;
  text-align: center;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.course-card img {
  max-width: 100%;
  height: auto;
  border-radius: 8px;
  margin-bottom: 1rem;
}

.course-card h4 {
  font-size: 1.1rem;
  margin-bottom: 0.5rem;
  color: #1b5e20;
}

.course-card p {
  font-size: 0.95rem;
  color: #424242;
}

.course-card:hover {
  transform: translateY(-6px);
  box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
}

/* Основной текст */
.info-section {
  max-width: 900px;
  margin: 2rem auto;
  line-height: 1.7;
  color: #333;
  padding: 0 10%;
  text-align: center;
}

.info-section p {
  margin-bottom: 1.2rem;
  font-size: 1.05rem;
}

/* Блок с картой */
.map-section {
  padding: 0 10%;
  margin: 2rem 0;
}

.map-section h3 {
  text-align: center;
  margin-bottom: 1rem;
  color: #1b5e20;
  font-size: 1.4rem;
}
</style>
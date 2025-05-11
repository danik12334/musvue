<template>
  <div class="about">
    <Header />

    <!-- Описание школы -->
    <section class="school-description">
      <h2>О музыкальной школе "Аккорд"</h2>
      <p>
        Музыкальная школа "Аккорд" — это место, где рождаются настоящие таланты.
        Мы помогаем детям и взрослым раскрыть себя в мире музыки, научиться играть на инструментах,
        петь и чувствовать ритм. Наша цель — сделать обучение доступным, интересным и эффективным.
      </p>
      <p>
        С момента основания школы прошло уже более 10 лет, за которые мы выпустили сотни учеников,
        многие из которых продолжили обучение в музыкальных колледжах и университетах.
        Наши преподаватели — профессионалы с высшим образованием и большим опытом работы.
      </p>
    </section>

    <!-- Галерея мероприятий -->
    <section class="events">
      <h2>Наши мероприятия</h2>
      <div class="event-gallery">
        <div class="event-item" v-for="(event, index) in events" :key="index">
          <img :src="event.image" :alt="event.title">
          <h3>{{ event.title }}</h3>
          <p>{{ event.description }}</p>
        </div>
      </div>
    </section>

    <!-- Дополнительная информация -->
    <section class="additional-info">
      <h2>Почему выбирают нас?</h2>
      <p>
        Мы предлагаем не только качественное обучение, но и атмосферу дружелюбия и вдохновения.
        У нас регулярно проводятся открытые уроки, концерты, фестивали и мастер-классы.
        Каждый ученик получает индивидуальный подход и поддержку на каждом этапе обучения.
      </p>
      <p>
        Занятия проходят как в очной, так и в онлайн-формате, что делает обучение удобным и доступным.
        Присоединяйтесь к нам — и пусть музыка станет частью вашей жизни!
      </p>
    </section>

    <Footer />
  </div>
</template>

<script>
// Импортируем изображения
import event1 from '@/assets/images/event1.jpg'
import event2 from '@/assets/images/event2.jpg'
import event3 from '@/assets/images/event3.jpg'
import event4 from '@/assets/images/event4.jpg'
import event5 from '@/assets/images/event5.jpg'

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
      events: [
        {
          title: 'Концерт весны',
          description: 'Наши ученики выступили на городском концерте.',
          image: event1
        },
        {
          title: 'Музыкальный фестиваль',
          description: 'Участие в региональном фестивале классической музыки.',
          image: event2
        },
        {
          title: 'Открытые уроки',
          description: 'Родители могли посетить открытые занятия с преподавателями.',
          image: event3
        },
        {
          title: 'Ночь искусств',
          description: 'Выступление учеников в рамках культурного праздника.',
          image: event4
        },
        {
          title: 'Заключный концерт года',
          description: 'Грандиозное завершение учебного года с яркими номерами.',
          image: event5
        }
      ]
    }
  }
}
</script>

<style scoped>
/* === Центрированный контент с отступами по бокам === */
.school-description,
.additional-info {
  max-width: 900px;
  margin: 2rem auto;
  padding: 0 10%;
  line-height: 1.7;
  text-align: center;
  color: #333;
}

.school-description h2,
.additional-info h2 {
  font-size: 1.8rem;
  margin-bottom: 1.5rem;
  color: #1b5e20;
}

.school-description p,
.additional-info p {
  font-size: 1.05rem;
  margin-bottom: 1.2rem;
}

/* === Галерея мероприятий === */
.events {
  padding: 2rem 10%;
}

.events h2 {
  text-align: center;
  font-size: 2rem;
  margin-bottom: 2rem;
  color: #2e7d32;
}

.event-gallery {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 2rem;
  justify-items: center;
}

.event-item {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 1rem;
  background-color: #fafafa;
  text-align: center;
  transition: box-shadow 0.3s ease;
}

.event-item:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.event-item img {
  max-width: 100%;
  height: auto;
  border-radius: 6px;
  margin-bottom: 1rem;
}

.event-item h3 {
  font-size: 1.1rem;
  margin-bottom: 0.5rem;
  color: #1b5e20;
}

.event-item p {
  font-size: 0.95rem;
  color: #424242;
}
</style>
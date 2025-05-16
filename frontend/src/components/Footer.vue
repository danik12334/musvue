<template>
  <footer>
    <div class="footer-content">
      <p>© 2023 Музыкальная школа "Аккорд"</p>
      <p>Контактный телефон: +7 (123) 456-78-90</p>
      <p>Email: info@akkord-music.ru</p>
    </div>
  </footer>
</template>

<script>
export default {
  name: 'Footer'
}
</script>

<style scoped>
footer {
  background-color: var(--secondary-color);
  color: white;
  padding: 2rem;
  text-align: center;
  margin-top: auto;
}

.footer-content p {
  margin: 0.5rem 0;
}
</style>
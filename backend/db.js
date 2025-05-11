import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

// Тест подключения (добавьте это)
const testConnection = async () => {
  try {
    const conn = await pool.getConnection();
    console.log('✅ Успешное подключение к MySQL!');
    conn.release();
  } catch (err) {
    console.error('❌ Ошибка подключения к MySQL:', err.message);
    process.exit(1); // Завершить процесс при ошибке
  }
};

testConnection();

export default pool;
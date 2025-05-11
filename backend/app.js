import express from 'express';
import cors from 'cors';
import teachersRouter from './routes/teachers.js';
import coursesRouter from './routes/courses.js';
import dotenv from 'dotenv';
import pool from './db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Загрузка переменных из .env
dotenv.config();

const app = express();

// Middleware для CORS
app.use(cors({
  origin: 'http://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Парсинг JSON
app.use(express.json());

// Логирование всех запросов
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Подключение роутеров
app.use('/api/teachers', teachersRouter);
app.use('/api/courses', coursesRouter);

// Маршрут для регистрации
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Все поля обязательны' });
  }

  try {
    // Проверка существования пользователя
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'Пользователь уже существует' });
    }

    // Хэширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Добавление пользователя
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    // Определение прав администратора
    const isAdmin = email.endsWith('@melody.ru');

    // Генерация токена
    const token = jwt.sign(
      { id: result.insertId, isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      user: {
        id: result.insertId,
        name,
        email,
        isAdmin
      }
    });
  } catch (error) {
    console.error('Ошибка регистрации:', error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Маршрут для входа (использует login.js)
import { login } from './api/login.js';
app.post('/api/login', login);

// Маршрут для получения информации о текущем пользователе (использует me.js)
import { getMe } from './api/me.js';
app.get('/api/me', getMe);

// Проверка API
app.get('/api/check', (req, res) => {
  res.json({ 
    status: 'API работает', 
    db: process.env.DB_NAME,
    timestamp: new Date().toISOString()
  });
});

// Middleware для проверки админских прав
const checkAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ message: 'Требуется авторизация' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Недостаточно прав' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Неверный токен' });
  }
};

// Защищённый админ-маршрут для примера
app.get('/api/admin-only', checkAdmin, (req, res) => {
  res.json({ message: 'Добро пожаловать, администратор!' });
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error('Ошибка сервера:', err.stack);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// Обработка 404
app.use((req, res) => {
  res.status(404).json({ error: 'Маршрут не найден' });
});


// === Новые строки: Отдаём статику из dist ===
app.use(express.static('../dist'));

app.get('*', (req, res) => {
  res.sendFile(path.resolve('../dist', 'index.html'));
});


// === Изменённая часть — запуск сервера на порту из env или 3001 ===
const PORT = process.env.PORT || 3001;
const path = require('path'); // <-- импорт path вынесен сюда, чтобы не было ReferenceError

app.listen(PORT, () => {
  console.log(`\n=== Сервер запущен ===`);
  console.log(`Порт: ${PORT}`);
  console.log(`База данных: ${process.env.DB_NAME}`);
  console.log(`CORS разрешен для: http://localhost:5173`);
  console.log(`Проверка API: http://localhost:${PORT}/api/check\n`);
});
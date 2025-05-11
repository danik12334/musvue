import pool from '../db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
  console.log('Request body:', req.body); // Логируем входящие данные
  
  // Проверка тела запроса
  if (!req.body || Object.keys(req.body).length === 0) {
    console.error('Empty request body');
    return res.status(400).json({ message: 'Тело запроса отсутствует' });
  }

  const { name, email, password } = req.body;

  // Проверка полей
  if (!name?.trim() || !email?.trim() || !password?.trim()) {
    console.error('Missing fields:', { name, email, password });
    return res.status(400).json({ message: 'Все поля обязательны!' });
  }

  try {
    // Проверка существования пользователя
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE email = ?', 
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'Пользователь с таким email уже существует' });
    }

    // Хэширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed');

    // Сохранение пользователя
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    // Генерация токена
    const token = jwt.sign(
      { id: result.insertId }, 
      process.env.JWT_SECRET || 'default_secret', // Используем переменную окружения или дефолтный ключ
      { expiresIn: '24h' }
    );

    // Успешный ответ
    res.status(201).json({
      token,
      user: {
        id: result.insertId,
        name,
        email,
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Ошибка сервера при регистрации' });
  }
};
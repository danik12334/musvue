import pool from '../db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны' });
  }

  try {
    // Поиск пользователя
    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Неверные учетные данные' });
    }

    const user = users[0];

    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Неверные учетные данные' });
    }

    // Проверка домена email для админских прав (из БД)
    const isAdmin = user.email.endsWith('@melody.ru');

    // Генерация токена с флагом isAdmin
    const token = jwt.sign(
      { id: user.id, isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Отправляем ответ без пароля и с флагом isAdmin
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isAdmin
      }
    });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
};
import pool from '../db.js';
import jwt from 'jsonwebtoken';

export const getMe = async (req, res) => {
  try {
    // 1. Проверка наличия заголовка Authorization
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      console.error('Отсутствует заголовок Authorization');
      return res.status(401).json({ 
        message: 'Требуется авторизация',
        code: 'MISSING_AUTH_HEADER'
      });
    }

    // 2. Извлечение токена
    const token = authHeader.split(' ')[1];

    // 3. Верификация токена
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      console.error('Ошибка верификации токена:', jwtError.message);
      return res.status(401).json({ 
        message: 'Недействительный токен',
        code: 'INVALID_TOKEN'
      });
    }

    // 4. Получение данных пользователя из БД
    const [users] = await pool.query(
      `SELECT 
        id, 
        name, 
        email,
        is_admin AS isAdmin 
       FROM users 
       WHERE id = ?`,
      [decoded.id]
    );

    if (!users.length) {
      console.error('Пользователь не найден в БД, ID:', decoded.id);
      return res.status(404).json({ 
        message: 'Пользователь не найден',
        code: 'USER_NOT_FOUND'
      });
    }

    const user = users[0];

    // 5. Определение статуса администратора
    const isUserAdmin = user.isAdmin === 1 || user.email.endsWith('@melody.ru');

    // 6. Логирование для отладки
    console.log('Запрос /me:', {
      userId: user.id,
      email: user.email,
      isAdmin: isUserAdmin,
      tokenIssuedAt: new Date(decoded.iat * 1000).toISOString()
    });

    // 7. Ответ клиенту
    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      isAdmin: isUserAdmin,
      permissions: {
        canEdit: isUserAdmin,
        canDelete: isUserAdmin,
        canCreate: isUserAdmin
      }
    });

  } catch (error) {
    // 8. Обработка критических ошибок
    console.error('Критическая ошибка в /me:', {
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({ 
      message: 'Внутренняя ошибка сервера',
      code: 'SERVER_ERROR'
    });
  }
};
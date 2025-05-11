import express from 'express';
import pool from '../db.js';
import jwt from 'jsonwebtoken';

const router = express.Router();

// Middleware для проверки админских прав
const checkAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'Требуется авторизация' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Доступ запрещён' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Неверный токен' });
  }
};

// Получить все курсы (доступно всем)
router.get('/', async (req, res) => {
  try {
    const [courses] = await pool.query('SELECT * FROM courses');
    res.json(courses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Получить один курс (доступно всем)
router.get('/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM courses WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Курс не найден' });
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Добавить курс (только админ)
router.post('/', checkAdmin, async (req, res) => {
  try {
    const { teacher_id, course_name, description, teacher_full_name, price,
            duration, level, start_date, enrollment_count, photo_url } = req.body;

    const [result] = await pool.query(
      `INSERT INTO courses 
      (teacher_id, course_name, description, teacher_full_name, price, 
       duration, level, start_date, enrollment_count, photo_url) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [teacher_id, course_name, description, teacher_full_name, price,
       duration, level, start_date, enrollment_count || 0, photo_url]
    );

    res.status(201).json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Обновить курс (только админ)
router.put('/:id', checkAdmin, async (req, res) => {
  try {
    const { teacher_id, course_name, description, teacher_full_name, price,
            duration, level, start_date, enrollment_count, photo_url } = req.body;

    await pool.query(
      `UPDATE courses SET 
      teacher_id = ?, course_name = ?, description = ?, teacher_full_name = ?, 
      price = ?, duration = ?, level = ?, start_date = ?, 
      enrollment_count = ?, photo_url = ? 
      WHERE id = ?`,
      [teacher_id, course_name, description, teacher_full_name, price,
       duration, level, start_date, enrollment_count || 0, photo_url, req.params.id]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Удалить курс (только админ)
router.delete('/:id', checkAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM courses WHERE id = ?', [req.params.id]);
    res.json({ message: 'Курс удалён' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
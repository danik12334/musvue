import express from 'express'
import pool from '../db.js'
import jwt from 'jsonwebtoken'

const router = express.Router()

// Middleware для проверки админских прав
const checkAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(403).json({ message: 'Требуется авторизация' })

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Доступ запрещён' })
    }
    req.user = decoded
    next()
  } catch (error) {
    res.status(401).json({ message: 'Неверный токен' })
  }
}

// Получить всех преподавателей (доступно всем)
router.get('/', async (req, res) => {
  try {
    const [teachers] = await pool.query('SELECT * FROM teachers')
    res.json(teachers)
  } catch (error) {
    console.error('Ошибка получения преподавателей:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Получить одного преподавателя
router.get('/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM teachers WHERE id = ?', [req.params.id])
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Преподаватель не найден' })
    }
    res.json(rows[0])
  } catch (error) {
    console.error('Ошибка получения преподавателя:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Добавить преподавателя (только админ)
router.post('/', checkAdmin, async (req, res) => {
  try {
    const { last_name, first_name, patronymic, subject, experience, education, contact_phone, email, photo_url } = req.body

    if (!last_name || !first_name || !subject) {
      return res.status(400).json({ error: 'Не все обязательные поля заполнены' })
    }

    const [result] = await pool.query(
      `INSERT INTO teachers 
        (last_name, first_name, patronymic, subject, experience, education, contact_phone, email, photo_url) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [last_name, first_name, patronymic, subject, experience, education, contact_phone, email, photo_url]
    )

    res.status(201).json({ id: result.insertId })
  } catch (error) {
    console.error('Ошибка при добавлении преподавателя:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Обновить преподавателя (только админ)
router.put('/:id', checkAdmin, async (req, res) => {
  try {
    const { last_name, first_name, patronymic, subject, experience, education, contact_phone, email, photo_url } = req.body

    if (!last_name || !first_name || !subject) {
      return res.status(400).json({ error: 'Не все обязательные поля заполнены' })
    }

    await pool.query(
      `UPDATE teachers SET 
        last_name = ?, first_name = ?, patronymic = ?, subject = ?, experience = ?, 
        education = ?, contact_phone = ?, email = ?, photo_url = ? 
        WHERE id = ?`,
      [last_name, first_name, patronymic, subject, experience, education, contact_phone, email, photo_url, req.params.id]
    )

    res.json({ success: true })
  } catch (error) {
    console.error('Ошибка при обновлении преподавателя:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Удалить преподавателя (только админ)
router.delete('/:id', checkAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM teachers WHERE id = ?', [req.params.id])
    res.json({ success: true })
  } catch (error) {
    console.error('Ошибка при удалении преподавателя:', error.message)
    res.status(500).json({ error: error.message })
  }
})

export default router
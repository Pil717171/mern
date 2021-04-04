const { Router } = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth
router.post('/register',
  [
    check('email', 'Некорректный емейл').isEmail(),
    check('password', 'Минимаьная длинна пароля 6 символов')
      .isLength({min: 6})
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Некорректные данные при регистрации'
        })
      }
      const {email, password} = req.body

      console.log('Email', email)
      console.log('User', User)
      const candidate =  await User.findOne({ email })

      console.log('Candidate', candidate)
      if (candidate) {
        return res.status(400).json({message: 'Такой пользователь есть'})
      }

      const hashedPassword = await bcrypt.hash(password, 12)

      console.log('Password', hashedPassword)
      const user = new User({ email, password: hashedPassword})

      console.log('USer', user)
      await user.save()

      res.status(201).json({message: 'Пользователь создан'})
    } catch (e) {
      res.status(500).json({message: 'Что-то поломалось'})
    }
})

// /api/login
router.post('/login',
  [
    check('email', 'Введите корректный емейл').normalizeEmail().isEmail(),
    check('password', 'Введите пароль').exists()
      .isLength({min: 6})
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Некорректные данные при входе'
        })
      }
      const { email, password } = req.body
      const user = await User.findOne({ email })

      if (!user) {
        return res.status(400).json({ message: 'Пользователь не найден'})
      }

      const isMatch = await  bcrypt.compare(password, user.password)

      if (!isMatch) {
        return res.status(400).json({message: 'Что-то пошло не так'})
      }

      const token = jwt.sign(
        { userId: user.id },
        config.get('jwtSecret'),
        { expiresIn: '1h' }
      )

      res.json({ token, userId: user.id })

    } catch (e) {
      res.status(500).json({message: 'Что-то поломалось'})
    }
})

module.exports = router
const router = require('express').Router();
const authController = require('../Controller/Auth')

router.post('/signup', authController.signUp)
router.post('/login', authController.login)
router.post('/verify', authController.verifyOtp)
router.get('/', (req, res) => {
    return res.json({
        hi : "hello"
    })
})

module.exports = router
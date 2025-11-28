const express = require('express');
const router = express.Router();
const studentController = require('../controllers/studentController');
const { authenticate, authorizeRole } = require('../middleware/auth');
const { validateStudentRegistration, validateLogin } = require('../middleware/validation');

router.post('/register', validateStudentRegistration, studentController.registerStudent);
router.post('/login', validateLogin, studentController.loginStudent);
router.get('/profile', authenticate, authorizeRole('student'), studentController.getStudentProfile);
router.put('/profile', authenticate, authorizeRole('student'), studentController.updateStudentProfile);
router.delete('/profile', authenticate, authorizeRole('student'), studentController.deleteStudent);
router.post('/logout', authenticate, studentController.logoutStudent);
router.get('/all', studentController.getAllStudents);

module.exports = router;
const express = require('express');
const router = express.Router();
const teacherController = require('../controllers/teacherController');
const { authenticate, authorizeRole } = require('../middleware/auth');
const { validateTeacherRegistration, validateLogin } = require('../middleware/validation');

router.post('/register', validateTeacherRegistration, teacherController.registerTeacher);
router.post('/login', validateLogin, teacherController.loginTeacher);
router.get('/profile', authenticate, authorizeRole('teacher'), teacherController.getTeacherProfile);
router.put('/profile', authenticate, authorizeRole('teacher'), teacherController.updateTeacherProfile);
router.delete('/profile', authenticate, authorizeRole('teacher'), teacherController.deleteTeacher);
router.post('/logout', authenticate, teacherController.logoutTeacher);
router.get('/all', teacherController.getAllTeachers);

module.exports = router;
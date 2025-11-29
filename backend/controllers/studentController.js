const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Student = require('../models/Student');
const { jwtSecret, jwtExpire, cookieExpire } = require('../config/auth');
const sendEmailOtp = require('../utils/sendOtp');

const otpStore = new Map();

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

exports.sendStudentOtp = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required' });
        }

        const existingStudent = await Student.findByEmail(email);
        if (existingStudent && existingStudent.is_verified) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }

        const otp = generateOTP();
        const otp_expiry = Date.now() + 10 * 60000;

        otpStore.set(email, {
            otp,
            otp_expiry,
            password,
            attempts: 0
        });

        await sendEmailOtp({ to: email, otp });

        res.status(200).json({
            success: true,
            message: 'OTP sent to your email',
            data: { email }
        });
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send OTP',
            error: error.message
        });
    }
};

exports.verifyStudentOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!otpStore.has(email)) {
            return res.status(400).json({ success: false, message: 'OTP not found or expired. Please request a new OTP' });
        }

        const storedData = otpStore.get(email);

        if (Date.now() > storedData.otp_expiry) {
            otpStore.delete(email);
            return res.status(400).json({ success: false, message: 'OTP expired. Please request a new OTP' });
        }

        if (storedData.otp !== otp) {
            storedData.attempts += 1;
            if (storedData.attempts >= 3) {
                otpStore.delete(email);
                return res.status(400).json({ success: false, message: 'Too many failed attempts. Please request a new OTP' });
            }
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }

        res.status(200).json({ success: true, message: 'Email verified successfully' });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during verification',
            error: error.message
        });
    }
};

exports.registerStudent = async (req, res) => {
    try {
        const {
            firstName, lastName, email, password, phone, currentStatus,
            branch, studyYear, schoolCollege, city, programInterest,
            salesSelections, craSelections, agreeTerms
        } = req.body;

        if (!otpStore.has(email)) {
            return res.status(400).json({ success: false, message: 'Email not verified. Please verify your email first' });
        }

        const existingStudent = await Student.findByEmail(email);
        if (existingStudent && existingStudent.is_verified) {
            return res.status(400).json({
                success: false,
                message: 'Student with this email already exists'
            });
        }

        const storedData = otpStore.get(email);
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(storedData.password, salt);

        const studentData = {
            firstName,
            lastName,
            email,
            password: hashedPassword,
            phone,
            currentStatus,
            branch,
            studyYear,
            schoolCollege,
            city,
            programInterest,
            salesSelections,
            craSelections,
            agreeTerms,
            is_verified: true
        };

        if (existingStudent) {
            await Student.update(existingStudent.id, studentData);
        } else {
            await Student.create(studentData);
        }

        otpStore.delete(email);

        res.status(201).json({
            success: true,
            message: 'Student registered successfully',
            data: { email, firstName, lastName }
        });
    } catch (error) {
        console.error('Student registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration',
            error: error.message
        });
    }
};

exports.loginStudent = async (req, res) => {
    try {
        const { email, password } = req.body;

        const student = await Student.findByEmail(email);
        if (!student) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        if (!student.is_verified) {
            return res.status(401).json({
                success: false,
                message: 'Email not verified. Please verify your email first.'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, student.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const token = jwt.sign({ id: student.id, role: 'student' }, jwtSecret, {
            expiresIn: jwtExpire
        });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: cookieExpire
        });

        res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                id: student.id,
                email: student.email,
                firstName: student.first_name,
                lastName: student.last_name
            },
            token
        });
    } catch (error) {
        console.error('Student login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login',
            error: error.message
        });
    }
};

exports.getStudentProfile = async (req, res) => {
    try {
        const student = await Student.findById(req.user.id);
        if (!student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found'
            });
        }
        delete student.password;
        res.status(200).json({
            success: true,
            data: student
        });
    } catch (error) {
        console.error('Get student profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.updateStudentProfile = async (req, res) => {
    try {
        const {
            firstName, lastName, phone, currentStatus, branch, studyYear,
            schoolCollege, city, programInterest, salesSelections, craSelections
        } = req.body;

        const studentData = {
            firstName,
            lastName,
            phone,
            currentStatus,
            branch,
            studyYear,
            schoolCollege,
            city,
            programInterest,
            salesSelections,
            craSelections
        };

        await Student.update(req.user.id, studentData);

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        console.error('Update student profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.getAllStudents = async (req, res) => {
    try {
        const students = await Student.getAll();
        res.status(200).json({
            success: true,
            count: students.length,
            data: students
        });
    } catch (error) {
        console.error('Get all students error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.deleteStudent = async (req, res) => {
    try {
        await Student.delete(req.user.id);
        res.clearCookie('token');
        res.status(200).json({
            success: true,
            message: 'Student account deleted successfully'
        });
    } catch (error) {
        console.error('Delete student error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.logoutStudent = async (req, res) => {
    try {
        res.clearCookie('token');
        res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Teacher = require('../models/Teacher');
const { jwtSecret, jwtExpire, cookieExpire } = require('../config/auth');
const sendEmailOtp = require('../utils/sendOtp');

const otpStore = new Map();

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

exports.sendTeacherOtp = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required' });
        }

        const existingTeacher = await Teacher.findByEmail(email);
        if (existingTeacher && existingTeacher.is_verified) {
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

exports.verifyTeacherOtp = async (req, res) => {
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

exports.registerTeacher = async (req, res) => {
    try {
        const {
            firstName, lastName, email, password, phone, city,
            highestEducation, experienceRange, institution, subjectExpertise,
            linkedin, experiencePdfUrl, teachingMode, availability,
            expectedHourlyRate, languages, bio, agreeTerms
        } = req.body;

        if (!otpStore.has(email)) {
            return res.status(400).json({ success: false, message: 'Email not verified. Please verify your email first' });
        }

        const existingTeacher = await Teacher.findByEmail(email);
        if (existingTeacher && existingTeacher.is_verified) {
            return res.status(400).json({
                success: false,
                message: 'Teacher with this email already exists'
            });
        }

        const storedData = otpStore.get(email);
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(storedData.password, salt);

        const teacherData = {
            firstName,
            lastName,
            email,
            password: hashedPassword,
            phone,
            city,
            highestEducation,
            experienceRange,
            institution,
            subjectExpertise,
            linkedin,
            experiencePdfUrl,
            teachingMode,
            availability,
            expectedHourlyRate,
            languages,
            bio,
            agreeTerms,
            is_verified: true
        };

        if (existingTeacher) {
            await Teacher.update(existingTeacher.id, teacherData);
        } else {
            await Teacher.create(teacherData);
        }

        otpStore.delete(email);

        res.status(201).json({
            success: true,
            message: 'Teacher registered successfully',
            data: { email, firstName, lastName }
        });
    } catch (error) {
        console.error('Teacher registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration',
            error: error.message
        });
    }
};

exports.loginTeacher = async (req, res) => {
    try {
        const { email, password } = req.body;

        const teacher = await Teacher.findByEmail(email);
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        if (!teacher.is_verified) {
            return res.status(401).json({
                success: false,
                message: 'Email not verified. Please verify your email first.'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, teacher.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const token = jwt.sign({ id: teacher.id, role: 'teacher' }, jwtSecret, {
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
                id: teacher.id,
                email: teacher.email,
                firstName: teacher.first_name,
                lastName: teacher.last_name
            },
            token
        });
    } catch (error) {
        console.error('Teacher login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login',
            error: error.message
        });
    }
};

exports.getTeacherProfile = async (req, res) => {
    try {
        const teacher = await Teacher.findById(req.user.id);
        if (!teacher) {
            return res.status(404).json({
                success: false,
                message: 'Teacher not found'
            });
        }
        delete teacher.password;
        res.status(200).json({
            success: true,
            data: teacher
        });
    } catch (error) {
        console.error('Get teacher profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.updateTeacherProfile = async (req, res) => {
    try {
        const {
            firstName, lastName, phone, city, highestEducation, experienceRange,
            institution, subjectExpertise, linkedin, experiencePdfUrl,
            teachingMode, availability, expectedHourlyRate, languages, bio
        } = req.body;

        const teacherData = {
            firstName,
            lastName,
            phone,
            city,
            highestEducation,
            experienceRange,
            institution,
            subjectExpertise,
            linkedin,
            experiencePdfUrl,
            teachingMode,
            availability,
            expectedHourlyRate,
            languages,
            bio
        };

        await Teacher.update(req.user.id, teacherData);

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        console.error('Update teacher profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.getAllTeachers = async (req, res) => {
    try {
        const teachers = await Teacher.getAll();
        res.status(200).json({
            success: true,
            count: teachers.length,
            data: teachers
        });
    } catch (error) {
        console.error('Get all teachers error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.deleteTeacher = async (req, res) => {
    try {
        await Teacher.delete(req.user.id);
        res.clearCookie('token');
        res.status(200).json({
            success: true,
            message: 'Teacher account deleted successfully'
        });
    } catch (error) {
        console.error('Delete teacher error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.logoutTeacher = async (req, res) => {
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

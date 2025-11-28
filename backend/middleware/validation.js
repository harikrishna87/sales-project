const { body, validationResult } = require('express-validator');

exports.validateStudentRegistration = [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('phone').matches(/^[0-9]{8,15}$/).withMessage('Valid phone number is required'),
  body('currentStatus').notEmpty().withMessage('Current status is required'),
  body('schoolCollege').notEmpty().withMessage('School/College name is required'),
  body('city').notEmpty().withMessage('City is required'),
  body('programInterest').notEmpty().withMessage('Program interest is required'),
  body('agreeTerms').isBoolean().withMessage('Must agree to terms'),
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];

exports.validateTeacherRegistration = [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('phone').matches(/^[0-9]{8,15}$/).withMessage('Valid phone number is required'),
  body('city').notEmpty().withMessage('City is required'),
  body('highestEducation').notEmpty().withMessage('Highest education is required'),
  body('experienceRange').notEmpty().withMessage('Experience range is required'),
  body('institution').notEmpty().withMessage('Institution is required'),
  body('subjectExpertise').notEmpty().withMessage('Subject expertise is required'),
  body('teachingMode').notEmpty().withMessage('Teaching mode is required'),
  body('availability').notEmpty().withMessage('Availability is required'),
  body('languages').isArray({ min: 1 }).withMessage('At least one language is required'),
  body('bio').notEmpty().withMessage('Bio is required'),
  body('agreeTerms').isBoolean().withMessage('Must agree to terms'),
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];

exports.validateLogin = [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required'),
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];
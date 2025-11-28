const db = require('../config/db');

class Teacher {
  static async create(teacherData) {
    const query = `
      INSERT INTO teachers (
        first_name, last_name, email, password, phone, city,
        highest_education, experience_range, institution, subject_expertise,
        linkedin, experience_pdf_url, teaching_mode, availability,
        expected_hourly_rate, languages, bio, agree_terms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    const values = [
      teacherData.firstName,
      teacherData.lastName,
      teacherData.email,
      teacherData.password,
      teacherData.phone,
      teacherData.city,
      teacherData.highestEducation,
      teacherData.experienceRange,
      teacherData.institution,
      teacherData.subjectExpertise,
      teacherData.linkedin || null,
      teacherData.experiencePdfUrl || null,
      teacherData.teachingMode,
      teacherData.availability,
      teacherData.expectedHourlyRate || null,
      JSON.stringify(teacherData.languages || []),
      teacherData.bio,
      teacherData.agreeTerms
    ];
    
    const [result] = await db.execute(query, values);
    return result;
  }

  static async findByEmail(email) {
    const query = 'SELECT * FROM teachers WHERE email = ?';
    const [rows] = await db.execute(query, [email]);
    return rows[0];
  }

  static async findById(id) {
    const query = 'SELECT * FROM teachers WHERE id = ?';
    const [rows] = await db.execute(query, [id]);
    if (rows[0]) {
      rows[0].languages = JSON.parse(rows[0].languages || '[]');
    }
    return rows[0];
  }

  static async getAll() {
    const query = `
      SELECT id, first_name, last_name, email, phone, city, 
             highest_education, experience_range, subject_expertise, 
             teaching_mode, created_at 
      FROM teachers
    `;
    const [rows] = await db.execute(query);
    return rows;
  }

  static async update(id, teacherData) {
    const query = `
      UPDATE teachers SET
        first_name = ?, last_name = ?, phone = ?, city = ?,
        highest_education = ?, experience_range = ?, institution = ?,
        subject_expertise = ?, linkedin = ?, experience_pdf_url = ?,
        teaching_mode = ?, availability = ?, expected_hourly_rate = ?,
        languages = ?, bio = ?
      WHERE id = ?
    `;
    
    const values = [
      teacherData.firstName,
      teacherData.lastName,
      teacherData.phone,
      teacherData.city,
      teacherData.highestEducation,
      teacherData.experienceRange,
      teacherData.institution,
      teacherData.subjectExpertise,
      teacherData.linkedin || null,
      teacherData.experiencePdfUrl || null,
      teacherData.teachingMode,
      teacherData.availability,
      teacherData.expectedHourlyRate || null,
      JSON.stringify(teacherData.languages || []),
      teacherData.bio,
      id
    ];
    
    const [result] = await db.execute(query, values);
    return result;
  }

  static async delete(id) {
    const query = 'DELETE FROM teachers WHERE id = ?';
    const [result] = await db.execute(query, [id]);
    return result;
  }
}

module.exports = Teacher;
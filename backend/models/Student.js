const db = require('../config/db');

class Student {
    static async create(studentData) {
        const query = `
            INSERT INTO students (
                first_name, last_name, email, password, phone, current_status,
                branch, study_year, school_college, city, program_interest,
                sales_selections, cra_selections, agree_terms, is_verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            studentData.firstName,
            studentData.lastName,
            studentData.email,
            studentData.password,
            studentData.phone,
            studentData.currentStatus,
            studentData.branch || null,
            studentData.studyYear || null,
            studentData.schoolCollege,
            studentData.city,
            studentData.programInterest,
            JSON.stringify(studentData.salesSelections || []),
            JSON.stringify(studentData.craSelections || []),
            studentData.agreeTerms,
            studentData.is_verified || false
        ];

        const [result] = await db.execute(query, values);
        return result;
    }

    static async findByEmail(email) {
        const query = 'SELECT * FROM students WHERE email = ?';
        const [rows] = await db.execute(query, [email]);
        return rows[0];
    }

    static async findById(id) {
        const query = 'SELECT * FROM students WHERE id = ?';
        const [rows] = await db.execute(query, [id]);
        if (rows[0]) {
            rows[0].sales_selections = JSON.parse(rows[0].sales_selections || '[]');
            rows[0].cra_selections = JSON.parse(rows[0].cra_selections || '[]');
        }
        return rows[0];
    }

    static async getAll() {
        const query = 'SELECT id, first_name, last_name, email, phone, current_status, city, program_interest, is_verified, created_at FROM students';
        const [rows] = await db.execute(query);
        return rows;
    }

    static async update(id, studentData) {
        const query = `
            UPDATE students SET
                first_name = ?, last_name = ?, phone = ?, current_status = ?,
                branch = ?, study_year = ?, school_college = ?, city = ?,
                program_interest = ?, sales_selections = ?, cra_selections = ?, is_verified = ?
            WHERE id = ?
        `;

        const values = [
            studentData.firstName,
            studentData.lastName,
            studentData.phone,
            studentData.currentStatus,
            studentData.branch || null,
            studentData.studyYear || null,
            studentData.schoolCollege,
            studentData.city,
            studentData.programInterest,
            JSON.stringify(studentData.salesSelections || []),
            JSON.stringify(studentData.craSelections || []),
            studentData.is_verified !== undefined ? studentData.is_verified : true,
            id
        ];

        const [result] = await db.execute(query, values);
        return result;
    }

    static async delete(id) {
        const query = 'DELETE FROM students WHERE id = ?';
        const [result] = await db.execute(query, [id]);
        return result;
    }
}

module.exports = Student;

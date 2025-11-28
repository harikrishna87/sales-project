CREATE DATABASE IF NOT EXISTS registration_db;
USE registration_db;

CREATE TABLE students (
    id INT PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    current_status VARCHAR(50) NOT NULL,
    branch VARCHAR(100),
    study_year VARCHAR(50),
    school_college VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    program_interest VARCHAR(100) NOT NULL,
    sales_selections JSON,
    cra_selections JSON,
    agree_terms BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE teachers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    city VARCHAR(100) NOT NULL,
    highest_education VARCHAR(100) NOT NULL,
    experience_range VARCHAR(50) NOT NULL,
    institution VARCHAR(255) NOT NULL,
    subject_expertise VARCHAR(255) NOT NULL,
    linkedin VARCHAR(255),
    experience_pdf_url VARCHAR(255),
    teaching_mode VARCHAR(50) NOT NULL,
    availability VARCHAR(255) NOT NULL,
    expected_hourly_rate VARCHAR(50),
    languages JSON NOT NULL,
    bio TEXT NOT NULL,
    agree_terms BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE INDEX idx_student_email ON students(email);
CREATE INDEX idx_teacher_email ON teachers(email);
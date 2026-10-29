-- Change the database name to match what your conn.js uses
CREATE DATABASE IF NOT EXISTS faculty_booking;
USE faculty_booking;

-- 1. event_bookings (not auto-created by the app, reconstructed from your queries)
CREATE TABLE IF NOT EXISTS event_bookings (
    booking_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_title VARCHAR(255) NOT NULL,
    event_type VARCHAR(120) NOT NULL,
    department VARCHAR(150) NOT NULL,
    event_description TEXT NULL,
    event_date DATE NOT NULL,
    expected_attendees INT NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    venue VARCHAR(150) NOT NULL,
    organizer_name VARCHAR(150) NOT NULL,
    contact_email VARCHAR(150) NOT NULL,
    owner_email VARCHAR(150) NULL,
    faculty_member VARCHAR(150) NULL,
    special_requests TEXT NULL,
    booking_status VARCHAR(30) NOT NULL DEFAULT 'Pending',
    rejection_message TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. users
CREATE TABLE IF NOT EXISTS users (
    user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. booking_status_history
CREATE TABLE IF NOT EXISTS booking_status_history (
    history_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    previous_status VARCHAR(30) NULL,
    new_status VARCHAR(30) NOT NULL,
    changed_by VARCHAR(150) NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX booking_history_lookup (booking_id, changed_at)
);

-- 4. booking_notifications
CREATE TABLE IF NOT EXISTS booking_notifications (
    notification_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    contact_email VARCHAR(150) NOT NULL,
    notification_type VARCHAR(20) NOT NULL,
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    source_history_id INT NULL UNIQUE,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX booking_notifications_user (contact_email, is_read, created_at)
);
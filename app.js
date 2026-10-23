const express = require('express');
const conn = require('./conn');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const app = express();
const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT) || 9000;
function loadSessionSecret() {
    if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
    const secretPath = path.join(__dirname, '.session-secret');
    try {
        return fs.readFileSync(secretPath, 'utf8').trim();
    } catch (err) {
        if (err.code !== 'ENOENT') throw err;
    }
    const secret = crypto.randomBytes(32).toString('hex');
    try {
        fs.writeFileSync(secretPath, secret, { flag: 'wx', mode: 0o600 });
        return secret;
    } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        return fs.readFileSync(secretPath, 'utf8').trim();
    }
}
const SESSION_SECRET = loadSessionSecret();
const SESSION_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_TEST_ADMIN_EMAIL = 'admin@faculty-booking.local';
let adminSetupInProgress = false;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.static('public'));

function query(sql, values = []) {
    return new Promise((resolve, reject) => {
        conn.query(sql, values, (err, result) => err ? reject(err) : resolve(result));
    });
}

async function addBookingNotification(bookingId, contactEmail, status, eventTitle, eventDate, venue, historyId) {
    const confirmed = status === 'Approved';
    const title = confirmed ? 'Booking confirmed' : 'Booking declined';
    const message = confirmed
        ? `${eventTitle} is confirmed for ${eventDate} at ${venue}.`
        : `${eventTitle} was declined because of a schedule conflict. Choose another date, time, or venue and resubmit your booking.`;
    await query(`INSERT INTO booking_notifications
        (booking_id, contact_email, notification_type, title, message, source_history_id)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [bookingId, contactEmail, confirmed ? 'confirmed' : 'declined', title, message, historyId]);
}

function makeCookie(user) {
    const payload = Buffer.from(JSON.stringify({ email: user.email, exp: Date.now() + SESSION_LIFETIME })).toString('base64url');
    const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
    return `${payload}.${signature}`;
}

function readCookie(token) {
    if (!token || !token.includes('.')) return null;
    const [payload, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest();
    let actual;
    try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
    try {
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
        return data.exp > Date.now() ? data : null;
    } catch { return null; }
}

function setLoginCookie(res, user) {
    res.cookie('faculty_session', makeCookie(user), {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: SESSION_LIFETIME,
        path: '/'
    });
}

app.use(async (req, res, next) => {
    res.locals.currentUser = null;
    const session = readCookie((req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('faculty_session='))?.slice('faculty_session='.length));
    if (!session) return next();
    try {
        const users = await query('SELECT user_id, full_name, email, role FROM users WHERE email = ?', [session.email]);
        req.user = users[0] || null;
        res.locals.currentUser = req.user;
        res.locals.unreadNotificationCount = 0;
        if (req.user && req.user.role !== 'admin') {
            const unread = await query('SELECT COUNT(*) AS total FROM booking_notifications WHERE LOWER(contact_email) = LOWER(?) AND is_read = 0', [req.user.email]);
            res.locals.unreadNotificationCount = Number(unread[0].total) || 0;
        }
        next();
    } catch (err) {
        console.error('Unable to load signed-in user:', err.message);
        res.status(500).send('Unable to load your account. Please try again.');
    }
});

function requireLogin(req, res, next) {
    if (!req.user) return res.redirect('/login');
    next();
}

function requireAdmin(req, res, next) {
    if (!req.user) return res.redirect('/login');
    if (req.user.role !== 'admin') return res.status(403).send('Administrator access is required.');
    next();
}

function renderError(res, message, status = 400) {
    res.status(status).render('auth', { mode: 'error', error: message });
}

function isValidDateInput(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ''));
    if (!match) return false;
    const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
    return date.toISOString().slice(0, 10) === value;
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = await scrypt(password, salt, 64);
    return `${salt}:${derived.toString('hex')}`;
}

async function verifyPassword(password, stored) {
    if (!stored || !stored.includes(':')) return false;
    const [salt, hash] = stored.split(':');
    const derived = await scrypt(password, salt, 64);
    const expected = Buffer.from(hash, 'hex');
    return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}

async function ensureSchema() {
    await query(`CREATE TABLE IF NOT EXISTS users (
        user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(150) NOT NULL,
        email VARCHAR(150) NOT NULL UNIQUE,
        password_hash VARCHAR(200) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS booking_status_history (
        history_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        booking_id INT NOT NULL,
        previous_status VARCHAR(30) NULL,
        new_status VARCHAR(30) NOT NULL,
        changed_by VARCHAR(150) NOT NULL,
        changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX booking_history_lookup (booking_id, changed_at)
    )`);
    const rejectionMessageColumn = await query(`SELECT COUNT(*) AS column_exists
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'event_bookings' AND COLUMN_NAME = 'rejection_message'`);
    if (!Number(rejectionMessageColumn[0].column_exists)) {
        await query('ALTER TABLE event_bookings ADD COLUMN rejection_message TEXT NULL');
    }
    const ownerEmailColumn = await query(`SELECT COUNT(*) AS column_exists
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'event_bookings' AND COLUMN_NAME = 'owner_email'`);
    if (!Number(ownerEmailColumn[0].column_exists)) {
        await query('ALTER TABLE event_bookings ADD COLUMN owner_email VARCHAR(150) NULL');
    }
    await query("UPDATE event_bookings SET owner_email = contact_email WHERE owner_email IS NULL OR owner_email = ''");

    await query(`CREATE TABLE IF NOT EXISTS booking_notifications (
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
    )`);
    await query(`UPDATE booking_notifications n
        JOIN event_bookings b ON b.booking_id = n.booking_id
        SET n.contact_email = b.owner_email
        WHERE b.owner_email IS NOT NULL AND b.owner_email <> ''`);

    // Local testing convenience: add the documented test admin once, using
    // the same password hashing as accounts created through the setup page.
    const testAdmin = await query('SELECT user_id FROM users WHERE email = ? LIMIT 1', [DEFAULT_TEST_ADMIN_EMAIL]);
    if (!testAdmin.length) {
        const passwordHash = await hashPassword('admin123');
        await query("INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            ['Test Administrator', DEFAULT_TEST_ADMIN_EMAIL, passwordHash]);
        console.log('Created test admin account (username: admin).');
    }

    // Existing bookings are associated with accounts by their contact email.
    await query(`INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by)
        SELECT b.booking_id, NULL, b.booking_status, b.contact_email
        FROM event_bookings b
        LEFT JOIN booking_status_history h ON h.booking_id = b.booking_id
        WHERE h.history_id IS NULL`);

    await query(`INSERT IGNORE INTO booking_notifications
        (booking_id, contact_email, notification_type, title, message, source_history_id, created_at)
        SELECT b.booking_id, b.owner_email,
            IF(UPPER(TRIM(h.new_status)) IN ('APPROVED', 'CONFIRMED'), 'confirmed', 'declined'),
            IF(UPPER(TRIM(h.new_status)) IN ('APPROVED', 'CONFIRMED'), 'Booking confirmed', 'Booking declined'),
            IF(UPPER(TRIM(h.new_status)) IN ('APPROVED', 'CONFIRMED'),
                CONCAT(b.event_title, ' is confirmed for ', DATE_FORMAT(b.event_date, '%Y-%m-%d'), ' at ', b.venue, '.'),
                CONCAT(b.event_title, ' was declined. Please review the reason and update your booking if needed.')),
            h.history_id, h.changed_at
        FROM booking_status_history h
        JOIN event_bookings b ON b.booking_id = h.booking_id
        WHERE UPPER(TRIM(h.new_status)) IN ('APPROVED', 'CONFIRMED', 'REJECTED')`);

}

app.get('/', async (req, res) => {
    try {
        const admins = await query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1");
        let homeStats = null;
        if (req.user) {
            const whereUser = req.user.role === 'admin' ? '' : ' WHERE LOWER(owner_email) = LOWER(?)';
            const values = req.user.role === 'admin' ? [] : [req.user.email];
            const result = await query(`SELECT COUNT(*) AS total,
                COALESCE(SUM(booking_status = 'Pending'), 0) AS pending,
                COALESCE(SUM(booking_status = 'Approved'), 0) AS approved,
                COALESCE(SUM(booking_status = 'Rejected'), 0) AS rejected
                FROM event_bookings${whereUser}`, values);
            homeStats = result[0];
        }
        res.render('home', { adminSetupAvailable: admins.length === 0, homeStats });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error loading the home page.');
    }
});

app.get('/signup', (req, res) => res.render('auth', { mode: 'signup', error: null }));
app.post('/signup', async (req, res) => {
    const fullName = (req.body.full_name || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    if (fullName.length < 2 || fullName.length > 150 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return renderError(res, 'Enter your name and a valid email address.');
    }
    if (password.length < 10 || password.length > 200) return renderError(res, 'Use a password between 10 and 200 characters.');
    try {
        const hash = await hashPassword(password);
        const result = await query('INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)', [fullName, email, hash]);
        const user = { user_id: result.insertId, full_name: fullName, email, role: 'user' };
        setLoginCookie(res, user);
        res.redirect('/user');
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return renderError(res, 'An account with that email already exists. Please sign in.');
        console.error(err);
        renderError(res, 'Could not create your account. Please try again.', 500);
    }
});

app.get('/setup-admin', async (req, res) => {
    try {
        const admins = await query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1");
        if (admins.length) return res.redirect('/login');
        res.render('auth', { mode: 'setup-admin', error: null });
    } catch (err) {
        console.error(err);
        res.status(500).send('Unable to check administrator setup.');
    }
});

app.post('/setup-admin', async (req, res) => {
    const fullName = (req.body.full_name || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    if (fullName.length < 2 || fullName.length > 150 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return renderError(res, 'Enter your name and a valid email address.');
    }
    if (password.length < 10 || password.length > 200) return renderError(res, 'Use a password between 10 and 200 characters.');
    if (adminSetupInProgress) return renderError(res, 'Administrator setup is already in progress. Please try again.', 409);
    adminSetupInProgress = true;
    try {
        const admins = await query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1");
        if (admins.length) return res.redirect('/login');
        const hash = await hashPassword(password);
        const result = await query("INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'admin')", [fullName, email, hash]);
        setLoginCookie(res, { user_id: result.insertId, full_name: fullName, email, role: 'admin' });
        res.redirect('/admin');
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return renderError(res, 'An account with that email already exists. Sign in or use another email.');
        console.error(err);
        renderError(res, 'Could not set up the administrator account. Please try again.', 500);
    } finally {
        adminSetupInProgress = false;
    }
});

app.get('/login', (req, res) => res.render('auth', { mode: 'login', error: null }));
app.post('/login', async (req, res) => {
    const identifier = (req.body.identifier || req.body.email || '').trim().toLowerCase();
    const loginType = req.body.login_type;
    if (!['user', 'admin'].includes(loginType)) return renderError(res, 'Choose User Sign In or Admin Sign In.');
    try {
        const email = loginType === 'admin' && identifier === 'admin' ? DEFAULT_TEST_ADMIN_EMAIL : identifier;
        const users = await query('SELECT user_id, full_name, email, password_hash, role FROM users WHERE email = ?', [email]);
        const user = users[0];
        if (!user || !(await verifyPassword(req.body.password || '', user.password_hash))) {
            return renderError(res, 'Email or password is incorrect.', 401);
        }
        if ((loginType === 'admin') !== (user.role === 'admin')) {
            return renderError(res, loginType === 'admin'
                ? 'This account is not an administrator. Choose User Sign In.'
                : 'This is an administrator account. Choose Admin Sign In.');
        }
        setLoginCookie(res, user);
        res.redirect(user.role === 'admin' ? '/admin' : '/user');
    } catch (err) {
        console.error(err);
        renderError(res, 'Unable to sign in. Please try again.', 500);
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('faculty_session', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' });
    res.redirect('/');
});

app.get('/user', requireLogin, async (req, res) => {
    try {
        const bookings = await query(`SELECT booking_id, event_title, event_type, department,
            DATE_FORMAT(event_date, '%Y-%m-%d') AS event_date, expected_attendees,
            TIME_FORMAT(start_time, '%H:%i') AS start_time, TIME_FORMAT(end_time, '%H:%i') AS end_time,
            venue, organizer_name, contact_email, faculty_member, special_requests, booking_status, rejection_message
            FROM event_bookings WHERE LOWER(owner_email) = LOWER(?) ORDER BY event_date DESC, start_time ASC`, [req.user.email]);
        const history = bookings.length ? await query(`SELECT h.booking_id, h.previous_status, h.new_status,
            h.changed_by, DATE_FORMAT(h.changed_at, '%Y-%m-%d %H:%i') AS changed_at
            FROM booking_status_history h JOIN event_bookings b ON b.booking_id = h.booking_id
            WHERE LOWER(b.owner_email) = LOWER(?) ORDER BY h.changed_at DESC`, [req.user.email]) : [];
        const notifications = await query(`SELECT notification_id, booking_id, notification_type, title, message,
            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
            FROM booking_notifications WHERE LOWER(contact_email) = LOWER(?) ORDER BY created_at DESC, notification_id DESC`, [req.user.email]);
        await query('UPDATE booking_notifications SET is_read = 1 WHERE LOWER(contact_email) = LOWER(?) AND is_read = 0', [req.user.email]);
        res.locals.unreadNotificationCount = 0;
        res.render('user', { bookings, history, notifications, resubmitError: req.query.resubmit === 'conflict' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Unable to load your booking history.');
    }
});

// Keep old bookmarks and forwarded links from ending at a removed chat page.
app.get('/messages', requireLogin, (req, res) => {
    res.redirect(req.user.role === 'admin' ? '/admin' : '/user');
});

app.get('/book', requireLogin, async (req, res) => {
    try {
        const result = await query(`SELECT COUNT(*) AS total,
            COALESCE(SUM(booking_status = 'Pending'), 0) AS pending,
            COALESCE(SUM(booking_status = 'Approved'), 0) AS approved,
            COALESCE(SUM(booking_status = 'Rejected'), 0) AS rejected FROM event_bookings`);
        res.render('index', { stats: result[0] });
    } catch (err) {
        console.error(err);
        res.status(500).send('Unable to load the booking form.');
    }
});

app.post(['/register', '/book'], requireLogin, async (req, res) => {
    const { event_title, event_type, department, event_description, event_date, start_time, end_time, venue, faculty_member, special_requests } = req.body;
    const organizer_name = String(req.body.organizer_name || '').trim();
    const otherEventType = String(req.body.other_event_type || '').trim();
    const savedEventType = event_type === 'Other' ? `Other: ${otherEventType}` : event_type;
    const expected_attendees = Number(req.body.expected_attendees);
    const contact_email = String(req.body.contact_email || '').trim().toLowerCase();
    const owner_email = req.user.email;
    if (!event_title || !event_title.length || !event_type || !department || !event_date || !start_time || !end_time || !venue || !organizer_name || organizer_name.length > 150 ||
        !Number.isInteger(expected_attendees) || expected_attendees < 1) return res.status(400).send('Please complete all required fields correctly.');
    if (contact_email.length > 150 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact_email)) {
        return res.status(400).send('Enter a valid contact email address.');
    }
    if (!isValidDateInput(event_date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(start_time) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(end_time)) {
        return res.status(400).send('Enter a valid event date and time.');
    }
    if (event_type === 'Other' && !otherEventType) return res.status(400).send('Please specify the type of event.');
    if (otherEventType.length > 80) return res.status(400).send('The event type clarification must be 80 characters or fewer.');
    if (end_time <= start_time) return res.status(400).send('End time must be later than start time.');
    try {
        const conflict = await query(`SELECT booking_id FROM event_bookings WHERE DATE(event_date) = DATE(?)
            AND LOWER(TRIM(venue)) = LOWER(TRIM(?))
            AND UPPER(TRIM(booking_status)) IN ('PENDING', 'APPROVED', 'CONFIRMED')
            AND TIME(start_time) < TIME(?) AND TIME(end_time) > TIME(?)`, [event_date, venue, end_time, start_time]);
        if (conflict.length) return res.status(409).send('This venue already has a pending or confirmed booking during that time.');
        const result = await query(`INSERT INTO event_bookings (event_title, event_type, department, event_description,
            event_date, expected_attendees, start_time, end_time, venue, organizer_name, contact_email, owner_email,
            faculty_member, special_requests) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [event_title, savedEventType, department, event_description || '', event_date, expected_attendees, start_time, end_time,
                venue, organizer_name, contact_email, owner_email, faculty_member || '', special_requests || '']);
        await query('INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by) VALUES (?, NULL, ?, ?)',
            [result.insertId, 'Pending', req.user.email]);
        res.redirect('/user');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error saving booking.');
    }
});

app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const bookings = await query(`SELECT booking_id, event_title, event_type, department, event_description,
            DATE_FORMAT(event_date, '%Y-%m-%d') AS event_date, expected_attendees,
            TIME_FORMAT(start_time, '%H:%i') AS start_time, TIME_FORMAT(end_time, '%H:%i') AS end_time,
            venue, organizer_name, contact_email, faculty_member, special_requests, booking_status
            FROM event_bookings ORDER BY event_date DESC, start_time ASC`);
        res.render('view', { bookings });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error loading bookings.');
    }
});
app.get('/admin/calendar', requireAdmin, async (req, res) => {
    try {
        const bookings = await query(`SELECT booking_id, event_title,
            DATE_FORMAT(event_date, '%Y-%m-%d') AS event_date,
            TIME_FORMAT(start_time, '%H:%i') AS start_time,
            TIME_FORMAT(end_time, '%H:%i') AS end_time, venue, booking_status
            FROM event_bookings ORDER BY event_date ASC, start_time ASC`);
        res.render('calendar', { bookings });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error loading booking availability.');
    }
});
app.get('/view', (req, res) => res.redirect('/admin'));

app.post('/status/:id', requireAdmin, async (req, res) => {
    const bookingId = req.params.id;
    const status = req.body.booking_status;
    if (!/^\d+$/.test(bookingId)) return res.status(400).send('Invalid booking ID.');
    if (!['Approved', 'Rejected'].includes(status)) return res.status(400).send('Choose Confirm or Decline.');
    try {
        if (status === 'Approved') {
            const conflicts = await query(`SELECT other.booking_id FROM event_bookings current_booking JOIN event_bookings other
                ON DATE(current_booking.event_date) = DATE(other.event_date)
                AND LOWER(TRIM(current_booking.venue)) = LOWER(TRIM(other.venue))
                AND current_booking.booking_id <> other.booking_id WHERE current_booking.booking_id = ?
                AND UPPER(TRIM(other.booking_status)) IN ('APPROVED', 'CONFIRMED')
                AND TIME(current_booking.start_time) < TIME(other.end_time)
                AND TIME(current_booking.end_time) > TIME(other.start_time)`, [bookingId]);
            if (conflicts.length) return res.status(409).send('Cannot confirm: this venue is already booked for another event at that time.');
        }
        const current = await query(`SELECT booking_status, event_title, owner_email, DATE_FORMAT(event_date, '%Y-%m-%d') AS event_date,
            TIME_FORMAT(start_time, '%H:%i') AS start_time, TIME_FORMAT(end_time, '%H:%i') AS end_time, venue
            FROM event_bookings WHERE booking_id = ?`, [bookingId]);
        if (!current.length) return res.status(404).send('Booking not found.');
        if (current[0].booking_status !== status) {
            const rejectionMessage = status === 'Rejected'
                ? 'Schedule conflict: Please choose an available date, time, or venue, then resubmit your booking.'
                : null;
            await query('UPDATE event_bookings SET booking_status = ?, rejection_message = ? WHERE booking_id = ?',
                [status, rejectionMessage, bookingId]);
            const historyResult = await query('INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by) VALUES (?, ?, ?, ?)',
                [bookingId, current[0].booking_status, status, req.user.email]);
            await addBookingNotification(bookingId, current[0].owner_email, status, current[0].event_title,
                current[0].event_date, current[0].venue, historyResult.insertId);
        }
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error updating booking.');
    }
});

app.post('/bookings/:id/resubmit', requireLogin, async (req, res) => {
    const bookingId = req.params.id;
    const eventDate = String(req.body.event_date || '').trim();
    const startTime = String(req.body.start_time || '').trim();
    const endTime = String(req.body.end_time || '').trim();
    const venue = String(req.body.venue || '').trim();
    if (!/^\d+$/.test(bookingId)) return res.status(400).send('Invalid booking ID.');
    if (!isValidDateInput(eventDate) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime) || !venue) {
        return res.status(400).send('Enter a valid date, time, and venue.');
    }
    if (endTime <= startTime) return res.status(400).send('End time must be later than start time.');
    try {
        const conflict = await query(`SELECT booking_id FROM event_bookings WHERE booking_id <> ?
            AND DATE(event_date) = DATE(?) AND LOWER(TRIM(venue)) = LOWER(TRIM(?))
            AND UPPER(TRIM(booking_status)) IN ('PENDING', 'APPROVED', 'CONFIRMED')
            AND TIME(start_time) < TIME(?) AND TIME(end_time) > TIME(?) LIMIT 1`,
            [bookingId, eventDate, venue, endTime, startTime]);
        if (conflict.length) return res.redirect('/user?resubmit=conflict');

        const result = await query(`UPDATE event_bookings SET event_date = ?, start_time = ?, end_time = ?, venue = ?,
            booking_status = 'Pending', rejection_message = NULL
            WHERE booking_id = ? AND LOWER(owner_email) = LOWER(?) AND booking_status = 'Rejected'`,
            [eventDate, startTime, endTime, venue, bookingId, req.user.email]);
        if (!result.affectedRows) return res.status(409).send('This rejected booking could not be resubmitted. Refresh My Bookings and try again.');
        await query('INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by) VALUES (?, ?, ?, ?)',
            [bookingId, 'Rejected', 'Pending', req.user.email]);
        res.redirect('/user');
    } catch (err) {
        console.error(err);
        res.status(500).send('Unable to resubmit this booking. Please try again.');
    }
});

app.post('/delete/:id', requireAdmin, async (req, res) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send('Invalid booking ID.');
    try {
        await query('DELETE FROM booking_notifications WHERE booking_id = ?', [req.params.id]);
        await query('DELETE FROM booking_status_history WHERE booking_id = ?', [req.params.id]);
        const result = await query('DELETE FROM event_bookings WHERE booking_id = ?', [req.params.id]);
        if (!result.affectedRows) return res.status(404).send('Booking not found.');
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting booking.');
    }
});

ensureSchema().then(() => {
    app.listen(PORT, () => console.log(`Faculty Booking System running on port ${PORT}.`));
})
    .catch(err => {
        console.error('Database setup failed:', err.message);
        process.exitCode = 1;
    });

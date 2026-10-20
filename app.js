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
let adminSetupInProgress = false;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.static('public'));

function query(sql, values = []) {
    return new Promise((resolve, reject) => {
        conn.query(sql, values, (err, result) => err ? reject(err) : resolve(result));
    });
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

    // Existing bookings are associated with accounts by their contact email.
    await query(`INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by)
        SELECT b.booking_id, NULL, b.booking_status, b.contact_email
        FROM event_bookings b
        LEFT JOIN booking_status_history h ON h.booking_id = b.booking_id
        WHERE h.history_id IS NULL`);

}

app.get('/', async (req, res) => {
    try {
        const admins = await query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1");
        res.render('home', { adminSetupAvailable: admins.length === 0 });
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
    const email = (req.body.email || '').trim().toLowerCase();
    const loginType = req.body.login_type;
    if (!['user', 'admin'].includes(loginType)) return renderError(res, 'Choose User Sign In or Admin Sign In.');
    try {
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
            venue, organizer_name, contact_email, faculty_member, special_requests, booking_status
            FROM event_bookings WHERE LOWER(contact_email) = LOWER(?) ORDER BY event_date DESC, start_time ASC`, [req.user.email]);
        const history = bookings.length ? await query(`SELECT h.booking_id, h.previous_status, h.new_status,
            h.changed_by, DATE_FORMAT(h.changed_at, '%Y-%m-%d %H:%i') AS changed_at
            FROM booking_status_history h JOIN event_bookings b ON b.booking_id = h.booking_id
            WHERE LOWER(b.contact_email) = LOWER(?) ORDER BY h.changed_at DESC`, [req.user.email]) : [];
        res.render('user', { bookings, history });
    } catch (err) {
        console.error(err);
        res.status(500).send('Unable to load your booking history.');
    }
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
    const otherEventType = String(req.body.other_event_type || '').trim();
    const savedEventType = event_type === 'Other' ? `Other: ${otherEventType}` : event_type;
    const expected_attendees = Number(req.body.expected_attendees);
    const organizer_name = req.user.full_name;
    const contact_email = req.user.email;
    if (!event_title || !event_type || !department || !event_date || !start_time || !end_time || !venue ||
        !Number.isInteger(expected_attendees) || expected_attendees < 1) return res.status(400).send('Please complete all required fields correctly.');
    if (event_type === 'Other' && !otherEventType) return res.status(400).send('Please specify the type of event.');
    if (otherEventType.length > 80) return res.status(400).send('The event type clarification must be 80 characters or fewer.');
    if (end_time <= start_time) return res.status(400).send('End time must be later than start time.');
    try {
        const conflict = await query(`SELECT booking_id FROM event_bookings WHERE event_date = ?
            AND LOWER(TRIM(venue)) = LOWER(TRIM(?)) AND booking_status IN ('Pending', 'Approved')
            AND start_time < ? AND end_time > ?`, [event_date, venue, end_time, start_time]);
        if (conflict.length) return res.status(409).send('This venue already has a pending or approved booking during that time.');
        const result = await query(`INSERT INTO event_bookings (event_title, event_type, department, event_description,
            event_date, expected_attendees, start_time, end_time, venue, organizer_name, contact_email,
            faculty_member, special_requests) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [event_title, savedEventType, department, event_description || '', event_date, expected_attendees, start_time, end_time,
                venue, organizer_name, contact_email, faculty_member || '', special_requests || '']);
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
app.get('/view', (req, res) => res.redirect('/admin'));

app.post('/status/:id', requireAdmin, async (req, res) => {
    const bookingId = req.params.id;
    const status = req.body.booking_status;
    if (!/^\d+$/.test(bookingId)) return res.status(400).send('Invalid booking ID.');
    if (!['Approved', 'Rejected'].includes(status)) return res.status(400).send('Choose Confirm or Decline.');
    try {
        if (status === 'Approved') {
            const conflicts = await query(`SELECT other.booking_id FROM event_bookings current_booking JOIN event_bookings other
                ON current_booking.event_date = other.event_date AND LOWER(TRIM(current_booking.venue)) = LOWER(TRIM(other.venue))
                AND current_booking.booking_id <> other.booking_id WHERE current_booking.booking_id = ?
                AND other.booking_status = 'Approved' AND current_booking.start_time < other.end_time
                AND current_booking.end_time > other.start_time`, [bookingId]);
            if (conflicts.length) return res.status(409).send('Cannot confirm: this venue is already approved for another event at that time.');
        }
        const current = await query('SELECT booking_status FROM event_bookings WHERE booking_id = ?', [bookingId]);
        if (!current.length) return res.status(404).send('Booking not found.');
        if (current[0].booking_status !== status) {
            await query('UPDATE event_bookings SET booking_status = ? WHERE booking_id = ?', [status, bookingId]);
            await query('INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by) VALUES (?, ?, ?, ?)',
                [bookingId, current[0].booking_status, status, req.user.email]);
        }
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error updating booking.');
    }
});

app.post('/delete/:id', requireAdmin, async (req, res) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send('Invalid booking ID.');
    try {
        await query('DELETE FROM booking_status_history WHERE booking_id = ?', [req.params.id]);
        const result = await query('DELETE FROM event_bookings WHERE booking_id = ?', [req.params.id]);
        if (!result.affectedRows) return res.status(404).send('Booking not found.');
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting booking.');
    }
});

ensureSchema().then(() => app.listen(PORT, () => console.log(`Faculty Booking System running on port ${PORT}.`)))
    .catch(err => {
        console.error('Database setup failed:', err.message);
        process.exitCode = 1;
    });

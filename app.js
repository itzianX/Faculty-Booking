
const express = require('express');
const conn = require('./conn');
const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// DASHBOARD AND BOOKING FORM
app.get('/', (req, res) => {
    const sql = `
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(booking_status = 'Pending'), 0) AS pending,
            COALESCE(SUM(booking_status = 'Approved'), 0) AS approved,
            COALESCE(SUM(booking_status = 'Rejected'), 0) AS rejected
        FROM event_bookings
    `;

    conn.query(sql, (err, result) => {
        if (err) {
            console.log(err);
            return res.send('Error loading dashboard.');
        }

        res.render('index', {
            stats: result[0]
        });
    });
});

// REGISTER A BOOKING
app.post('/register', (req, res) => {
    const event_title = req.body.event_title;
    const event_type = req.body.event_type;
    const department = req.body.department;
    const event_description = req.body.event_description;
    const event_date = req.body.event_date;
    const expected_attendees = Number(req.body.expected_attendees);
    const start_time = req.body.start_time;
    const end_time = req.body.end_time;
    const venue = req.body.venue;
    const organizer_name = req.body.organizer_name;
    const contact_email = req.body.contact_email;
    const faculty_member = req.body.faculty_member;
    const special_requests = req.body.special_requests;

    if (
        !event_title || !event_type || !department ||
        !event_date || !start_time || !end_time ||
        !venue || !organizer_name || !contact_email ||
        !Number.isInteger(expected_attendees) ||
        expected_attendees < 1
    ) {
        return res.send('Please complete all required fields correctly.');
    }

    if (end_time <= start_time) {
        return res.send('End time must be later than start time.');
    }

    // CHECK FOR OVERLAPPING BOOKINGS AT THE SAME VENUE
    const checkSql = `
        SELECT booking_id
        FROM event_bookings
        WHERE event_date = ?
        AND LOWER(TRIM(venue)) = LOWER(TRIM(?))
        AND booking_status IN ('Pending', 'Approved')
        AND start_time < ?
        AND end_time > ?
    `;

    conn.query(
        checkSql,
        [event_date, venue, end_time, start_time],
        (err, result) => {
            if (err) {
                console.log(err);
                return res.send('Error checking venue availability.');
            }

            if (result.length > 0) {
                return res.send(
                    'This venue already has a pending or approved booking during that time. Please choose another time or venue.'
                );
            }

            const sql = `
                INSERT INTO event_bookings
                (
                    event_title, event_type, department,
                    event_description, event_date,
                    expected_attendees, start_time, end_time,
                    venue, organizer_name, contact_email,
                    faculty_member, special_requests
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            const values = [
                event_title,
                event_type,
                department,
                event_description,
                event_date,
                expected_attendees,
                start_time,
                end_time,
                venue,
                organizer_name,
                contact_email,
                faculty_member,
                special_requests
            ];

            conn.query(sql, values, (err) => {
                if (err) {
                    console.log(err);
                    return res.send('Error saving booking.');
                }

                res.redirect('/view');
            });
        }
    );
});

// VIEW ALL BOOKINGS
app.get('/view', (req, res) => {
    const sql = `
        SELECT
            booking_id,
            event_title,
            event_type,
            department,
            DATE_FORMAT(event_date, '%Y-%m-%d') AS event_date,
            expected_attendees,
            TIME_FORMAT(start_time, '%H:%i') AS start_time,
            TIME_FORMAT(end_time, '%H:%i') AS end_time,
            venue,
            organizer_name,
            contact_email,
            faculty_member,
            special_requests,
            booking_status
        FROM event_bookings
        ORDER BY event_date DESC, start_time ASC
    `;

    conn.query(sql, (err, result) => {
        if (err) {
            console.log(err);
            return res.send('Error loading bookings.');
        }

        res.render('view', {
            bookings: result
        });
    });
});

// UPDATE BOOKING STATUS
app.post('/status/:id', (req, res) => {
    const booking_id = req.params.id;
    const booking_status = req.body.booking_status;

    const allowed_status = [
        'Pending',
        'Approved',
        'Rejected',
        'Cancelled'
    ];

    if (!/^\d+$/.test(booking_id)) {
        return res.send('Invalid booking ID.');
    }

    if (!allowed_status.includes(booking_status)) {
        return res.send('Invalid booking status.');
    }

    // CHECK VENUE AVAILABILITY BEFORE APPROVING
    if (booking_status === 'Approved') {
        const checkSql = `
            SELECT other.booking_id
            FROM event_bookings AS current_booking
            JOIN event_bookings AS other
                ON current_booking.event_date = other.event_date
                AND LOWER(TRIM(current_booking.venue)) =
                    LOWER(TRIM(other.venue))
                AND current_booking.booking_id <> other.booking_id
            WHERE current_booking.booking_id = ?
            AND other.booking_status = 'Approved'
            AND current_booking.start_time < other.end_time
            AND current_booking.end_time > other.start_time
        `;

        conn.query(checkSql, [booking_id], (err, result) => {
            if (err) {
                console.log(err);
                return res.send('Error checking booking availability.');
            }

            if (result.length > 0) {
                return res.send(
                    'Cannot approve this booking because the venue is already approved for another event at that time.'
                );
            }

            updateStatus(booking_id, booking_status, res);
        });

        return;
    }

    updateStatus(booking_id, booking_status, res);
});

function updateStatus(booking_id, booking_status, res) {
    const sql = `
        UPDATE event_bookings
        SET booking_status = ?
        WHERE booking_id = ?
    `;

    conn.query(sql, [booking_status, booking_id], (err, result) => {
        if (err) {
            console.log(err);
            return res.send('Error updating booking.');
        }

        if (result.affectedRows === 0) {
            return res.send('Booking not found.');
        }

        res.redirect('/view');
    });
}

// DELETE BOOKING
app.post('/delete/:id', (req, res) => {
    const booking_id = req.params.id;

    if (!/^\d+$/.test(booking_id)) {
        return res.send('Invalid booking ID.');
    }

    const sql = 'DELETE FROM event_bookings WHERE booking_id = ?';

    conn.query(sql, [booking_id], (err, result) => {
        if (err) {
            console.log(err);
            return res.send('Error deleting booking.');
        }

        if (result.affectedRows === 0) {
            return res.send('Booking not found.');
        }

        res.redirect('/view');
    });
});

app.listen(9000);


const mysql = require('mysql');

const conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'faculty_booking'
});

conn.connect((err) => {
    if (err) {
        console.log('Database connection failed:', err.message);
        return;
    }

    console.log('MySQL Connected!');
});

module.exports = conn;

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'super_secret_school_key';

app.use(express.json());
app.use(express.static('.'));

// Подключение к базе данных SQLite
const db = new sqlite3.Database('./school.db', (err) => {
    if (err) console.error('Ошибка подключения к БД:', err.message);
    else console.log('Подключено к базе данных SQLite.');
});

// Создание таблиц (включая расписание и посещаемость)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            class_id INTEGER,
            FOREIGN KEY (class_id) REFERENCES classes(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            grade INTEGER NOT NULL,
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            day_of_week TEXT NOT NULL,
            lesson_time TEXT NOT NULL,
            FOREIGN KEY (class_id) REFERENCES classes(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            schedule_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (schedule_id) REFERENCES schedule(id)
        )
    `);
});

// Middleware для проверки JWT и прав учителя
function verifyTeacherToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Нет токена авторизации" });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Неверный или просроченный токен" });
        if (user.role !== 'teacher') return res.status(403).json({ error: "Доступ разрешен только учителям" });
        req.user = user;
        next();
    });
}

// Middleware для общей проверки JWT
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Нет токена авторизации" });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Неверный или просроченный токен" });
        req.user = user;
        next();
    });
}

// --- СПРАВОЧНИКИ (Классы и Предметы) ---

app.get('/api/classes', (req, res) => {
    db.all(`SELECT * FROM classes`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/classes', (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Укажите название класса" });

    db.run(`INSERT INTO classes (name) VALUES (?)`, [name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Класс добавлен", id: this.lastID });
    });
});

app.get('/api/subjects', (req, res) => {
    db.all(`SELECT * FROM subjects`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/subjects', (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Укажите название предмета" });

    db.run(`INSERT INTO subjects (name) VALUES (?)`, [name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Предмет добавлен", id: this.lastID });
    });
});

// Получить список учеников
app.get('/api/students', (req, res) => {
    db.all(`SELECT id, username FROM users WHERE role = 'student'`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ ---

app.post('/api/register', async (req, res) => {
    const { username, password, role, class_id } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ error: "Заполните все обязательные поля" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (username, password, role, class_id) VALUES (?, ?, ?, ?)`;
        db.run(sql, [username, hashedPassword, role, class_id || null], function(err) {
            if (err) return res.status(400).json({ error: "Пользователь уже существует или ошибка БД" });
            res.json({ message: "Регистрация успешна!" });
        });
    } catch (err) {
        res.status(500).json({ error: "Ошибка сервера при хэшировании" });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: "Введите логин и пароль" });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: "Неверный логин или пароль" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: "Неверный логин или пароль" });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, role: user.role, username: user.username });
    });
});

// --- ОЦЕНКИ ---

app.get('/api/grades', verifyToken, (req, res) => {
    if (req.user.role === 'teacher') {
        const sql = `
            SELECT grades.id, users.username AS student, subjects.name AS subject, grades.grade
            FROM grades
            JOIN users ON grades.student_id = users.id
            JOIN subjects ON grades.subject_id = subjects.id
        `;
        db.all(sql, [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    } else {
        const sql = `
            SELECT grades.id, subjects.name AS subject, grades.grade
            FROM grades
            JOIN subjects ON grades.subject_id = subjects.id
            WHERE grades.student_id = ?
        `;
        db.all(sql, [req.user.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            
            let avg = 0;
            if (rows.length > 0) {
                const sum = rows.reduce((acc, curr) => acc + curr.grade, 0);
                avg = (sum / rows.length).toFixed(2);
            }
            res.json({ grades: rows, average: avg });
        });
    }
});

app.post('/api/grades', verifyTeacherToken, (req, res) => {
    const { student_id, subject_id, grade } = req.body;
    if (!student_id || !subject_id || !grade) {
        return res.status(400).json({ error: "Заполните все поля!" });
    }

    const sql = `INSERT INTO grades (student_id, subject_id, grade) VALUES (?, ?, ?)`;
    db.run(sql, [student_id, subject_id, grade], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Оценка успешно добавлена!" });
    });
});

app.delete('/api/grades/:id', verifyTeacherToken, (req, res) => {
    const gradeId = req.params.id;
    const sql = `DELETE FROM grades WHERE id = ?`;
    db.run(sql, [gradeId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: "Оценка не найдена" });
        res.json({ message: "Оценка успешно удалена!" });
    });
});

// --- РАСПИСАНИЕ И ПОСЕЩАЕМОСТЬ ---

app.get('/api/schedule', (req, res) => {
    let sql = `
        SELECT schedule.id, classes.name AS class_name, subjects.name AS subject_name, schedule.day_of_week, schedule.lesson_time
        FROM schedule
        JOIN classes ON schedule.class_id = classes.id
        JOIN subjects ON schedule.subject_id = subjects.id
    `;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/schedule', verifyTeacherToken, (req, res) => {
    const { class_id, subject_id, day_of_week, lesson_time } = req.body;
    if (!class_id || !subject_id || !day_of_week || !lesson_time) {
        return res.status(400).json({ error: "Заполните все поля расписания!" });
    }

    const sql = `INSERT INTO schedule (class_id, subject_id, day_of_week, lesson_time) VALUES (?, ?, ?, ?)`;
    db.run(sql, [class_id, subject_id, day_of_week, lesson_time], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Урок успешно добавлен в расписание!" });
    });
});

app.post('/api/attendance', verifyTeacherToken, (req, res) => {
    const { student_id, schedule_id, date, status } = req.body;
    if (!student_id || !schedule_id || !date || !status) {
        return res.status(400).json({ error: "Заполните все данные посещаемости!" });
    }

    const sql = `INSERT INTO attendance (student_id, schedule_id, date, status) VALUES (?, ?, ?, ?)`;
    db.run(sql, [student_id, schedule_id, date, status], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Посещаемость успешно сохранена!" });
    });
});

app.get('/api/attendance/:student_id', (req, res) => {
    const studentId = req.params.student_id;
    const sql = `
        SELECT attendance.date, subjects.name AS subject, schedule.lesson_time, attendance.status
        FROM attendance
        JOIN schedule ON attendance.schedule_id = schedule.id
        JOIN subjects ON schedule.subject_id = subjects.id
        WHERE attendance.student_id = ?
    `;
    db.all(sql, [studentId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
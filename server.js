const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = "super-secret-key-school";

app.use(express.json());

// Отдаем главную страницу
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Подключаемся к базе данных
const db = new sqlite3.Database('./school.db', (err) => {
    if (err) console.error('Ошибка БД:', err.message);
    else console.log('Реляционная база данных подключена.');
});

// Создаем связанные таблицы
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
});

// --- АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ ---

app.post('/api/register', async (req, res) => {
    const { username, password, role, class_id } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ error: "Заполните обязательные поля!" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (username, password, role, class_id) VALUES (?, ?, ?, ?)`;
        
        db.run(sql, [username, hashedPassword, role, class_id || null], function(err) {
            if (err) {
                return res.status(400).json({ error: "Такое имя пользователя уже занято!" });
            }
            res.status(201).json({ message: "Регистрация успешна!" });
        });
    } catch (err) {
        res.status(500).json({ error: "Ошибка сервера" });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: "Неверный логин или пароль" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Неверный логин или пароль" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, class_id: user.class_id }, 
            SECRET_KEY, 
            { expiresIn: '1h' }
        );

        res.json({ message: "Успешный вход!", token, role: user.role });
    });
});

// --- СПРАВОЧНИКИ (Классы и Предметы) ---

app.get('/api/classes', (req, res) => {
    db.all("SELECT * FROM classes", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/classes', (req, res) => {
    const { name } = req.body;
    db.run("INSERT INTO classes (name) VALUES (?)", [name], function(err) {
        if (err) return res.status(400).json({ error: "Класс уже существует" });
        res.status(201).json({ id: this.lastID, name });
    });
});

app.get('/api/subjects', (req, res) => {
    db.all("SELECT * FROM subjects", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/subjects', (req, res) => {
    const { name } = req.body;
    db.run("INSERT INTO subjects (name) VALUES (?)", [name], function(err) {
        if (err) return res.status(400).json({ error: "Предмет уже существует" });
        res.status(201).json({ id: this.lastID, name });
    });
});

// --- РАБОТА С ОЦЕНКАМИ ---

// Получить оценки с учетом роли
app.get('/api/grades', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    let tokenUser = null;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        try {
            tokenUser = jwt.verify(token, SECRET_KEY);
        } catch (e) {}
    }

    let sql = `
        SELECT grades.id, users.username AS student, subjects.name AS subject, grades.grade, grades.student_id 
        FROM grades
        JOIN users ON grades.student_id = users.id
        JOIN subjects ON grades.subject_id = subjects.id
    `;

    if (tokenUser && tokenUser.role === 'student') {
        sql += ` WHERE grades.student_id = ?`;
        db.all(sql, [tokenUser.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            
            // Считаем средний балл ученика
            let average = 0;
            if (rows.length > 0) {
                const sum = rows.reduce((acc, curr) => acc + curr.grade, 0);
                average = (sum / rows.length).toFixed(2);
            }

            res.json({ grades: rows, average });
        });
    } else {
        db.all(sql, [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ grades: rows });
        });
    }
});

// Middleware проверки токена учителя
const verifyTeacherToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Нет токена авторизации" });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err || decoded.role !== 'teacher') {
            return res.status(403).json({ error: "Доступ запрещен!" });
        }
        req.user = decoded;
        next();
    });
};

// Добавить оценку (только учитель)
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
// Добавить оценку (только учитель)
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
// Удалить оценку по ID (только для учителя)
app.delete('/api/grades/:id', verifyTeacherToken, (req, res) => {
    const gradeId = req.params.id;

    const sql = `DELETE FROM grades WHERE id = ?`;
    db.run(sql, [gradeId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        if (this.changes === 0) {
            return res.status(404).json({ error: "Оценка не найдена" });
        }

        res.json({ message: "Оценка успешно удалена!" });
    });
});
// Список учеников для выбора учителем
app.get('/api/students', (req, res) => {
    db.all("SELECT id, username FROM users WHERE role = 'student'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`Сервер запущен и работает: http://localhost:${PORT}`);
});
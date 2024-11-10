const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');
const defaultUser = {
    id: 1,
    firstName: 'Bono',
    lastName: 'Tadic',
    email: 'bono.tadic@fer.hr',
    phone: '+385 93 234 8273'
};

db.serialize(() => {
    db.run("CREATE TABLE sql_user (id INT, name TEXT)");

    const stmt = db.prepare("INSERT INTO sql_user VALUES (?, ?)");
    stmt.run(1, 'Antonio');
    stmt.run(2, 'Jelena');
    stmt.run(3, 'Mislav');
    stmt.finalize();

    db.run(`CREATE TABLE csrf_user (
        id INTEGER PRIMARY KEY,
        firstName TEXT,
        lastName TEXT,
        email TEXT,
        phone TEXT
    )`);

    db.run(`INSERT INTO csrf_user (id, firstName, lastName, email, phone) VALUES (?, ?, ?, ?, ?)`,
        [defaultUser.id, defaultUser.firstName, defaultUser.lastName, defaultUser.email, defaultUser.phone]);
});

module.exports = { db, defaultUser };

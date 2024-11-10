const cookieParser = require('cookie-parser');
const express = require('express');
const { db, defaultUser } = require('./database');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const app = express();
const port = 3000;

const secret = "rTZ[7&ZQ%&8{B3z(FF#'/#$sks^~7^";
const sessionId = "43335310fafc27a2e0e0634f4c0e7905";
const csrfToken = crypto.randomBytes(16).toString('hex');

let csrfVulnerabilityEnabled = true;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());
app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = csrfToken
    }

    if (!req.cookies['sessionId']) {
        res.cookie('sessionId', sessionId, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    }

    next();
});

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/sql-injection', (req, res) => {
    res.render('sql-injection', { vulnerable: false, rows: [] });
});

app.post('/test-sql', (req, res) => {
    const { userName, vulnerable } = req.body;
    let sqlQuery = "SELECT * FROM sql_user WHERE name = ?";
    let rows = [];

    if (userName) {
        const insertQuery = "INSERT INTO sql_user (name) VALUES (?)";
        db.run(insertQuery, [userName], (err) => {
            if (err) {
                res.status(500).send("Error inserting new user");
            }
        });
    }

    if (vulnerable === 'on') {
        sqlQuery = `SELECT * FROM sql_user WHERE name = '${userName}'`;
    }

    db.all(sqlQuery, [], (err, result) => {
        if (err) {
            res.status(500).send("Error executing query");
        } else {
            rows = result;
            res.render('sql-injection', { vulnerable: vulnerable === 'on', rows });
        }
    });
});

app.get('/csrf', (req, res) => {
    req.session.csrfVulnerabilityEnabled = csrfVulnerabilityEnabled
    db.get("SELECT * FROM csrf_user WHERE id = 1", (err, user) => {
        if (err || !user) {
            res.render('csrf', { user: null, csrfToken, csrfVulnerabilityEnabled, userDeleted: true });
        } else {
            res.render('csrf', { user, csrfToken, csrfVulnerabilityEnabled, userDeleted: false });
        }
    });
});

app.post('/toggle-csrf', (req, res) => {
    csrfVulnerabilityEnabled = req.body.csrfVulnerabilityEnabled === 'on';
    req.session.csrfVulnerabilityEnabled = csrfVulnerabilityEnabled;

    res.redirect('/csrf');
});

app.post('/delete-account', (req, res) => {
    const { csrfToken, redirectToAccountDeleted } = req.body;
    const sessionCsrfToken = req.session.csrfToken;

    if (csrfToken === sessionCsrfToken || csrfVulnerabilityEnabled) {
        db.run('DELETE FROM csrf_user WHERE id = 1', (err) => {
            if (err) {
                return res.status(500).send('Error deleting account');
            }
            req.session.userDeleted = true;
        });
    } else {
        req.query.error = "Unable to perform action! CSRF token mismatch!";
    }

    const shouldDelete = req.session.userDeleted || false;
    const error = req.query.error || null

    if (redirectToAccountDeleted === 'true') {
        return res.render('account-deleted');
    } else {
        res.render('account-security', { shouldDelete, error });
    }
});

app.post('/regenerate-user', (req, res) => {
    db.run('INSERT INTO csrf_user (id, firstName, lastName, email, phone) VALUES (?, ?, ?, ?, ?)',
        [defaultUser.id, defaultUser.firstName, defaultUser.lastName, defaultUser.email, defaultUser.phone], (err) => {
            if (err) {
                return res.status(500).send('Error regenerating user');
            }

            csrfVulnerabilityEnabled = true;
            req.session.userDeleted = false;
            req.session.csrfVulnerabilityEnabled = csrfVulnerabilityEnabled;
            res.redirect('/csrf');
        });
});

app.get('/account-security', (req, res) => {
    const shouldDelete = req.session.userDeleted || true;
    const error = req.query.error || null;

    res.render('account-security', { shouldDelete, error });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

// How another application adds WEVA: list the routes it should guard, and
// call req.weva.loginSucceeded() after a real login. Nothing else changes.
//
//   npm run example       then, in a second terminal:   npm run attack
import express from 'express';
import { wevaSecurity } from 'weva-security';

const app = express();
// app.set('trust proxy', 1);   // behind a reverse proxy (Render, Nginx), so req.ip is the client's address
app.use(express.json());        // before WEVA: it reads the login email from req.body

app.use(wevaSecurity({
    authPaths: ['/api/login'],          // password checks: weight 2, failed attempts tracked
    endpointWeights: {                  // other routes to guard, by blast radius
        '/api/students/:id': 3,         // edits or deletes one record
        '/api/admin/backup': 4          // exports the whole database
    },
    // Every verdict, for the demo. A real app sends these to its audit log or SIEM.
    onEvaluation: e => console.log(`[WEVA] ${e.decision.padEnd(8)} ${e.method} ${e.endpoint} | ${e.decidedBy} ${e.key} | ${e.breakdown.formula}`)
}));

// ---- The application's own routes (authentication left out for brevity). ----
// Only /api/login knows WEVA is there.

const users = new Map([['student@example.edu', 'correct-horse']]);   // demo only; a real app checks a bcrypt hash

app.post('/api/login', (req, res) => {
    const { email, password } = req.body ?? {};
    if (typeof password !== 'string' || users.get(email) !== password) {
        return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }
    req.weva.loginSucceeded(email);   // settles this device's failed attempts at this account
    res.json({ success: true, message: `Welcome, ${email}.` });
});

app.delete('/api/students/:id', (req, res) => res.json({ success: true, deleted: req.params.id }));
app.get('/api/admin/backup', (req, res) => res.json({ success: true, tables: ['students', 'grades'] }));

const port = Number(process.env.PORT) || 4000;
app.listen(port, () => console.log(`Example app guarded by WEVA on http://localhost:${port}`));

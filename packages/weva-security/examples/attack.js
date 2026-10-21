// A scripted password-guessing attack on examples/server.js: one device, one
// wrong password per second (ignoring Retry-After, as a bot would), then the
// right password. Start the server first with `npm run example`.
// Wait 30 s between runs: the IP window remembers a run's failures that long.
const target = process.env.TARGET ?? 'http://localhost:4000';
const deviceId = `DEV-attacker-${Date.now().toString(36)}`;   // a fresh device every run

async function tryLogin(attempt, password) {
    const res = await fetch(`${target}/api/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-device-id': deviceId },
        body: JSON.stringify({ email: 'student@example.edu', password })
    });
    const { message } = await res.json();
    const retryAfter = res.headers.get('retry-after');
    const hint = retryAfter ? `Retry-After: ${retryAfter}s` : '';
    console.log(`#${attempt}  ${password.padEnd(13)} -> ${res.status}  ${hint.padEnd(18)} ${message}`);
}

console.log(`Device ${deviceId} -> POST ${target}/api/login\n`);
for (let attempt = 1; attempt <= 8; attempt++) {
    await tryLogin(attempt, `guess-${attempt}`);
    await new Promise(resolve => setTimeout(resolve, 1000));
}
await tryLogin(9, 'correct-horse');   // the right password, from the now-blocked device

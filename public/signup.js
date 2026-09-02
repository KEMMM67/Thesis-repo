console.log('[signup] Script parsed. Waiting for DOMContentLoaded...');

document.addEventListener('DOMContentLoaded', () => {
    console.log('[signup] DOMContentLoaded fired. Wiring registration form...');

    // No POST /api/signup endpoint exists yet - self-registration is not
    // implemented on the backend (see the Student model's comment in
    // prisma/schema.prisma). This handler preserves the page's existing
    // placeholder behavior (redirect straight to the student dashboard)
    // rather than introducing new registration logic; it only fixes
    // delivery, since this block was previously inline and silently
    // dropped by the strict Content-Security-Policy (see helmet() in
    // server.js) once served through the real app instead of a bare
    // static file.
    try {
        const signupForm = document.getElementById('signupForm');
        if (!signupForm) throw new Error('#signupForm not found in the DOM.');

        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            window.location.href = 'student_dashboard.html';
        });
        console.log('[signup] Registration form wired successfully.');
    } catch (err) {
        console.error('[signup] Failed to wire registration form:', err.message);
    }
});

console.log('[student_dashboard] Script parsed. Waiting for DOMContentLoaded...');

document.addEventListener('DOMContentLoaded', () => {
    console.log('[student_dashboard] DOMContentLoaded fired. Beginning initialization.');

    // =============================================================
    // SIDEBAR NAVIGATION (section switching)
    // =============================================================
    try {
        console.log('[student_dashboard] Wiring sidebar navigation...');
        const sidebarNav = document.getElementById('sidebar-nav');
        const mainTitle = document.getElementById('main-title');
        const sectionContainers = document.querySelectorAll('.section-container');
        if (!sidebarNav) throw new Error('#sidebar-nav not found in the DOM.');

        sidebarNav.addEventListener('click', (e) => {
            const clickedItem = e.target.closest('li');
            if (!clickedItem) return;

            sidebarNav.querySelectorAll('li').forEach(li => li.classList.remove('active'));
            clickedItem.classList.add('active');

            sectionContainers.forEach(container => container.style.display = 'none');
            const targetSectionId = clickedItem.dataset.section;
            document.getElementById(targetSectionId).style.display = 'block';

            mainTitle.innerText = clickedItem.innerText;
        });
        console.log('[student_dashboard] Sidebar navigation wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire sidebar navigation:', err.message);
    }

    // =============================================================
    // PRINTABLE GRADES REPORT
    // =============================================================
    // Mirrors #btnGenerateReport in public/admin_dashboard.js: window.print()
    // is a native browser capability, and style.css's @media print block
    // does the formatting - hiding page chrome and printing only whichever
    // .section-container is currently visible.
    try {
        console.log('[student_dashboard] Wiring printable grades report...');
        const btnPrintGrades = document.getElementById('btnPrintGrades');
        if (!btnPrintGrades) throw new Error('#btnPrintGrades not found in the DOM.');

        btnPrintGrades.addEventListener('click', () => window.print());
        console.log('[student_dashboard] Printable grades report wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire printable grades report:', err.message);
    }

    // =============================================================
    // LOGOUT
    // =============================================================
    // Clears the stored session before the link navigates back to the login
    // page, consistent with goToLogin() in public/admin_dashboard.js -
    // without this, a stale JWT/email would linger in localStorage after
    // logout instead of being cleared immediately.
    try {
        console.log('[student_dashboard] Wiring logout...');
        const btnLogout = document.getElementById('btnLogout');
        if (!btnLogout) throw new Error('#btnLogout not found in the DOM.');

        btnLogout.addEventListener('click', () => {
            localStorage.removeItem('authToken');
            localStorage.removeItem('userEmail');
        });
        console.log('[student_dashboard] Logout wired successfully.');
    } catch (err) {
        console.error('[student_dashboard] Failed to wire logout:', err.message);
    }

    console.log('[student_dashboard] Initialization complete.');
});

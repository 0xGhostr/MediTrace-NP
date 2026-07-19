/**
 * Sidebar toggle — desktop collapse + mobile overlay.
 */
document.addEventListener('DOMContentLoaded', function () {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('sidebarToggle');
    const backdrop = document.getElementById('sidebarBackdrop');
    if (!sidebar || !toggleBtn) return;

    const MOBILE_BP = 992;
    const isMobile = () => window.innerWidth < MOBILE_BP;

    const stored = localStorage.getItem('meditrace_sidebar_collapsed');
    if (stored === '1' && !isMobile()) {
        document.body.classList.add('sidebar-collapsed');
    }

    function closeMobileSidebar() {
        document.body.classList.remove('sidebar-mobile-open');
    }

    function toggleSidebar() {
        if (isMobile()) {
            document.body.classList.toggle('sidebar-mobile-open');
            return;
        }
        document.body.classList.toggle('sidebar-collapsed');
        const collapsed = document.body.classList.contains('sidebar-collapsed');
        localStorage.setItem('meditrace_sidebar_collapsed', collapsed ? '1' : '0');
    }

    toggleBtn.addEventListener('click', toggleSidebar);

    if (backdrop) {
        backdrop.addEventListener('click', closeMobileSidebar);
    }

    window.addEventListener('resize', function () {
        if (!isMobile()) {
            closeMobileSidebar();
        }
    });

    sidebar.querySelectorAll('.nav-link').forEach(function (link) {
        link.addEventListener('click', function () {
            if (isMobile()) closeMobileSidebar();
        });
    });
});

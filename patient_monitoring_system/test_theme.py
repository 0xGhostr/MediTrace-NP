"""Frontend-only Light/Dark Mode integration and regression checks."""
from __future__ import annotations

import re
import sqlite3
import tempfile
from pathlib import Path

from config import Config


PROJECT_ROOT = Path(__file__).resolve().parent


def table_counts(path):
    conn = sqlite3.connect(path)
    tables = [
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    counts = {table: conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in tables}
    conn.close()
    return counts


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH

    with tempfile.TemporaryDirectory(prefix='meditrace-theme-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')
        import app as app_module
        from database import init_db

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None
        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        base = (PROJECT_ROOT / 'templates' / 'base.html').read_text(encoding='utf-8')
        init_js = (PROJECT_ROOT / 'static' / 'js' / 'theme-init.js').read_text(encoding='utf-8')
        toggle_js = (PROJECT_ROOT / 'static' / 'js' / 'theme-toggle.js').read_text(encoding='utf-8')
        theme_css = (PROJECT_ROOT / 'static' / 'css' / 'theme.css').read_text(encoding='utf-8')
        dashboard_js = (PROJECT_ROOT / 'static' / 'js' / 'dashboard.js').read_text(encoding='utf-8')

        assert '<html lang="{{ current_locale|default(\'en\') }}" data-theme="light">' in base
        assert base.index("js/theme-init.js") < base.index("css/style.css")
        assert base.index('{% block extra_head %}') < base.index("css/theme.css")
        assert "localStorage.getItem('meditrace-theme')" in init_js
        assert "saved === 'dark' || saved === 'light'" in init_js
        assert "localStorage.setItem(STORAGE_KEY, theme)" in toggle_js
        assert 'location.reload' not in toggle_js and 'location.href' not in toggle_js
        assert 'fetch(' not in toggle_js
        checks.append('early allowlisted localStorage initialization without navigation')

        assert re.search(r'<button\s+type="button"\s+class="theme-toggle', base)
        assert 'aria-pressed="false"' in base
        assert "data-label-dark=\"{{ _('Switch to Dark Mode') }}\"" in base
        assert "data-label-light=\"{{ _('Switch to Light Mode') }}\"" in base
        assert 'bi bi-moon-stars' in base and "'bi bi-sun'" in toggle_js
        assert '.theme-toggle:focus-visible' in theme_css
        checks.append('semantic keyboard-accessible moon/sun control')

        # The shared authenticated order is Theme, Language, Avatar. Public
        # pages use the same first two controls without changing auth layouts.
        auth_block = base[base.index('authenticated-header-actions'):base.index('sidebar-backdrop')]
        assert auth_block.index('theme_toggle') < auth_block.index('language_switch')
        assert auth_block.index('language_switch') < auth_block.index('header-user-avatar')
        public_block = base[base.index('public-header-actions'):base.index('auth-main container')]
        assert public_block.index('theme_toggle') < public_block.index('language_switch')
        checks.append('shared header placement for authenticated and public pages')

        client = app_module.app.test_client()
        for route in ('/login', '/register', '/account-recovery'):
            response = client.get(route)
            assert response.status_code == 200, route
            html = response.get_data(as_text=True)
            assert 'data-theme="light"' in html
            assert html.index('theme-toggle') < html.index('language-switch')
            assert 'header-user-avatar' not in html

        nepali = client.get('/login', headers={'Accept-Language': 'ne'}).get_data(as_text=True)
        assert 'डार्क मोडमा जानुहोस्' in nepali
        assert 'लाइट मोडमा जानुहोस्' in nepali
        checks.append('public English/Nepali theme labels and control order')

        before = table_counts(Config.DATABASE_PATH)
        login = client.post(
            '/login', data={'username': 'superadmin', 'password': 'Super@123'},
            follow_redirects=True,
        )
        assert login.status_code == 200
        representative_routes = (
            '/admin/dashboard', '/records', '/admin/alerts', '/admin/events',
            '/admin/usb-monitoring', '/admin/users', '/admin/account-recovery',
            '/admin/security', '/admin/messages', '/admin/reports',
            '/admin/patient-data', '/simulated-patient-data',
        )
        for route in representative_routes:
            response = client.get(route)
            assert response.status_code == 200, route
            html = response.get_data(as_text=True)
            assert html.index('theme-toggle') < html.index('language-switch')
            assert html.index('language-switch') < html.index('header-user-avatar')
            assert 'css/theme.css' in html
            assert 'js/theme-toggle.js' in html
        checks.append('shared theme assets across admin/superadmin application areas')

        # Switching language remains its existing POST workflow and does not
        # interact with or clear the browser-owned theme key.
        switched = client.post(
            '/language', data={'language': 'ne', 'next': '/records?page=2&search=PR'},
        )
        assert switched.status_code == 302
        assert 'page=2' in switched.location and 'search=PR' in switched.location
        page = client.get('/records?page=2&search=PR').get_data(as_text=True)
        assert 'डार्क मोडमा जानुहोस्' in page
        assert 'meditrace-theme' not in str(switched.headers.getlist('Set-Cookie'))
        checks.append('language and query-state independence from theme storage')

        required_dark_coverage = (
            '.main-content', '.sidebar-toggle-btn', '.language-switch', '.card',
            '.table', '.form-control', '.modal-content', '.dropdown-menu',
            '.alert-info', '.auth-main', '.pr-table', '.pr-row-restricted',
            '.pr-page-link', '.pr-sensitivity-high', '.pr-sensitivity-critical',
            '.security-alert-card', '.message-list-row', '.recovery-message-box',
            '.usb-device-status', '.scoring-explanation',
        )
        for selector in required_dark_coverage:
            assert selector in theme_css, selector
        assert 'filter: invert' not in theme_css
        assert 'html[data-theme="light"]' not in theme_css
        checks.append('dark-only coverage with unchanged approved Light selectors')

        assert "document.addEventListener('meditrace:themechange'" in dashboard_js
        assert "chart.update('none')" in dashboard_js
        assert 'dashboardCharts.push(chart)' in dashboard_js
        assert 'tooltipBackground' in dashboard_js and 'pieBorder' in dashboard_js
        assert dashboard_js.count('new Chart(') == 3
        checks.append('in-place Chart.js theme refresh without duplicate instances')

        # Theme scripts are deliberately frontend-only and cannot touch Flask,
        # CSRF, authentication, routes, or patient/security data.
        forbidden_js = ('XMLHttpRequest', 'document.cookie', 'sessionStorage', '/api/', 'csrf')
        assert not any(token in init_js + toggle_js for token in forbidden_js)
        after = table_counts(Config.DATABASE_PATH)
        # Login legitimately adds login history and updates last_login; theme
        # rendering itself creates no domain objects or schema changes.
        for protected_table in (
            'patient_records', 'access_events', 'alerts', 'usb_devices',
            'usb_events', 'messages', 'account_recovery_requests',
        ):
            assert before[protected_table] == after[protected_table]
        checks.append('frontend-only security boundary and domain-data preservation')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Theme checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')

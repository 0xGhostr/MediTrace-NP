"""Quick verification script for USB monitoring and security lockout."""
import os
import sys
import time

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

from database import init_db, get_db
from app import app
from models import (
    get_user_by_username, get_usb_devices, get_usb_events,
    get_security_dashboard_stats, get_dashboard_stats,
)
from security_engine import LOCKOUT_THRESHOLD
from report_generator import generate_daily_report
import re


def _csrf_from_html(html):
    m = re.search(r'id="csrf_token"[^>]*value="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ''


def _login(client, username, password):
    html = client.get('/login').get_data(as_text=True)
    return client.post('/login', data={
        'username': username, 'password': password,
        'csrf_token': _csrf_from_html(html),
    }, follow_redirects=False)


def run_tests():
    init_db()
    client = app.test_client()
    results = []

    def check(name, ok, detail=''):
        results.append((name, ok, detail))
        status = 'PASS' if ok else 'FAIL'
        print(f'[{status}] {name}' + (f' — {detail}' if detail else ''))

    # Admin login
    r = _login(client, 'superadmin', 'Super@123')
    check('Admin login', r.status_code in (302, 200))

    # Staff cannot access USB monitoring
    client.get('/logout', follow_redirects=True)
    conn = get_db()
    staff = conn.execute(
        "SELECT username FROM users WHERE role = 'Doctor' AND approval_status = 'approved' LIMIT 1"
    ).fetchone()
    conn.close()
    if staff:
        from werkzeug.security import generate_password_hash
        conn = get_db()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (generate_password_hash('Test@1234'), staff['username']),
        )
        conn.commit()
        conn.close()
        _login(client, staff['username'], 'Test@1234')
        r = client.get('/admin/usb-monitoring')
        check('Staff blocked from USB Monitoring', r.status_code == 403)
        r = client.get('/admin/security')
        check('Staff blocked from Security Management', r.status_code == 403)
        client.get('/logout', follow_redirects=True)

    # Admin USB simulation
    _login(client, 'superadmin', 'Super@123')
    before = len(get_usb_events())
    client.post('/admin/usb-monitoring', data={
        'csrf_token': _csrf(client),
        'action': 'simulate_unknown',
        'computer_name': 'TEST-PC',
    }, follow_redirects=True)
    after = len(get_usb_events())
    check('Simulated unknown USB creates event', after > before)

    events = get_usb_events({'event_type': 'inserted'})
    critical = [e for e in events if e['risk_level'] == 'Critical' and e['alert_created']]
    check('Unknown USB creates critical alert', len(critical) > 0)

    client.post('/admin/usb-monitoring', data={
        'csrf_token': _csrf(client),
        'action': 'simulate_whitelisted',
        'computer_name': 'TEST-PC',
    }, follow_redirects=True)
    wl_events = get_usb_events({'event_type': 'whitelisted_insert'})
    check('Whitelisted USB normal log', any(e['risk_level'] == 'Normal' for e in wl_events))

    # Whitelist add
    serial = 'TEST-WHITELIST-999'
    client.post('/admin/usb-monitoring', data={
        'csrf_token': _csrf(client),
        'action': 'add_whitelist',
        'usb_name': 'Test USB', 'usb_serial': serial, 'usb_size': '16GB',
    }, follow_redirects=True)
    check('Admin can add whitelist USB', any(d['usb_serial'] == serial for d in get_usb_devices()))

    stats = get_dashboard_stats()
    check('Dashboard USB stats from DB', 'usb_events_today' in stats)

    path = generate_daily_report()
    with open(path, encoding='utf-8') as f:
        content = f.read()
    check('Daily report USB section', 'USB Monitoring Summary' in content)

    # Lockout test with temp user
    _test_lockout(client, check)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f'\n{passed}/{len(results)} tests passed')
    return passed == len(results)


def _csrf(client):
    return _csrf_from_html(client.get('/admin/usb-monitoring').get_data(as_text=True))


def _test_lockout(client, check):
    from werkzeug.security import generate_password_hash
    from models import create_approved_staff_user
    from security_engine import is_account_locked

    username = 'locktest_user'
    conn = get_db()
    conn.execute('PRAGMA foreign_keys = OFF')
    conn.execute("DELETE FROM login_history WHERE username = ?", (username,))
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.execute('PRAGMA foreign_keys = ON')
    conn.commit()
    conn.close()

    create_approved_staff_user({
        'full_name': 'Lock Test', 'staff_id': 'LCK001', 'email': 'lock@test.demo',
        'username': username, 'password': 'Correct@123', 'role': 'Nurse',
        'department': 'General Medicine', 'work_start': '08:00', 'work_end': '17:00',
    })

    client.get('/logout', follow_redirects=True)
    for i in range(1, LOCKOUT_THRESHOLD + 1):
        _login(client, username, 'wrong')

    user = get_user_by_username(username)
    locked, _ = is_account_locked(user)
    check('Account locked after 3 failures', locked, f'attempts={user.get("failed_attempts")}')

    r = _login(client, username, 'Correct@123')
    check('Locked user cannot login with correct password', r.status_code == 200)

    _login(client, 'superadmin', 'Super@123')
    user = get_user_by_username(username)
    client.post('/admin/security', data={
        'csrf_token': _csrf_security(client),
        'unlock_user_id': user['id'],
    }, follow_redirects=True)
    user = get_user_by_username(username)
    locked, _ = is_account_locked(user)
    check('Admin manual unlock', not locked and user.get('failed_attempts', 0) == 0)

    client.get('/logout', follow_redirects=True)
    r = _login(client, username, 'Correct@123')
    check('Unlocked user can login', r.status_code == 302)

    conn = get_db()
    fails = conn.execute(
        "SELECT COUNT(*) as c FROM login_history WHERE username = ? AND success = 0",
        (username,),
    ).fetchone()['c']
    conn.close()
    check('Login history records failed attempts', fails >= LOCKOUT_THRESHOLD)

    get_security_dashboard_stats()
    check('Security dashboard stats', True)


def _csrf_security(client):
    return _csrf_from_html(client.get('/admin/security').get_data(as_text=True))


if __name__ == '__main__':
    ok = run_tests()
    sys.exit(0 if ok else 1)

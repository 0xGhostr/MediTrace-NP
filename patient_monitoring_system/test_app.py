"""Quick smoke test for the application."""
import re
import os
from app import app
from models import get_user_by_username
from report_generator import generate_daily_report

with app.test_client() as client:
    r = client.get('/login')
    assert r.status_code == 200
    html = r.data.decode()
    m = re.search(r'csrf_token.*?value="([^"]+)"', html)
    token = m.group(1) if m else ''
    r = client.post('/login', data={
        'username': 'admin', 'password': 'Admin@123', 'csrf_token': token
    }, follow_redirects=True)
    print('Login:', r.status_code)
    assert r.status_code == 200

    r = client.get('/admin/dashboard')
    print('Dashboard:', r.status_code)
    assert r.status_code == 200

    r = client.get('/api/charts/access-timeline')
    print('Chart:', r.status_code, r.json)
    assert r.status_code == 200

    admin_user = get_user_by_username('admin')
    assert admin_user is not None
    path = generate_daily_report(generated_by=admin_user['id'])
    print('Report:', path, os.path.exists(path))
    assert os.path.exists(path)

print('All tests passed!')

import re

from app import app
from database import init_db
from models import get_unread_messages_for_user, get_user_by_username


def extract_csrf(html):
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    return match.group(1) if match else ""


def main():
    init_db()
    client = app.test_client()

    # Registration flow
    page = client.get("/register")
    token = extract_csrf(page.data.decode())
    payload = {
        "full_name": "Test User",
        "staff_id": "TEST999",
        "email": "test999@example.com",
        "username": "test999",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
        "role": "Nurse",
        "department": "General Medicine",
        "work_start": "08:00",
        "work_end": "17:00",
        "csrf_token": token,
    }
    response = client.post("/register", data=payload, follow_redirects=True)
    print("register_status", response.status_code)

    user = get_user_by_username("test999")
    print("user_status", user["approval_status"], user["is_active"])

    # Pending login denied
    page = client.get("/login")
    token = extract_csrf(page.data.decode())
    response = client.post(
        "/login",
        data={"username": "test999", "password": "Test@1234", "csrf_token": token},
        follow_redirects=True,
    )
    print("pending_blocked", b"waiting for admin approval" in response.data)

    # Admin login and dashboard/charts
    page = client.get("/login")
    token = extract_csrf(page.data.decode())
    response = client.post(
        "/login",
        data={"username": "admin", "password": "Admin@123", "csrf_token": token},
        follow_redirects=True,
    )
    print("admin_login", response.status_code)
    print("dashboard_status", client.get("/admin/dashboard").status_code)
    print("timeline_chart", client.get("/api/charts/access-timeline").status_code)
    print("severity_chart", client.get("/api/charts/alerts-by-severity").status_code)

    # Messagin
    messages_page = client.get("/admin/messages")
    token = extract_csrf(messages_page.data.decode())
    doctor_id = get_user_by_username("doctor1")["id"]
    client.post(
        "/admin/messages/send",
        data={
            "receiver_id": str(doctor_id),
            "title": "Notice",
            "body": "Please review logs.",
            "is_urgent": "on",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    print("doctor_has_unread", len(get_unread_messages_for_user(doctor_id)) > 0)


if __name__ == "__main__":
    main()

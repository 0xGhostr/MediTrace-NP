"""Application configuration."""
import os

from record_policy import CANONICAL_SENSITIVITIES

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    APP_NAME = 'MediTrace-Np'
    SECRET_KEY = os.environ.get('SECRET_KEY', 'thesis-dev-secret-change-in-production')
    DATABASE_PATH = os.path.join(BASE_DIR, 'instance', 'database.db')
    SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get('SQLITE_BUSY_TIMEOUT_MS', '30000'))
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    ML_MODEL_PATH = os.path.join(BASE_DIR, 'ml_model', 'model.pkl')
    LOCAL_TIMEZONE = 'Asia/Kathmandu'

    # Record categories and sensitivity levels
    RECORD_CATEGORIES = [
        'General Medical',
        'Billing',
        'Laboratory',
        'HIV-related',
        'Psychiatric',
        'Confidential',
        'Emergency',
    ]

    SENSITIVITY_LEVELS = list(CANONICAL_SENSITIVITIES)

    DEPARTMENTS = [
        'General Medicine',
        'Emergency',
        'Billing',
        'Laboratory',
        'Psychiatry',
        'Infectious Disease',
        'Reception',
        'Administration',
    ]

    ROLES = [
        'Super Admin',
        'Admin',
        'Doctor',
        'Nurse',
        'Receptionist',
        'Billing Staff',
        'Laboratory Staff',
    ]

    # Roles staff can request at self-registration
    STAFF_REGISTER_ROLES = [
        'Doctor', 'Nurse', 'Receptionist', 'Billing Staff', 'Laboratory Staff',
    ]

    ADMIN_PANEL_ROLES = ('Super Admin', 'Admin')

    RISK_LEVELS = ['Normal', 'Medium', 'High', 'Critical']

    # Role-based allowed record categories
    ROLE_ACCESS = {
        'Super Admin': None,
        'Admin': None,  # All categories
        'Doctor': ['General Medical', 'Emergency', 'Confidential'],
        'Nurse': ['General Medical', 'Emergency'],
        'Receptionist': ['General Medical'],
        'Billing Staff': ['Billing'],
        'Laboratory Staff': ['Laboratory'],
    }

    APPROVAL_STATUSES = ['pending', 'approved', 'rejected', 'suspended']

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Public account-recovery abuse controls. Public responses intentionally do
    # not disclose which limit, match, or duplicate condition was encountered.
    RECOVERY_REQUEST_WINDOW_MINUTES = int(
        os.environ.get('RECOVERY_REQUEST_WINDOW_MINUTES', '30')
    )
    RECOVERY_MAX_REQUESTS_PER_IP = int(
        os.environ.get('RECOVERY_MAX_REQUESTS_PER_IP', '5')
    )
    RECOVERY_MAX_REQUESTS_PER_STAFF_ID = int(
        os.environ.get('RECOVERY_MAX_REQUESTS_PER_STAFF_ID', '3')
    )
    RECOVERY_MESSAGE_MAX_LENGTH = 1000
    RECOVERY_REVIEW_NOTES_MAX_LENGTH = 2000
    TEMPORARY_PASSWORD_MIN_LENGTH = 12

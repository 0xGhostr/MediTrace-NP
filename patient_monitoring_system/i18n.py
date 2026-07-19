"""Lightweight, dependency-free English/Nepali internationalisation.

English source strings are the stable translation keys.  The Nepali catalogue is
loaded from ``translations/ne.json`` and missing entries intentionally fall back
to English.  Stored domain values remain canonical English values.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from flask import g, has_request_context, request, session
from flask_login import current_user
from markupsafe import Markup


SUPPORTED_LOCALES = ("en", "ne")
DEFAULT_LOCALE = "en"
LANGUAGE_COOKIE = "meditrace_language"
CATALOGUE_PATH = Path(__file__).with_name("translations") / "ne.json"


@lru_cache(maxsize=1)
def _catalogue() -> dict[str, str]:
    try:
        with CATALOGUE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return {
        str(source): str(translation)
        for source, translation in data.items()
        if source and translation
    }


def normalize_locale(value) -> str | None:
    """Return a supported two-letter locale or ``None`` for invalid input."""
    candidate = str(value or "").strip().lower().replace("_", "-").split("-", 1)[0]
    return candidate if candidate in SUPPORTED_LOCALES else None


def resolve_locale() -> str:
    """Resolve locale in the required authenticated/session/cookie/browser order."""
    if not has_request_context():
        return DEFAULT_LOCALE
    if current_user.is_authenticated:
        saved = normalize_locale(getattr(current_user, "preferred_language", None))
        if saved:
            return saved
    saved = normalize_locale(session.get("language"))
    if saved:
        return saved
    saved = normalize_locale(request.cookies.get(LANGUAGE_COOKIE))
    if saved:
        return saved
    browser = request.accept_languages.best_match(SUPPORTED_LOCALES)
    return normalize_locale(browser) or DEFAULT_LOCALE


def get_locale() -> str:
    if not has_request_context():
        return DEFAULT_LOCALE
    return normalize_locale(getattr(g, "locale", None)) or resolve_locale()


def translate(source, **values) -> str:
    """Translate an English source string and safely interpolate named values."""
    source = str(source or "")
    translated = _catalogue().get(source, source) if get_locale() == "ne" else source
    if values:
        try:
            return translated.format(**values)
        except (KeyError, ValueError):
            return translated
    return translated


_ = translate


def is_safe_next_url(value: str | None) -> bool:
    """Accept only application-local absolute paths, never schemes or // hosts."""
    if not value:
        return False
    value = str(value).strip()
    decoded = unquote(value)
    parsed = urlsplit(decoded)
    return (
        decoded.startswith("/")
        and not decoded.startswith("//")
        and "\\" not in decoded
        and not parsed.scheme
        and not parsed.netloc
        and "\r" not in decoded
        and "\n" not in decoded
    )


DISPLAY_SOURCES = {
    # Workflow/status values
    "open": "Open", "resolved": "Resolved", "pending": "Pending",
    "approved": "Approved", "rejected": "Rejected", "suspended": "Suspended",
    "active": "Active", "inactive": "Inactive", "deleted": "Deleted",
    "in_review": "In Review", "identity_verified": "Identity Verified",
    "cancelled": "Cancelled", "completed": "Completed", "blocked": "Blocked",
    "whitelisted": "Whitelisted", "connected": "Connected", "removed": "Removed",
    "true": "Yes", "false": "No", "yes": "Yes", "no": "No",
    # Risk/sensitivity
    "normal": "Normal", "low": "Low", "medium": "Medium",
    "high": "High", "critical": "Critical", "urgent": "Urgent",
    # Roles
    "super admin": "Super Admin", "admin": "Admin", "doctor": "Doctor",
    "nurse": "Nurse", "lab technician": "Lab Technician",
    "pharmacist": "Pharmacist", "receptionist": "Receptionist",
    # Departments/categories
    "general medicine": "General Medicine", "emergency": "Emergency",
    "cardiology": "Cardiology", "neurology": "Neurology", "orthopedics": "Orthopedics",
    "paediatrics": "Paediatrics", "pediatrics": "Pediatrics", "radiology": "Radiology",
    "laboratory": "Laboratory", "pharmacy": "Pharmacy", "administration": "Administration",
    "general medical": "General Medical", "psychiatric": "Psychiatric",
    "hiv": "HIV", "reproductive health": "Reproductive Health",
    # Actions/events
    "view": "View", "export": "Export", "delete": "Delete", "login": "Login",
    "inserted": "Inserted", "auto_detected": "Auto Detected",
    "whitelisted_insert": "Whitelisted Insert", "export_to_usb": "Export to USB",
    "blocked_export": "Blocked Export", "patient_access_usb": "Patient Access with USB",
    "sensitive_access_usb": "Sensitive Access with USB",
}


def translate_display(value) -> str:
    """Translate a canonical enum-like value without changing the stored value."""
    if value is None:
        return translate("N/A")
    raw = str(value)
    direct = translate(raw)
    if direct != raw:
        return direct
    source = DISPLAY_SOURCES.get(raw.strip().lower(), raw.replace("_", " ").title())
    return translate(source)


def js_messages() -> dict[str, str]:
    keys = (
        "Access Events", "Last 7 days", "{count} access event(s) on {date}",
        "alert(s)", "Month total registrations: {count}",
        "new user(s) registered", "Showing {visible} of {total} records",
        "message", "messages", "{visible} of {total} messages",
        "Blocked USB Connected", "USB Connected (Whitelisted)",
        "USB Pending Review — Monitoring Active",
        "Patient-data USB operations are permitted and continue to be logged.",
        "Patient-record USB export is denied until an administrator whitelists this device.",
        "Serial", "N/A",
    )
    return {key: translate(key) for key in keys}


_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@lru_cache(maxsize=1)
def _dynamic_entries():
    entries = []
    for source, translated in _catalogue().items():
        if not _PLACEHOLDER.search(source):
            continue
        names = _PLACEHOLDER.findall(source)
        pattern = re.escape(source)
        for name in names:
            pattern = pattern.replace(re.escape("{" + name + "}"), rf"(?P<{name}>.+?)", 1)
        entries.append((re.compile(r"^" + pattern + r"$"), translated))
    return entries


def _translate_rendered_text(text: str) -> str:
    if not text or not text.strip():
        return text
    leading = text[: len(text) - len(text.lstrip())]
    trailing = text[len(text.rstrip()):]
    core = text.strip()
    translated = _catalogue().get(core)
    if translated is None:
        for pattern, template in _dynamic_entries():
            match = pattern.match(core)
            if match:
                try:
                    translated = template.format(**match.groupdict())
                except (KeyError, ValueError):
                    translated = None
                break
    return leading + (translated if translated is not None else core) + trailing


_HTML_TOKEN = re.compile(r"(<[^>]+>)")
_TAG_NAME = re.compile(r"^</?\s*([A-Za-z0-9:-]+)")
_TRANSLATABLE_ATTRIBUTE = re.compile(
    r'''(?P<prefix>\b(?:placeholder|aria-label|title|data-confirm)\s*=\s*)(?P<quote>["'])(?P<value>.*?)(?P=quote)''',
    re.IGNORECASE,
)
_NO_TRANSLATE_TAGS = {"script", "style", "code", "pre", "textarea"}


def localize_html(html: str) -> str:
    """Translate fixed rendered HTML text while leaving code/raw evidence untouched."""
    if get_locale() != "ne" or not html:
        return html
    parts = _HTML_TOKEN.split(html)
    suppressed = []
    output = []
    for part in parts:
        if not part:
            continue
        if part.startswith("<"):
            match = _TAG_NAME.match(part)
            tag = match.group(1).lower() if match else ""
            closing = part.startswith("</")
            if closing:
                output.append(part)
                if suppressed and suppressed[-1] == tag:
                    suppressed.pop()
                continue
            no_translate = (
                tag in _NO_TRANSLATE_TAGS
                or bool(re.search(r'''\b(?:translate=["']no["']|data-no-translate)''', part, re.I))
            )
            if no_translate and not part.rstrip().endswith("/>"):
                suppressed.append(tag)
            if not suppressed:
                def replace_attribute(attr_match):
                    value = _translate_rendered_text(attr_match.group("value"))
                    return (
                        attr_match.group("prefix") + attr_match.group("quote")
                        + value + attr_match.group("quote")
                    )
                part = _TRANSLATABLE_ATTRIBUTE.sub(replace_attribute, part)
            output.append(part)
        else:
            output.append(part if suppressed else _translate_rendered_text(part))
    return "".join(output)


def install_i18n(app) -> None:
    """Register locale resolution, template helpers, and HTML localization."""
    @app.before_request
    def select_request_locale():
        g.locale = resolve_locale()

    @app.context_processor
    def inject_i18n_context():
        return {
            "_": translate,
            "current_locale": get_locale(),
            "supported_locales": SUPPORTED_LOCALES,
            "tr_display": translate_display,
            "js_i18n": js_messages(),
        }

    app.jinja_env.globals.update(_=translate, tr_display=translate_display)

    @app.after_request
    def translate_html_response(response):
        if (
            get_locale() == "ne"
            and response.status_code != 204
            and response.mimetype == "text/html"
            and not response.direct_passthrough
        ):
            response.set_data(localize_html(response.get_data(as_text=True)))
            response.headers["Content-Language"] = "ne"
        else:
            response.headers.setdefault("Content-Language", get_locale())
        response.vary.add("Cookie")
        response.vary.add("Accept-Language")
        return response


class LocalizedFormMixin:
    """Translate WTForms labels, choices, descriptions, and validation errors."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self:
            if field.label:
                field.label.text = translate(field.label.text)
            if field.description:
                field.description = translate(field.description)
            if getattr(field, "choices", None):
                field.choices = [(value, translate_display(label)) for value, label in field.choices]

    def validate(self, extra_validators=None):
        valid = super().validate(extra_validators=extra_validators)
        for field in self:
            if field.errors:
                field.errors = tuple(translate(error) for error in field.errors)
        return valid


def mark_safe_translation(source, **values):
    """Explicit helper for catalogue strings that intentionally contain safe markup."""
    return Markup(translate(source, **values))

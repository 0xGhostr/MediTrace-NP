"""Audit centralized translation keys without modifying application data."""
from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CATALOGUE = ROOT / 'translations' / 'ne.json'


def python_translation_keys(path):
    keys = set()
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == '_'
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value)
    return keys


def template_translation_keys(path):
    """Extract simple Jinja `_('literal')` calls with Python's string parser."""
    import re
    keys = set()
    source = path.read_text(encoding='utf-8')
    for match in re.finditer(r"\b_\(\s*(['\"])(.*?)\1", source, re.DOTALL):
        try:
            keys.add(ast.literal_eval(match.group(1) + match.group(2) + match.group(1)))
        except (SyntaxError, ValueError):
            continue
    return keys


def run_audit():
    raw = CATALOGUE.read_text(encoding='utf-8')
    pairs = json.loads(raw, object_pairs_hook=lambda value: value)
    duplicate_keys = sorted(
        key for key, count in Counter(key for key, _ in pairs).items() if count > 1
    )
    if duplicate_keys:
        raise AssertionError(f'Duplicate translation keys: {duplicate_keys}')
    catalogue = dict(pairs)
    empty = sorted(key for key, value in pairs if not key.strip() or not value.strip())
    if empty:
        raise AssertionError(f'Empty translation entries: {empty}')

    used = set()
    for path in ROOT.glob('*.py'):
        if path.name != 'audit_i18n.py':
            used.update(python_translation_keys(path))
    for path in (ROOT / 'templates').glob('*.html'):
        used.update(template_translation_keys(path))
    missing = sorted(key for key in used if key not in catalogue)
    if missing:
        raise AssertionError('Explicit translation keys missing from catalogue: ' + repr(missing))
    return len(catalogue), len(used)


if __name__ == '__main__':
    catalogue_count, explicit_count = run_audit()
    print(f'[PASS] {catalogue_count} unique Nepali translations loaded')
    print(f'[PASS] {explicit_count} explicit Python/Jinja source keys are covered')

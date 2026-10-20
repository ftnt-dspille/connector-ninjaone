#!/usr/bin/env python3
"""Render every Jinja expression in the compiled playbooks against a live FortiSOAR.

Why this exists: the static linter (pyfsr.jinja_validate) reports these playbooks
clean, because it validates *filter names* -- and the bug that actually broke a
run was an invalid **test**, `selectattr(..., 'search', ...)`, which is an
Ansible-ism FortiSOAR does not have. Nothing catches that short of asking the
real renderer, which is what `POST /api/wf/api/jinja-editor/` does.

It also catches the subtler class: an expression that parses but *raises* on real
data. `json_query("[?contains(name, 'x')]")` looks fine and blows up on any row
whose `name` is null -- exactly what the software inventory contains.

    python3 tools/validate_playbook_jinja.py --env /path/to/.env.159

Exit code 1 if any expression fails to render. Expressions are rendered against
a synthetic context, so a NameError-ish "undefined" result is fine -- we are
looking for hard renderer errors (unknown filter, unknown test, type errors).
"""

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS = os.path.join(ROOT, 'ninjaone', 'playbooks', 'playbooks.json')

JINJA = re.compile(r'\{\{.*?\}\}|\{%.*?%\}', re.S)


def iter_expressions(doc):
    """Yield (playbook, step, expression) for every Jinja-bearing string."""
    for collection in doc.get('data', []):
        for workflow in collection.get('workflows', []):
            for step in workflow.get('steps', []):
                blob = json.dumps(step.get('arguments') or {})
                seen = set()
                for match in JINJA.findall(blob):
                    # Un-escape the JSON string encoding so the renderer sees the
                    # expression exactly as the engine will.
                    expr = match.encode().decode('unicode_escape')
                    if expr in seen:
                        continue
                    seen.add(expr)
                    yield workflow.get('name'), step.get('name'), expr


def build_context():
    """A context shaped like a real run, with the awkward cases included.

    The null-field row is deliberate: it is what made json_query raise, and a
    context of tidy uniform dicts would have hidden that.
    """
    rows = [
        {'name': '7-Zip 19.00 (x64)', 'productName': '7-Zip', 'deviceId': 1, 'version': '19.00'},
        {'name': None, 'deviceId': 2},
        {'noname': True, 'deviceId': 3},
    ]
    step = {'count': 1, 'cursor': {}, 'results': rows, 'devices': rows,
            'url': 'https://example.invalid/x', 'systemName': 'HOST',
            'nodeClass': 'WINDOWS_WORKSTATION', 'offline': False,
            'organizationId': 1, 'id': 1, 'state': 'RUNNING', 'status': 'ok'}
    steps = {}
    doc = json.load(open(PLAYBOOKS, encoding='utf-8'))
    for collection in doc.get('data', []):
        for workflow in collection.get('workflows', []):
            for s in workflow.get('steps', []):
                steps[(s.get('name') or '').replace(' ', '_')] = dict(step, **{'0': step})
    return {'vars': {'steps': steps, 'input': {'params': {
        'product': '7-Zip', 'hostname': 'HOST', 'device_id': 1, 'service_name': 'Spooler'}},
        'rows': rows}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--env', required=True, help='pyfsr .env file for the target instance')
    args = parser.parse_args()

    from pyfsr import FortiSOAR
    client = FortiSOAR.from_env_file(args.env)

    doc = json.load(open(PLAYBOOKS, encoding='utf-8'))
    context = build_context()

    checked = failed = 0
    for playbook, step, expr in iter_expressions(doc):
        checked += 1
        try:
            client.wf_tools.render(expr, context)
        except Exception as err:            # noqa: BLE001 - report, never crash
            message = str(err).replace('\n', ' ')[:160]
            # An undefined name is expected against a synthetic context; a bad
            # filter, a bad test, or a type error is a real defect.
            if 'is undefined' in message or 'has no attribute' in message:
                continue
            failed += 1
            print(f'FAIL {playbook} / {step}')
            print(f'     {expr[:120]}')
            print(f'     {message}')

    print(f'\n{checked} expression(s) rendered, {failed} failed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())

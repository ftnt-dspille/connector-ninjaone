#!/usr/bin/env python3
"""Run every operation against a live tenant and record what actually passed.

The point is a durable answer to "which operations have really been exercised?"
-- one that survives a context switch, instead of living in someone's memory of
a terminal session. Each run writes three things:

  .cache/live/<op>.json    raw response, GITIGNORED (carries live host names,
                           addresses, serials, and a bearer installer URL)
  tests/fixtures/<op>.json sanitized copy, safe to commit
  COVERAGE.md              the matrix: operation, status, and why

Operations are grouped by blast radius and run in that order, so a failure in a
harmless read never leaves a machine mid-reboot:

  read      no side effects at all
  write     changes tenant/device state, but reverts or is trivially undone
  disrupt   visibly interrupts the endpoint (service bounce, script, reboot)

    python3 tools/live_matrix.py --device 1                 # read + write
    python3 tools/live_matrix.py --device 1 --disruptive    # everything
    python3 tools/live_matrix.py --device 1 --only run_script

Nothing in the `disrupt` tier runs unless --disruptive is passed explicitly.
"""

import argparse
import json
import os
import re
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def _stub_platform():
    class ConnectorError(Exception):
        pass

    class Connector:
        pass

    def get_logger(name):
        import logging
        logging.basicConfig(level=os.environ.get('NINJAONE_LOG_LEVEL', 'ERROR'))
        return logging.getLogger(name)

    core = types.ModuleType('connectors.core.connector')
    core.ConnectorError = ConnectorError
    core.Connector = Connector
    core.get_logger = get_logger
    sys.modules.setdefault('connectors', types.ModuleType('connectors'))
    sys.modules.setdefault('connectors.core', types.ModuleType('connectors.core'))
    sys.modules['connectors.core.connector'] = core
    return ConnectorError


ConnectorError = _stub_platform()

from ninjaone import operations as ops  # noqa: E402
from ninjaone.constants import REGION_HOSTS  # noqa: E402

RAW_DIR = os.path.join(ROOT, '.cache', 'live')
FIXTURE_DIR = os.path.join(ROOT, 'tests', 'fixtures')
COVERAGE_PATH = os.path.join(ROOT, 'COVERAGE.md')
# The rendered matrix is built from this ledger, not from the current run alone.
# Without it a `--only` run would silently blank the other 56 operations, which
# is exactly the "what has actually been tested?" question the file exists to
# answer.
LEDGER_PATH = os.path.join(FIXTURE_DIR, '_coverage.json')
INCIDENT = re.compile(r'\s*\(incident [^)]+\)')


# ------------------------------------------------------------ sanitizing --

# Live responses are full of things that must not reach a public repo: the lab's
# host names and addresses, hardware serials, tenant UIDs, and -- worst -- the
# installer URL, which is a bearer credential for joining the tenant. Redaction
# is by KEY first (so a serial is caught whatever it looks like) and then by
# PATTERN over the remaining strings.
REDACT_KEYS = {
    'serialnumber', 'biosserialnumber', 'macaddresses', 'macaddress', 'ipaddresses',
    'ipaddress', 'publicip', 'privateip', 'url', 'uid', 'dnsname', 'systemname',
    'netbiosname', 'domain', 'lastloggedinuser', 'username', 'email', 'firstname',
    'lastname', 'devicename', 'displayname', 'name', 'friendlyname', 'hostname',
    # Free text is the leakiest of the lot: an activity message embeds the device's
    # FQDN in prose ("Device 'HOST.example.lab' registered"), where no key-based
    # rule would ever see it. The structure and status codes are what make these
    # fixtures useful, not the sentence.
    'message', 'output', 'subject', 'sourcename', 'dnssuffix', 'dnshostname',
}
# Keys whose values are safe structural labels rather than live identity.
KEEP_NAME_IN = {'policies', 'groups', 'software_products', 'automation_scripts',
                'get_policies', 'get_groups', 'get_software_products',
                'get_automation_scripts', 'get_scripting_options',
                'get_device_windows_services'}

PATTERNS = [
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '<ip>'),
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'), '<mac>'),
    # IPv6, including link-local with a zone id. Found by the leak audit below,
    # not by inspection -- neither the key list nor the IPv4 pattern saw it.
    (re.compile(r'\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\w+)?'), '<ipv6>'),
    (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), '<uuid>'),
    (re.compile(r'https?://[^\s"\']+'), '<url>'),
    # An FQDN-ish token: dotted labels with at least one letter somewhere, so a
    # version string like "11.2312.18.0" is left alone.
    (re.compile(r'\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9-]*'
                r'(?:\.[A-Za-z0-9-]+)+\b'), '<host>'),
]


def identity_terms():
    """Live identity strings harvested from the raw capture itself.

    A key denylist is only ever as good as the last field someone remembered --
    `dnsHostName` slipped through precisely because it is a bare NetBIOS name
    with no dot for the FQDN pattern and nobody had listed the key. So instead of
    trusting the denylist, take the device's real identifiers straight from the
    raw response and assert none of them survive into a committed fixture.
    """
    terms = set()
    device_path = os.path.join(RAW_DIR, 'get_device.json')
    if os.path.exists(device_path):
        dev = json.load(open(device_path, encoding='utf-8'))
        for key in ('systemName', 'dnsName', 'netbiosName', 'publicIP'):
            if dev.get(key):
                terms.add(str(dev[key]))
        for key in ('ipAddresses', 'macAddresses'):
            terms.update(str(v) for v in (dev.get(key) or []))
        sys_block = dev.get('system') or {}
        for key in ('name', 'domain', 'serialNumber', 'biosSerialNumber'):
            if sys_block.get(key):
                terms.add(str(sys_block[key]))
    installer = os.path.join(RAW_DIR, 'generate_installer.json')
    if os.path.exists(installer):
        url = json.load(open(installer, encoding='utf-8')).get('url')
        if url:
            terms.add(url)
    # Split an FQDN so the bare host name is caught on its own too.
    for term in list(terms):
        if '.' in term and not term.startswith('http'):
            head = term.split('.')[0]
            if len(head) > 3 and not head.isdigit():
                terms.add(head)
    return {t for t in terms if len(t) > 3}


def audit_fixtures(terms):
    """Return [(fixture, term)] for any live identifier that survived."""
    findings = []
    for fname in sorted(os.listdir(FIXTURE_DIR)):
        if not fname.endswith('.json'):
            continue
        body = open(os.path.join(FIXTURE_DIR, fname), encoding='utf-8').read()
        for term in terms:
            if term in body:
                findings.append((fname, term))
    return findings


def sanitize(value, op_name, key=None):
    if isinstance(value, dict):
        return {k: sanitize(v, op_name, k) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v, op_name, key) for v in value]
    if isinstance(value, str):
        if key and key.lower() in REDACT_KEYS and op_name not in KEEP_NAME_IN:
            return '<redacted>'
        out = value
        for pattern, repl in PATTERNS:
            out = pattern.sub(repl, out)
        return out
    return value


# --------------------------------------------------------------- fixtures --

def load_env():
    path = os.path.join(ROOT, '.env.ninjaone')
    if not os.path.exists(path):
        sys.exit('Missing .env.ninjaone; copy .env.ninjaone.example and fill it in.')
    env = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def build_config(env):
    prefix = (env.get('NINJAONE_REGION') or 'app').strip()
    region = next((label for label, url in REGION_HOSTS.items()
                   if url == f'https://{prefix}.ninjarmm.com'), None)
    if not region:
        sys.exit('NINJAONE_REGION must be one of: app, us2, eu, ca, oc')
    return {
        'region': region,
        'client_id': env.get('NINJAONE_CLIENT_ID', ''),
        'client_secret': env.get('NINJAONE_CLIENT_SECRET', ''),
        'scope': env.get('NINJAONE_SCOPE', ''),
        'verify_ssl': True,
    }


def shape(value):
    """A one-line description of what came back, for the matrix."""
    if isinstance(value, list):
        return f'list[{len(value)}]'
    if isinstance(value, dict):
        for key in ('count', 'results', 'devices', 'organizations', 'findings', 'activities'):
            if key in value:
                inner = value[key]
                return f'{key}={len(inner) if isinstance(inner, list) else inner}'
        return 'dict{' + ','.join(list(value)[:4]) + '}'
    return str(value)[:40]


def build_checks(device, org, location):
    """(name, tier, callable, params, note). Ordered by blast radius."""
    D = {'device_id': device}
    checks = [
        # ---------------------------------------------------------- read --
        ('check_health', 'read', lambda c, p: ops._check_health(c), {}, ''),
        ('get_organizations', 'read', ops.get_organizations, {}, ''),
        ('get_organization', 'read', ops.get_organization, {'organization_id': org}, ''),
        ('get_organization_devices', 'read', ops.get_organization_devices, {'organization_id': org}, ''),
        ('get_organization_locations', 'read', ops.get_organization_locations, {'organization_id': org}, ''),
        ('get_groups', 'read', ops.get_groups, {}, ''),
        ('get_policies', 'read', ops.get_policies, {}, ''),
        ('get_software_products', 'read', ops.get_software_products, {}, ''),
        ('get_devices', 'read', ops.get_devices, {'max_records': 5}, ''),
        ('get_devices_detailed', 'read', ops.get_devices_detailed, {'max_records': 5}, ''),
        ('search_devices', 'read', ops.search_devices, {'query': 'a', 'limit': 5}, ''),
        ('get_device', 'read', ops.get_device, D, ''),
        ('get_device_custom_fields', 'read', ops.get_device_custom_fields, D, ''),
        ('get_device_dashboard_url', 'read', ops.get_device_dashboard_url, D, ''),
        ('get_device_software', 'read', ops.get_device_software, D, ''),
        ('get_device_disks', 'read', ops.get_device_disks, D, ''),
        ('get_device_volumes', 'read', ops.get_device_volumes, D, ''),
        ('get_device_processors', 'read', ops.get_device_processors, D, ''),
        ('get_device_network_interfaces', 'read', ops.get_device_network_interfaces, D, ''),
        ('get_device_last_logged_on_user', 'read', ops.get_device_last_logged_on_user, D, ''),
        ('get_device_windows_services', 'read', ops.get_device_windows_services, D, ''),
        ('get_software_inventory_report', 'read', ops.get_software_inventory_report, {'max_records': 5}, ''),
        ('get_device_health_report', 'read', ops.get_device_health_report, {'max_records': 5}, ''),
        ('get_device_pending_os_patches', 'read', ops.get_device_pending_os_patches, D, ''),
        ('get_device_pending_software_patches', 'read', ops.get_device_pending_software_patches, D, ''),
        ('get_device_installed_os_patches', 'read', ops.get_device_installed_os_patches, D, ''),
        ('get_device_installed_software_patches', 'read', ops.get_device_installed_software_patches, D, ''),
        ('get_pending_os_patches_report', 'read', ops.get_pending_os_patches_report, {'max_records': 5}, ''),
        ('get_pending_software_patches_report', 'read', ops.get_pending_software_patches_report,
         {'max_records': 5}, ''),
        ('fetch_patch_findings', 'read', ops.fetch_patch_findings, {'max_records': 5}, ''),
        ('get_alerts', 'read', ops.get_alerts, {}, ''),
        ('get_device_alerts', 'read', ops.get_device_alerts, D, ''),
        ('get_activities', 'read', ops.get_activities, {'max_records': 5}, ''),
        ('get_device_activities', 'read', ops.get_device_activities, dict(D, max_records=5), ''),
        ('get_jobs', 'read', ops.get_jobs, {}, ''),
        ('get_device_jobs', 'read', ops.get_device_jobs, D, ''),
        ('get_automation_scripts', 'read', ops.get_automation_scripts, {}, ''),
        ('get_scripting_options', 'read', ops.get_scripting_options, D, ''),
        ('get_group_devices', 'read', ops.get_group_devices, {'group_id': 1}, ''),

        # --------------------------------------------------------- write --
        ('generate_installer', 'write', ops.generate_installer,
         {'organization_id': org, 'location_id': location,
          'installer_type': 'WINDOWS_MSI', 'usage_limit': 1},
         'mints a real installer link; usage_limit 1'),
        ('update_device', 'write', ops.update_device,
         dict(D, display_name='ninjaone-connector-live-check'),
         'sets the display name, then restores it'),
        ('update_device_custom_fields', 'write', ops.update_device_custom_fields,
         dict(D, fields={'soarTest': 'ok'}),
         'needs a custom field defined in the tenant'),
        ('schedule_maintenance', 'write', ops.schedule_maintenance,
         dict(D, end_time=int(time.time()) + 600, reason='connector live check',
              disabled_features='ALERTS'),
         '10-minute window, cancelled immediately after'),
        ('cancel_maintenance', 'write', ops.cancel_maintenance, D, ''),
        ('scan_os_patches', 'write', ops.scan_os_patches, D,
         'needs OS patching enabled in the device policy'),
        ('scan_software_patches', 'write', ops.scan_software_patches, D,
         'needs software patching enabled in the device policy'),
        ('apply_os_patches', 'write', ops.apply_os_patches, D,
         'needs OS patching enabled in the device policy'),
        ('apply_software_patches', 'write', ops.apply_software_patches, D,
         'needs software patching enabled in the device policy'),
        ('reset_alert', 'write', ops.reset_alert, {'alert_uid': None},
         'needs a triggered condition to exist'),

        # ------------------------------------------------------- disrupt --
        ('control_windows_service', 'disrupt', ops.control_windows_service,
         dict(D, service_id='Themes', action='RESTART'),
         'bounces a cosmetic service'),
        ('run_script', 'disrupt', ops.run_script,
         dict(D, script_id=49),
         'runs the built-in "Clear DNS cache"'),
        ('reboot_device', 'disrupt', ops.reboot_device,
         dict(D, mode='NORMAL', reason='ninjaone connector live check'),
         'reboots the endpoint; run last'),
    ]
    # Ticketing needs the add-on, so it is declared but always attempted last and
    # expected to fail loudly rather than be silently omitted from the matrix.
    checks += [
        ('get_ticket', 'read', ops.get_ticket, {'ticket_id': 1}, 'needs the ticketing add-on'),
        ('get_tickets_by_board', 'read', ops.get_tickets_by_board,
         {'board_id': 1}, 'needs the ticketing add-on'),
        ('create_ticket', 'write', ops.create_ticket,
         {'organization_id': org, 'ticket_form_id': 1, 'subject': 'connector live check',
          'status': 'NEW'}, 'needs the ticketing add-on'),
        ('update_ticket', 'write', ops.update_ticket,
         {'ticket_id': 1, 'status': 'NEW'}, 'needs the ticketing add-on'),
        ('add_ticket_comment', 'write', ops.add_ticket_comment,
         {'ticket_id': 1, 'body': 'connector live check'}, 'needs the ticketing add-on'),
    ]
    return checks


TIER_ORDER = {'read': 0, 'write': 1, 'disrupt': 2}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', type=int)
    parser.add_argument('--org', type=int, default=1)
    parser.add_argument('--location', type=int, default=1)
    parser.add_argument('--disruptive', action='store_true',
                        help='also run the tier that interrupts the endpoint')
    parser.add_argument('--only', help='run just this operation')
    parser.add_argument('--resanitize', action='store_true',
                        help='rebuild tests/fixtures from .cache/live without calling the API')
    args = parser.parse_args()

    if args.resanitize:
        os.makedirs(FIXTURE_DIR, exist_ok=True)
        n = 0
        for fname in sorted(os.listdir(RAW_DIR)):
            if not fname.endswith('.json'):
                continue
            op_name = fname[:-5]
            raw = json.load(open(os.path.join(RAW_DIR, fname), encoding='utf-8'))
            with open(os.path.join(FIXTURE_DIR, fname), 'w', encoding='utf-8') as fh:
                json.dump(sanitize(raw, op_name), fh, indent=2)
            n += 1
        print(f'resanitized {n} fixture(s) from {RAW_DIR}')
        leaks = audit_fixtures(identity_terms())
        for fixture, term in leaks:
            print(f'  LEAK {fixture}: {term[:40]!r}')
        print('leak audit:', 'CLEAN' if not leaks else f'{len(leaks)} LEAK(S)')
        return 1 if leaks else 0

    if not args.device:
        parser.error('--device is required unless --resanitize is passed')
    config = build_config(load_env())
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(FIXTURE_DIR, exist_ok=True)

    checks = build_checks(args.device, args.org, args.location)
    checks.sort(key=lambda c: TIER_ORDER[c[1]])
    if args.only:
        checks = [c for c in checks if c[0] == args.only]
        if not checks:
            sys.exit(f'no such operation: {args.only}')

    # Sentinel, not None: this device's displayName was genuinely unset, so
    # `if original_name:` skipped the restore and left the test value on a real
    # device. "Not captured" and "captured as empty" are different states and
    # have to be represented differently.
    UNSET = object()
    original_name = UNSET
    rows = []
    for name, tier, func, params, note in checks:
        if tier == 'disrupt' and not args.disruptive:
            rows.append((name, tier, 'skip', '', 'not run without --disruptive', note))
            print(f'skip  {name:<38} (needs --disruptive)')
            continue
        if name == 'reset_alert' and not params.get('alert_uid'):
            alerts = ops.get_alerts(config, {})
            if alerts:
                params = {'alert_uid': alerts[0].get('uid')}
            else:
                rows.append((name, tier, 'skip', '', 'no triggered condition exists', note))
                print(f'skip  {name:<38} (no alerts to reset)')
                continue
        # Remember the display name so update_device can put it back.
        if name == 'update_device' and original_name is UNSET:
            original_name = (ops.get_device(config, {'device_id': args.device})
                             .get('displayName'))
        try:
            result = func(config, params)
        except ConnectorError as err:
            rows.append((name, tier, 'fail', '', str(err)[:200], note))
            print(f'FAIL  {name:<38} {str(err)[:110]}')
            continue
        except Exception as err:  # noqa: BLE001 - a survey reports, never crashes
            rows.append((name, tier, 'error', '', f'{type(err).__name__}: {err}'[:200], note))
            print(f'ERR   {name:<38} {type(err).__name__}: {err}')
            continue

        rows.append((name, tier, 'ok', shape(result), '', note))
        print(f'ok    {name:<38} {shape(result)}')
        with open(os.path.join(RAW_DIR, name + '.json'), 'w', encoding='utf-8') as fh:
            json.dump(result, fh, indent=2)
        with open(os.path.join(FIXTURE_DIR, name + '.json'), 'w', encoding='utf-8') as fh:
            json.dump(sanitize(result, name), fh, indent=2)

        if name == 'update_device' and original_name is not UNSET:
            # An empty string is how NinjaOne clears a displayName, and
            # update_device refuses an empty body, so this goes straight to the API.
            ops._client(config, {}).make_request(
                f'/device/{args.device}', method='PATCH',
                body={'displayName': original_name or ''})
            print('      (display name restored to its previous value)')

    write_coverage(rows, args)
    leaks = audit_fixtures(identity_terms())
    for fixture, term in leaks:
        print(f'  LEAK {fixture}: {term[:40]!r}')
    if leaks:
        print(f'\nREFUSING TO CALL THIS CLEAN: {len(leaks)} live identifier(s) '
              f'reached tests/fixtures/. Fix sanitize() and re-run --resanitize.')
    ok = sum(1 for r in rows if r[2] == 'ok')
    print(f'\n{ok}/{len(rows)} ok -- matrix written to COVERAGE.md')
    return 0


def write_coverage(rows, args):
    # Merge this run over whatever previous runs recorded.
    ledger = {}
    if os.path.exists(LEDGER_PATH):
        try:
            ledger = json.load(open(LEDGER_PATH, encoding='utf-8'))
        except ValueError:
            ledger = {}
    for name, tier, status, sh, err, note in rows:
        if status == 'skip' and name in ledger and ledger[name].get('result') != 'skip':
            # A skipped run must never downgrade a real result already on record.
            continue
        ledger[name] = {
            'tier': tier, 'result': status, 'returned': sh,
            # Incident ids are per-request live provenance and meaningless later.
            'detail': INCIDENT.sub('', err or ''), 'note': note,
        }
    with open(LEDGER_PATH, 'w', encoding='utf-8') as fh:
        json.dump(ledger, fh, indent=2, sort_keys=True)

    rows = [(n, v['tier'], v['result'], v['returned'], v['detail'], v['note'])
            for n, v in ledger.items()]
    total = len(rows)
    counts = {}
    for r in rows:
        counts[r[2]] = counts.get(r[2], 0) + 1

    lines = [
        '# Live coverage',
        '',
        'Generated by `tools/live_matrix.py` against a live NinjaOne tenant with an',
        'enrolled Windows endpoint. Do not hand-edit -- re-run the tool.',
        '',
        '`ok` means the operation was actually called and NinjaOne accepted it.',
        '`fail` means it was called and rejected, and the reason is recorded -- which',
        'is itself useful: most failures here are tenant configuration, not code.',
        '',
        '| result | count |',
        '|---|---|',
    ]
    for key in ('ok', 'fail', 'error', 'skip'):
        if counts.get(key):
            lines.append(f'| {key} | {counts[key]} |')
    lines += [f'| **total** | **{total}** |', '']

    for tier, title, blurb in (
        ('read', 'Read', 'No side effects.'),
        ('write', 'Write', 'Changes tenant or device state; reverted where possible.'),
        ('disrupt', 'Disruptive', 'Visibly interrupts the endpoint. Needs `--disruptive`.'),
    ):
        subset = [r for r in rows if r[1] == tier]
        if not subset:
            continue
        lines += [f'## {tier.capitalize()} -- {title}', '', blurb, '',
                  '| operation | result | returned | notes |', '|---|---|---|---|']
        for name, _tier, status, sh, err, note in sorted(subset):
            detail = err or note or ''
            detail = detail.replace('|', '\\|')
            lines.append(f'| `{name}` | {status} | {sh} | {detail} |')
        lines.append('')

    with open(COVERAGE_PATH, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))


if __name__ == '__main__':
    sys.exit(main())

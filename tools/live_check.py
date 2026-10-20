#!/usr/bin/env python3
"""Exercise the connector against a real NinjaOne tenant.

This drives the actual operations module -- not a hand-rolled HTTP client -- so
what passes here is what the connector does on-box. Credentials come from
.env.ninjaone (gitignored); see .env.ninjaone.example.

    python3 tools/live_check.py                 # read-only checks
    python3 tools/live_check.py --device 42     # add device-scoped reads
    python3 tools/live_check.py --save-fixtures # record responses to tests/fixtures/

Read-only by default. Nothing here reboots a machine, applies a patch, or writes
a ticket: those need a device you are willing to disturb, and are listed at the
end as the manual steps they are.
"""

import argparse
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def _stub_platform():
    """Stand in for the FortiSOAR-only modules the connector imports."""

    class ConnectorError(Exception):
        pass

    class Connector:
        pass

    def get_logger(name):
        import logging
        logging.basicConfig(level=os.environ.get('NINJAONE_LOG_LEVEL', 'WARNING'))
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

FIXTURE_DIR = os.path.join(ROOT, 'tests', 'fixtures')


def load_env():
    path = os.path.join(ROOT, '.env.ninjaone')
    if not os.path.exists(path):
        sys.exit(f'Missing {path}. Copy .env.ninjaone.example and fill it in.')
    env = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def build_config(env):
    # The env file names the region by its short host prefix ('ca'); the
    # connector configuration uses the human label the dropdown shows.
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


def summarize(value):
    if isinstance(value, list):
        return 'list[{}] {}'.format(len(value), json.dumps(value[:1])[:120] if value else '')
    if isinstance(value, dict):
        for key in ('count', 'results', 'devices', 'organizations', 'findings', 'activities'):
            if key in value:
                inner = value[key]
                if isinstance(inner, list):
                    return '{}={} {}'.format(key, len(inner),
                                             json.dumps(inner[:1])[:110] if inner else '')
                return f'{key}={inner}'
        return json.dumps(value)[:130]
    return str(value)[:130]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', type=int, help='device ID for device-scoped reads')
    parser.add_argument('--save-fixtures', action='store_true',
                        help='write each response to tests/fixtures/')
    args = parser.parse_args()

    config = build_config(load_env())
    checks = [
        ('check_health', lambda cfg, _params: ops._check_health(cfg), {}),
        ('get_organizations', ops.get_organizations, {}),
        ('get_groups', ops.get_groups, {}),
        ('get_policies', ops.get_policies, {}),
        ('get_devices', ops.get_devices, {'max_records': 5}),
        ('get_alerts', ops.get_alerts, {}),
        ('get_activities', ops.get_activities, {'max_records': 5}),
        ('get_jobs', ops.get_jobs, {}),
        ('get_automation_scripts', ops.get_automation_scripts, {}),
        ('get_software_products', ops.get_software_products, {}),
        ('get_pending_os_patches_report', ops.get_pending_os_patches_report, {'max_records': 5}),
        ('get_pending_software_patches_report', ops.get_pending_software_patches_report,
         {'max_records': 5}),
        ('get_software_inventory_report', ops.get_software_inventory_report, {'max_records': 5}),
        ('get_device_health_report', ops.get_device_health_report, {'max_records': 5}),
        ('fetch_patch_findings', ops.fetch_patch_findings, {'max_records': 5}),
    ]

    if args.device:
        device = {'device_id': args.device}
        checks += [
            ('get_device', ops.get_device, device),
            ('get_device_software', ops.get_device_software, device),
            ('get_device_disks', ops.get_device_disks, device),
            ('get_device_volumes', ops.get_device_volumes, device),
            ('get_device_processors', ops.get_device_processors, device),
            ('get_device_network_interfaces', ops.get_device_network_interfaces, device),
            ('get_device_windows_services', ops.get_device_windows_services, device),
            ('get_device_last_logged_on_user', ops.get_device_last_logged_on_user, device),
            ('get_device_pending_os_patches', ops.get_device_pending_os_patches, device),
            ('get_device_pending_software_patches', ops.get_device_pending_software_patches, device),
            ('get_device_installed_os_patches', ops.get_device_installed_os_patches, device),
            ('get_device_alerts', ops.get_device_alerts, device),
            ('get_device_jobs', ops.get_device_jobs, device),
            ('get_device_activities', ops.get_device_activities, dict(device, max_records=5)),
            ('get_scripting_options', ops.get_scripting_options, device),
            ('get_device_dashboard_url', ops.get_device_dashboard_url, device),
            ('get_device_custom_fields', ops.get_device_custom_fields, device),
        ]

    if args.save_fixtures:
        os.makedirs(FIXTURE_DIR, exist_ok=True)

    passed = failed = 0
    for name, func, params in checks:
        try:
            result = func(config, params)
        except ConnectorError as err:
            print(f'FAIL  {name:38} {err}')
            failed += 1
            continue
        except Exception as err:  # noqa: BLE001 - a live check reports, never crashes
            print(f'ERROR {name:38} {type(err).__name__}: {err}')
            failed += 1
            continue
        print(f'ok    {name:38} {summarize(result)}')
        passed += 1
        if args.save_fixtures:
            with open(os.path.join(FIXTURE_DIR, name + '.json'), 'w', encoding='utf-8') as fh:
                json.dump(result, fh, indent=2)

    print(f'\n{passed} passed, {failed} failed')
    if not args.device:
        print('\nDevice-scoped reads were skipped. Re-run with --device <id> once the '
              'tenant has an agent installed.')
    print('Not covered here, because they change state on a real machine: '
          'apply/scan patches, run_script, reboot_device, control_windows_service, '
          'schedule_maintenance, reset_alert, and the ticketing writes.')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())

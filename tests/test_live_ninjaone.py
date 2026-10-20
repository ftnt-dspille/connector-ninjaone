"""Live tests against a real NinjaOne tenant.

Opt-in: ``pytest -m live``. The default run excludes them (see pyproject.toml),
because they need credentials and spend real API calls.

Every test here is READ-ONLY. Nothing reboots a machine, applies a patch, runs a
script, or writes a ticket -- those are destructive against whatever endpoints
the tenant manages, and belong in a deliberate manual run, not in a suite anyone
might execute by reflex.

Credentials come from .env.ninjaone (gitignored); see .env.ninjaone.example.
"""

import os

import pytest

from ninjaone import operations as ops
from ninjaone.constants import REGION_HOSTS

ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        '.env.ninjaone')

pytestmark = pytest.mark.live


def _load_env():
    if not os.path.exists(ENV_PATH):
        pytest.skip('no .env.ninjaone; live tests need credentials')
    env = {}
    for line in open(ENV_PATH, encoding='utf-8'):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


@pytest.fixture(scope='module')
def config():
    env = _load_env()
    prefix = env.get('NINJAONE_REGION', 'app')
    region = next((label for label, url in REGION_HOSTS.items()
                   if url == f'https://{prefix}.ninjarmm.com'), None)
    if not region:
        pytest.skip('NINJAONE_REGION must be one of: app, us2, eu, ca, oc')
    if not env.get('NINJAONE_CLIENT_ID'):
        pytest.skip('NINJAONE_CLIENT_ID is not set')
    # Module-scoped so the access token is minted once and reused, which is also
    # what exercises the caching path.
    return {
        'region': region,
        'client_id': env['NINJAONE_CLIENT_ID'],
        'client_secret': env.get('NINJAONE_CLIENT_SECRET', ''),
        'scope': env.get('NINJAONE_SCOPE', ''),
        'verify_ssl': True,
    }


def test_health_check(config):
    assert ops._check_health(config) is True


def test_token_is_cached_after_the_first_call(config):
    ops.get_groups(config, {})
    assert config.get('access_token')
    assert config.get('access_token_expiry', 0) > 0


def test_organizations_returns_a_list(config):
    result = ops.get_organizations(config, {})
    assert isinstance(result['organizations'], list)
    assert result['count'] == len(result['organizations'])


def test_policies_carry_ids_update_device_can_use(config):
    policies = ops.get_policies(config, {})
    assert isinstance(policies, list)
    if policies:
        assert 'id' in policies[0] and 'name' in policies[0]


def test_automation_scripts_carry_ids_run_script_can_use(config):
    scripts = ops.get_automation_scripts(config, {})
    assert isinstance(scripts, list)
    if scripts:
        assert 'id' in scripts[0]


def test_software_products_carry_the_patch_filter_identifier(config):
    products = ops.get_software_products(config, {})
    assert isinstance(products, list)
    if products:
        assert 'productName' in products[0]


def test_patch_reports_use_the_results_envelope(config):
    # Live-verified: these answer {"results": [...]} and omit the cursor key
    # entirely when empty, which the pagination loop has to survive.
    result = ops.get_pending_os_patches_report(config, {'max_records': 5})
    assert isinstance(result['results'], list)
    assert result['count'] == len(result['results'])


def test_fetch_patch_findings_normalizes_both_sources(config):
    result = ops.fetch_patch_findings(config, {'max_records': 5})
    assert isinstance(result['findings'], list)
    for finding in result['findings']:
        assert finding['source_id']
        assert finding['patch_kind'] in ('os', 'software')


def test_activities_use_their_own_envelope(config):
    # Not a bare list and not `results` -- activities sit under `activities`
    # alongside a lastActivityId cursor.
    result = ops.get_activities(config, {'max_records': 5})
    assert 'activities' in result


def test_unknown_device_reports_a_useful_error(config):
    from connectors.core.connector import ConnectorError
    with pytest.raises(ConnectorError) as err:
        ops.get_device(config, {'device_id': 999999999})
    assert 'not found' in str(err.value).lower()

"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import json
import time
from datetime import datetime, timezone

import requests
from connectors.core.connector import get_logger, ConnectorError

from .constants import (
    API_PATH,
    CONNECTOR_NAME,
    CONNECTOR_VERSION,
    DEFAULT_PAGE_SIZE,
    DEFAULT_REGION,
    DEFAULT_SCOPE,
    ERROR_MESSAGES,
    INSTALLER_TYPES,
    MAX_PAGES,
    MAX_PAGE_SIZE,
    REGION_HOSTS,
    SCOPE_HINT,
    TOKEN_ERROR_HINTS,
    TOKEN_EXPIRY_SKEW_SECONDS,
    TOKEN_PATH,
)

logger = get_logger(CONNECTOR_NAME)

try:
    from connectors.core.utils import update_connnector_config
except ImportError:  # pragma: no cover
    try:
        from connectors.core.connector import update_connnector_config
    except ImportError:  # pragma: no cover - local dev / unit tests
        update_connnector_config = None

try:
    from integrations.crudhub import trigger_ingest_playbook
except ImportError:  # pragma: no cover - local dev / unit tests
    trigger_ingest_playbook = None


def _text(value):
    """Config values as strings, whatever the platform stored them as.

    FortiSOAR stores a numeric-looking 'text' field as an int, and the connector
    then dies on the appliance with "'int' object has no attribute 'strip'" --
    a message that names nothing useful and cannot reproduce off-box, where the
    same values arrive from a JSON file as strings.
    """
    if value is None:
        return ''
    return value if isinstance(value, str) else str(value)


class NinjaOne(object):
    """Thin REST client over the NinjaOne Public API v2.

    Auth is OAuth 2.0 client credentials: the app itself is the principal, so
    there is no user token and no refresh token to rotate. Access tokens are
    short-lived, so the minted token is cached back onto the connector
    configuration -- otherwise every single operation spends a round trip
    re-minting one before it does any work.
    """

    def __init__(self, config, connector_info=None):
        self.config = config
        self.connector_info = connector_info or {}

        region = _text(config.get('region')).strip() or DEFAULT_REGION
        server_url = _text(config.get('server_url')).strip().rstrip('/')
        if not server_url:
            # An unrecognised region label is a typo in a hand-edited config, not
            # a reason to silently query North America and report an empty estate.
            if region not in REGION_HOSTS:
                raise ConnectorError(
                    'Unknown region "{}". Expected one of: {}'.format(
                        region, ', '.join(sorted(REGION_HOSTS))))
            server_url = REGION_HOSTS[region]
        if not server_url.startswith('http'):
            server_url = 'https://' + server_url

        self.server_url = server_url
        self.base_url = self.server_url + API_PATH
        self.verify_ssl = config.get('verify_ssl', True)
        self.client_id = _text(config.get('client_id')).strip()
        self.client_secret = _text(config.get('client_secret'))
        self.scope = _text(config.get('scope')).strip() or DEFAULT_SCOPE

    # ---------------------------------------------------------------- auth --

    def _token_is_fresh(self):
        expiry = self.config.get('access_token_expiry')
        if not (self.config.get('access_token') and expiry):
            return False
        try:
            return float(expiry) - TOKEN_EXPIRY_SKEW_SECONDS > time.time()
        except (TypeError, ValueError):
            return False

    def _mint_access_token(self):
        if not (self.client_id and self.client_secret):
            raise ConnectorError(
                'NinjaOne is not fully configured: both Client ID and Client Secret '
                'are required to obtain an access token.')
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope,
        }
        logger.info('Requesting a NinjaOne access token from %s', self.server_url)
        try:
            response = requests.post(
                self.server_url + TOKEN_PATH, data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded',
                         'Accept': 'application/json'},
                verify=self.verify_ssl, timeout=60)
        except requests.exceptions.SSLError:
            raise ConnectorError(ERROR_MESSAGES['ssl_error'])
        except requests.exceptions.Timeout:
            raise ConnectorError(ERROR_MESSAGES['time_out'])
        except Exception as err:
            raise ConnectorError('Could not reach the NinjaOne token endpoint: {}'.format(err))

        body = _safe_text(response)
        if response.status_code != 200:
            raise ConnectorError('Could not obtain a NinjaOne access token [{}]: {}{}'.format(
                response.status_code, body, _token_hint(body)))

        try:
            data = response.json()
        except ValueError:
            raise ConnectorError(
                'The NinjaOne token endpoint returned a non-JSON response: {}'.format(body))

        access_token = data.get('access_token')
        if not access_token:
            # A 200 carrying an error body is exactly how a region mismatch and a
            # disallowed grant type both surface, so the hint matters most here.
            raise ConnectorError('NinjaOne returned no access_token: {}{}'.format(
                body, _token_hint(body)))

        updated = {
            'access_token': access_token,
            'access_token_expiry': time.time() + float(data.get('expires_in') or 3600),
        }
        self.config.update(updated)
        self._persist_config(updated)
        return access_token

    def _persist_config(self, updated):
        """Cache the minted token back onto the connector configuration."""
        if not update_connnector_config:
            return
        config_id = self.config.get('config_id')
        if not config_id:
            # Off-box, or an operation invoked without a stored configuration.
            logger.info('No config_id on the configuration; the token will not be cached')
            return
        self.config.update(updated)
        try:
            update_connnector_config(
                self.connector_info.get('connector_name') or CONNECTOR_NAME,
                self.connector_info.get('connector_version') or CONNECTOR_VERSION,
                self.config,
                config_id,
            )
        except Exception as err:
            # Not fatal for THIS call -- the token in hand still works -- but every
            # subsequent operation will re-mint, so it is worth a warning rather
            # than a debug line.
            logger.warning('Could not cache the NinjaOne access token, so every '
                           'operation will re-mint one: {}'.format(err))

    def _headers(self, extra=None):
        token = self.config.get('access_token') if self._token_is_fresh() else self._mint_access_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(token),
        }
        if extra:
            headers.update(extra)
        return headers

    # ------------------------------------------------------------- request --

    def make_request(self, endpoint, method='GET', params=None, body=None, files=None,
                     headers=None, retry_auth=True):
        url = endpoint if endpoint.startswith('http') else self.base_url + endpoint
        extra = dict(headers or {})
        kwargs = {}
        if files is not None:
            # The ticket comment endpoint is multipart/form-data, not JSON. Letting
            # requests set the boundary itself is mandatory -- a hand-set
            # Content-Type here produces a body the server cannot parse.
            kwargs['files'] = files
            if body:
                kwargs['data'] = body
        elif body is not None:
            extra.setdefault('Content-Type', 'application/json')
            kwargs['data'] = json.dumps(body)

        try:
            response = requests.request(method, url, params=params,
                                        headers=self._headers(extra),
                                        verify=self.verify_ssl, timeout=120, **kwargs)
        except requests.exceptions.SSLError:
            raise ConnectorError(ERROR_MESSAGES['ssl_error'])
        except requests.exceptions.Timeout:
            raise ConnectorError(ERROR_MESSAGES['time_out'])
        except ConnectorError:
            # _headers() raises this when minting fails, and its message already
            # names the real cause. Re-wrapping it as 'Request to NinjaOne failed'
            # buries the one sentence the operator needs.
            raise
        except Exception as err:
            raise ConnectorError('Request to NinjaOne failed: {}'.format(err))

        if response.status_code == 401 and retry_auth:
            # The cached token was revoked or expired early. Mint one and retry
            # exactly once, so a genuinely bad credential still fails fast.
            # Live-verified: an expired or tampered token answers 401
            # ("not_authenticated"), while a missing or malformed Authorization
            # header answers 400. Only the former is worth a retry -- the latter
            # is a bug here, and retrying it would just double the latency.
            logger.info('NinjaOne returned 401; minting a new token and retrying once')
            self.config.pop('access_token_expiry', None)
            self._mint_access_token()
            return self.make_request(endpoint, method=method, params=params, body=body,
                                     files=files, headers=headers, retry_auth=False)

        if response.ok:
            if not response.content:
                # Reboot, patch scan/apply and cancel-maintenance all answer 204.
                return {'status': 'Success'}
            try:
                return response.json()
            except ValueError:
                return {'status': 'Success', 'response': _safe_text(response)}

        message = ERROR_MESSAGES.get(response.status_code, 'Request failed')
        detail = _error_detail(response)
        if response.status_code == 403 and not detail:
            message += SCOPE_HINT
        raise ConnectorError('{} [{}]: {}'.format(
            message, response.status_code, detail))

    # ---------------------------------------------------------- pagination --

    def paginate_after(self, endpoint, params, max_records, id_key='id'):
        """Walk the `after` cursor used by /v2/devices and /v2/organizations.

        These endpoints return a bare JSON array and carry no next-page token:
        the caller is expected to pass the last id it saw back as `after`. A page
        shorter than the page size means the end.
        """
        collected = []
        query = dict(params or {})
        for _ in range(MAX_PAGES):
            page_size = min(MAX_PAGE_SIZE, max_records - len(collected))
            if page_size <= 0:
                break
            query['pageSize'] = page_size
            page = self.make_request(endpoint, params=_build_params(query))
            if isinstance(page, dict):
                # Defensive: a filter error answers an object, not a list, and
                # iterating it would silently yield key names.
                page = page.get('results') or page.get('data') or []
            if not page:
                break
            collected.extend(page)
            last_id = (page[-1] or {}).get(id_key)
            if last_id is None or len(page) < page_size:
                break
            query['after'] = last_id
        else:
            logger.warning('Stopped after %s pages; results may be truncated.', MAX_PAGES)
        return collected[:max_records]

    def paginate_cursor(self, endpoint, params, max_records):
        """Walk the opaque cursor used by every /v2/queries/* report.

        The report endpoints wrap their rows in an object and return the next
        cursor nested under `cursor.name` -- not at the top level, and not as the
        `after` integer the device endpoints use. The two schemes are not
        interchangeable, and mixing them silently re-reads page one forever.
        """
        collected = []
        query = dict(params or {})
        cursor_meta = None
        for _ in range(MAX_PAGES):
            page_size = min(MAX_PAGE_SIZE, max_records - len(collected))
            if page_size <= 0:
                break
            query['pageSize'] = page_size
            response = self.make_request(endpoint, params=_build_params(query))
            if not isinstance(response, dict):
                collected.extend(response or [])
                break
            rows = response.get('results')
            if rows is None:
                rows = response.get('data') or []
            collected.extend(rows)
            cursor_meta = response.get('cursor') or {}
            next_cursor = cursor_meta.get('name') if isinstance(cursor_meta, dict) else None
            if not next_cursor or not rows or len(rows) < page_size:
                break
            query['cursor'] = next_cursor
        else:
            logger.warning('Stopped after %s pages; results may be truncated.', MAX_PAGES)
        return collected[:max_records], cursor_meta


# --------------------------------------------------------------- helpers --

def _safe_text(response):
    try:
        return response.text[:1000]
    except Exception:
        return ''


def _error_detail(response):
    """Pull the human-readable cause out of a NinjaOne error body.

    Live-verified: NinjaOne uses three different error shapes, and the raw text
    of the first two buries the cause behind an incidentId that means nothing to
    the operator.
      * {"resultCode": "FAILURE", "errorMessage": "Device not found", ...}
      * {"errorMessage": {"code": "Ninja Ticketing Integration is not enabled"}}
      * a bare string body, e.g. "uid incorrect type"
    """
    text = _safe_text(response)
    try:
        data = response.json()
    except ValueError:
        return text
    if not isinstance(data, dict):
        return text
    message = data.get('errorMessage')
    if isinstance(message, dict):
        message = message.get('code') or json.dumps(message)
    if not message:
        message = data.get('error_description') or data.get('error') or data.get('resultCode')
    if not message:
        return text
    incident = data.get('incidentId')
    return '{}{}'.format(message, ' (incident {})'.format(incident) if incident else '')


def _token_hint(body):
    """Turn NinjaOne's terse token errors into the actual remedy.

    'Client app not exist' and 'unauthorized_client' both read like a bad secret
    but mean entirely different things -- wrong region versus a grant type the
    app is not allowed to use -- and neither is guessable from the string.
    """
    for needle, hint in TOKEN_ERROR_HINTS.items():
        if needle in (body or ''):
            return ' -- {}'.format(hint)
    return ''


def _client(config, kwargs):
    return NinjaOne(config, connector_info=(kwargs or {}).get('connector_info'))


def _build_params(params):
    return {k: v for k, v in (params or {}).items()
            if v is not None and v != '' and v != {} and v != []}


def _require(params, name, label):
    value = params.get(name)
    if value in (None, '', [], {}):
        raise ConnectorError('{} is required.'.format(label))
    return value


def _device_id(params, name='device_id'):
    value = _require(params, name, 'Device ID')
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConnectorError(
            'Device ID must be a number, got "{}". Use Search Devices to resolve a '
            'hostname to its numeric NinjaOne device ID.'.format(value))


def _int_or_none(value):
    if value in (None, '', []):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _max_records(params, default=DEFAULT_PAGE_SIZE):
    value = _int_or_none(params.get('max_records'))
    if not value or value < 1:
        return default
    return value


def _as_list(value):
    """Accept a list, a JSON array, or a comma-separated string."""
    if value in (None, ''):
        return []
    if isinstance(value, list):
        return value
    text = str(value).strip()
    if text.startswith('['):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
        except ValueError:
            pass
    return [item.strip() for item in text.split(',') if item.strip()]


def _as_csv(value):
    """NinjaOne's multi-valued filters take a comma-separated string."""
    items = _as_list(value)
    return ','.join(str(i) for i in items) if items else None


def _as_dict(value, label):
    """Accept a dict or a JSON object string, which is what a playbook often passes."""
    if value in (None, '', {}):
        return {}
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as err:
        raise ConnectorError('{} must be valid JSON: {}'.format(label, err))
    if not isinstance(parsed, dict):
        raise ConnectorError('{} must be a JSON object.'.format(label))
    return parsed


def _filter_by_name(rows, needle, *keys):
    """Case-insensitive substring match over the first present key in each row.

    This lives here rather than in a playbook's Jinja on purpose. FortiSOAR's
    Jinja has no substring *test*, so `selectattr(..., 'search', ...)` -- the
    Ansible idiom the shape invites -- fails at runtime with "No test named
    'search'". The alternatives (a namespace loop, or a JMESPath expression
    built by string concatenation) are unreadable and untestable. Doing it in
    Python keeps it one expression in the playbook and covered by unit tests.
    """
    if not needle:
        return rows
    needle = str(needle).strip().lower()
    if not needle:
        return rows
    matched = []
    for row in rows or []:
        for key in keys:
            value = (row or {}).get(key)
            if value and needle in str(value).lower():
                matched.append(row)
                break
    return matched


def _to_epoch_millis(value):
    """NinjaOne maintenance windows take epoch milliseconds."""
    seconds = _to_epoch_seconds(value)
    return None if seconds is None else int(seconds * 1000)


def _to_epoch_seconds(value):
    """Accept whatever a FortiSOAR datetime field, a macro, or a user hands over."""
    if value in (None, ''):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # Tolerate milliseconds, which is what a datetime picker yields once it
        # has been through some Jinja filters.
        return int(value / 1000) if value > 1e11 else int(value)
    text = str(value).strip()
    if text.isdigit():
        return _to_epoch_seconds(int(text))
    try:
        # fromisoformat rejects a trailing Z until 3.11; normalize it first.
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except ValueError:
        pass
    try:
        import arrow
        return arrow.get(text).int_timestamp
    except Exception as err:
        raise ConnectorError('Could not parse the datetime "{}": {}'.format(value, err))


def _to_iso(value):
    seconds = _to_epoch_seconds(value)
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def _epoch_to_iso(value):
    if not value:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds > 1e11:
        seconds = seconds / 1000
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# ------------------------------------------------------------- devices --

def get_devices(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({'df': params.get('device_filter')})
    devices = client.paginate_after('/devices', query, _max_records(params))
    return {'count': len(devices), 'devices': devices}


def get_devices_detailed(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({'df': params.get('device_filter')})
    devices = client.paginate_after('/devices-detailed', query, _max_records(params))
    return {'count': len(devices), 'devices': devices}


def search_devices(config, params, **kwargs):
    query = _build_params({
        'q': _require(params, 'query', 'Search Query'),
        'limit': _int_or_none(params.get('limit')),
    })
    return _client(config, kwargs).make_request('/devices/search', params=query)


def get_device(config, params, **kwargs):
    return _client(config, kwargs).make_request('/device/{}'.format(_device_id(params)))


def update_device(config, params, **kwargs):
    body = _as_dict(params.get('additional_fields'), 'Additional Fields')
    body.update(_build_params({
        'displayName': params.get('display_name'),
        'nodeRoleId': _int_or_none(params.get('node_role_id')),
        'policyId': _int_or_none(params.get('policy_id')),
        'organizationId': _int_or_none(params.get('organization_id')),
        'locationId': _int_or_none(params.get('location_id')),
        'userData': _as_dict(params.get('user_data'), 'Custom Attributes') or None,
    }))
    if not body:
        raise ConnectorError('Nothing to update: supply at least one field.')
    return _client(config, kwargs).make_request(
        '/device/{}'.format(_device_id(params)), method='PATCH', body=body)


def get_device_custom_fields(config, params, **kwargs):
    query = _build_params({'withInheritance': params.get('with_inheritance')})
    return _client(config, kwargs).make_request(
        '/device/{}/custom-fields'.format(_device_id(params)), params=query)


def update_device_custom_fields(config, params, **kwargs):
    fields = _as_dict(_require(params, 'fields', 'Field Values'), 'Field Values')
    return _client(config, kwargs).make_request(
        '/device/{}/custom-fields'.format(_device_id(params)), method='PATCH', body=fields)


def get_device_dashboard_url(config, params, **kwargs):
    # redirect=false keeps NinjaOne from answering a 302 to the console, which
    # requests would follow and hand back an HTML login page.
    return _client(config, kwargs).make_request(
        '/device/{}/dashboard-url'.format(_device_id(params)), params={'redirect': 'false'})


# ----------------------------------------------------------- inventory --

def get_device_software(config, params, **kwargs):
    return _client(config, kwargs).make_request('/device/{}/software'.format(_device_id(params)))


def get_device_disks(config, params, **kwargs):
    return _client(config, kwargs).make_request('/device/{}/disks'.format(_device_id(params)))


def get_device_volumes(config, params, **kwargs):
    # 'bl' asks for BitLocker status, which is the reason most callers want this.
    query = _build_params({'include': 'bl' if params.get('include_bitlocker') else None})
    return _client(config, kwargs).make_request(
        '/device/{}/volumes'.format(_device_id(params)), params=query)


def get_device_processors(config, params, **kwargs):
    return _client(config, kwargs).make_request('/device/{}/processors'.format(_device_id(params)))


def get_device_network_interfaces(config, params, **kwargs):
    return _client(config, kwargs).make_request(
        '/device/{}/network-interfaces'.format(_device_id(params)))


def get_device_last_logged_on_user(config, params, **kwargs):
    return _client(config, kwargs).make_request(
        '/device/{}/last-logged-on-user'.format(_device_id(params)))


def get_device_windows_services(config, params, **kwargs):
    query = _build_params({'name': params.get('name'), 'state': params.get('state')})
    return _client(config, kwargs).make_request(
        '/device/{}/windows-services'.format(_device_id(params)), params=query)


def get_software_inventory_report(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({
        'df': params.get('device_filter'),
        'installedAfter': _to_iso(params.get('installed_after')),
        'installedBefore': _to_iso(params.get('installed_before')),
    })
    rows, cursor = client.paginate_cursor('/queries/software', query, _max_records(params))
    rows = _filter_by_name(rows, params.get('name_contains'), 'name', 'productName')
    return {'count': len(rows), 'cursor': cursor, 'results': rows}


def get_device_health_report(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({'df': params.get('device_filter'), 'health': params.get('health')})
    rows, cursor = client.paginate_cursor('/queries/device-health', query, _max_records(params))
    return {'count': len(rows), 'cursor': cursor, 'results': rows}


# ------------------------------------------------------------ patching --

def get_device_pending_os_patches(config, params, **kwargs):
    query = _build_params({
        'status': _as_csv(params.get('status')),
        'type': _as_csv(params.get('type')),
        'severity': _as_csv(params.get('severity')),
    })
    return _client(config, kwargs).make_request(
        '/device/{}/os-patches'.format(_device_id(params)), params=query)


def get_device_installed_os_patches(config, params, **kwargs):
    query = _build_params({
        'status': _as_csv(params.get('status')),
        'installedAfter': _to_iso(params.get('installed_after')),
        'installedBefore': _to_iso(params.get('installed_before')),
    })
    return _client(config, kwargs).make_request(
        '/device/{}/os-patch-installs'.format(_device_id(params)), params=query)


def get_device_pending_software_patches(config, params, **kwargs):
    query = _build_params({
        'status': _as_csv(params.get('status')),
        'productIdentifier': params.get('product_identifier'),
        'type': _as_csv(params.get('type')),
        'impact': _as_csv(params.get('impact')),
    })
    return _client(config, kwargs).make_request(
        '/device/{}/software-patches'.format(_device_id(params)), params=query)


def get_device_installed_software_patches(config, params, **kwargs):
    query = _build_params({
        'status': _as_csv(params.get('status')),
        'productIdentifier': params.get('product_identifier'),
        'type': _as_csv(params.get('type')),
        'impact': _as_csv(params.get('impact')),
        'installedAfter': _to_iso(params.get('installed_after')),
        'installedBefore': _to_iso(params.get('installed_before')),
    })
    return _client(config, kwargs).make_request(
        '/device/{}/software-patch-installs'.format(_device_id(params)), params=query)


def get_pending_os_patches_report(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({
        'df': params.get('device_filter'),
        'ts': params.get('timestamp_filter'),
        'status': _as_csv(params.get('status')),
        'type': _as_csv(params.get('type')),
        'severity': _as_csv(params.get('severity')),
    })
    rows, cursor = client.paginate_cursor('/queries/os-patches', query, _max_records(params))
    return {'count': len(rows), 'cursor': cursor, 'results': rows}


def get_pending_software_patches_report(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({
        'df': params.get('device_filter'),
        'ts': params.get('timestamp_filter'),
        'status': _as_csv(params.get('status')),
        'productIdentifier': params.get('product_identifier'),
        'type': _as_csv(params.get('type')),
        'impact': _as_csv(params.get('impact')),
    })
    rows, cursor = client.paginate_cursor('/queries/software-patches', query, _max_records(params))
    rows = _filter_by_name(rows, params.get('name_contains'), 'productName', 'name')
    return {'count': len(rows), 'cursor': cursor, 'results': rows}


def _submit_patch_job(config, params, kwargs, path, label):
    """Patch scan/apply are fire-and-forget: they answer 204 with no job id.

    There is nothing to correlate a returned handle against, so the honest
    contract is 'submitted'. Poll Get Device Jobs, or re-read the pending patch
    list, to find out what actually happened.
    """
    device_id = _device_id(params)
    _client(config, kwargs).make_request(
        '/device/{}/{}'.format(device_id, path), method='POST')
    return {
        'status': 'Submitted',
        'device_id': device_id,
        'action': label,
        'message': '{} submitted to device {}. NinjaOne returns no job identifier for '
                   'this call -- poll Get Device Jobs, or re-read the pending patch '
                   'list, to confirm completion.'.format(label, device_id),
    }


def scan_os_patches(config, params, **kwargs):
    return _submit_patch_job(config, params, kwargs, 'patch/os/scan', 'OS patch scan')


def apply_os_patches(config, params, **kwargs):
    return _submit_patch_job(config, params, kwargs, 'patch/os/apply', 'OS patch apply')


def scan_software_patches(config, params, **kwargs):
    return _submit_patch_job(config, params, kwargs, 'patch/software/scan', 'Software patch scan')


def apply_software_patches(config, params, **kwargs):
    return _submit_patch_job(config, params, kwargs, 'patch/software/apply', 'Software patch apply')


# ------------------------------------------------------------- control --

def run_script(config, params, **kwargs):
    """Run a saved script, or a built-in action, on one device.

    NinjaOne distinguishes the two by which identifier is supplied: a numeric
    `id` for a script from the automation library, a string `uid` for a built-in
    action. Sending both, or neither, is rejected.
    """
    script_id = _int_or_none(params.get('script_id'))
    action_uid = (_text(params.get('action_uid')) or '').strip()
    if not script_id and not action_uid:
        raise ConnectorError(
            'Supply either a Script ID (from Get Automation Scripts) or an Action UID.')
    if script_id and action_uid:
        raise ConnectorError(
            'Supply only one of Script ID or Action UID -- NinjaOne rejects both together.')

    body = _build_params({
        'type': 'SCRIPT' if script_id else 'ACTION',
        'id': script_id,
        'uid': action_uid or None,
        'parameters': params.get('parameters'),
        'runAs': params.get('run_as'),
    })
    # LIVE-VERIFIED LIMITATION: a client-credentials token cannot run scripts.
    # NinjaOne answers 403 "Access key does not have user context which is
    # required for this request" -- it attributes a script run to a person, and
    # a machine-to-machine app has no person behind it. Reboot and Windows
    # service control, which look like the same class of operation, are NOT
    # restricted this way and work fine on the same token. There is no scope
    # that lifts this; it needs an authorization-code token instead.
    return _client(config, kwargs).make_request(
        '/device/{}/script/run'.format(_device_id(params)), method='POST', body=body)


def get_automation_scripts(config, params, **kwargs):
    query = _build_params({'lang': params.get('language')})
    return _client(config, kwargs).make_request('/automation/scripts', params=query)


def get_scripting_options(config, params, **kwargs):
    query = _build_params({'lang': params.get('language')})
    return _client(config, kwargs).make_request(
        '/device/{}/scripting/options'.format(_device_id(params)), params=query)


def reboot_device(config, params, **kwargs):
    mode = (_text(params.get('mode')) or 'NORMAL').strip().upper()
    if mode not in ('NORMAL', 'FORCED'):
        raise ConnectorError('Reboot Mode must be NORMAL or FORCED, got "{}".'.format(mode))
    body = _build_params({'reason': params.get('reason')})
    device_id = _device_id(params)
    _client(config, kwargs).make_request(
        '/device/{}/reboot/{}'.format(device_id, mode), method='POST', body=body or None)
    return {'status': 'Submitted', 'device_id': device_id, 'mode': mode}


def control_windows_service(config, params, **kwargs):
    action = (_text(_require(params, 'action', 'Action'))).strip().upper()
    if action not in ('START', 'PAUSE', 'STOP', 'RESTART'):
        raise ConnectorError('Action must be one of START, PAUSE, STOP, RESTART.')
    service_id = _require(params, 'service_id', 'Service ID')
    device_id = _device_id(params)
    _client(config, kwargs).make_request(
        '/device/{}/windows-service/{}/control'.format(device_id, service_id),
        method='POST', body={'action': action})
    return {'status': 'Submitted', 'device_id': device_id,
            'service_id': service_id, 'action': action}


def schedule_maintenance(config, params, **kwargs):
    """Suppress monitoring on a device for a window.

    `end` is mandatory: NinjaOne has no open-ended maintenance, and omitting it
    fails the call rather than defaulting to anything.
    """
    end = _to_epoch_millis(_require(params, 'end_time', 'End Time'))
    body = _build_params({
        'disabledFeatures': _as_list(params.get('disabled_features')) or None,
        'start': _to_epoch_millis(params.get('start_time')),
        'end': end,
        'reasonMessage': params.get('reason'),
    })
    device_id = _device_id(params)
    _client(config, kwargs).make_request(
        '/device/{}/maintenance'.format(device_id), method='PUT', body=body)
    return {'status': 'Success', 'device_id': device_id, 'end': end}


def cancel_maintenance(config, params, **kwargs):
    device_id = _device_id(params)
    _client(config, kwargs).make_request(
        '/device/{}/maintenance'.format(device_id), method='DELETE')
    return {'status': 'Success', 'device_id': device_id}


def get_jobs(config, params, **kwargs):
    query = _build_params({
        'jobType': _as_csv(params.get('job_type')),
        'df': params.get('device_filter'),
        'tz': params.get('timezone'),
    })
    return _client(config, kwargs).make_request('/jobs', params=query)


def get_device_jobs(config, params, **kwargs):
    query = _build_params({'tz': params.get('timezone')})
    return _client(config, kwargs).make_request(
        '/device/{}/jobs'.format(_device_id(params)), params=query)


# --------------------------------------------------- alerts & activities --

def get_alerts(config, params, **kwargs):
    query = _build_params({
        'sourceType': params.get('source_type'),
        'df': params.get('device_filter'),
        'tz': params.get('timezone'),
    })
    return _client(config, kwargs).make_request('/alerts', params=query)


def get_device_alerts(config, params, **kwargs):
    query = _build_params({'tz': params.get('timezone')})
    return _client(config, kwargs).make_request(
        '/device/{}/alerts'.format(_device_id(params)), params=query)


def reset_alert(config, params, **kwargs):
    uid = _require(params, 'alert_uid', 'Alert UID')
    activity_data = _as_dict(params.get('activity_data'), 'Activity Data')
    client = _client(config, kwargs)
    if activity_data:
        # The POST variant records custom data on the resulting activity; the
        # DELETE variant just clears the condition.
        client.make_request('/alert/{}/reset'.format(uid), method='POST', body=activity_data)
    else:
        client.make_request('/alert/{}'.format(uid), method='DELETE')
    return {'status': 'Success', 'alert_uid': uid}


def get_activities(config, params, **kwargs):
    query = _build_params({
        'class': params.get('activity_class'),
        'df': params.get('device_filter'),
        'type': params.get('type'),
        'status': _as_csv(params.get('status')),
        'user': _as_csv(params.get('user')),
        'seriesUid': params.get('series_uid'),
        'olderThan': _int_or_none(params.get('older_than')),
        'newerThan': _int_or_none(params.get('newer_than')),
        'startTime': _to_iso(params.get('start_time')),
        'endTime': _to_iso(params.get('end_time')),
        'pageSize': _max_records(params),
        'tz': params.get('timezone'),
    })
    return _client(config, kwargs).make_request('/activities', params=query)


def get_device_activities(config, params, **kwargs):
    query = _build_params({
        'activityType': params.get('type'),
        'status': _as_csv(params.get('status')),
        'seriesUid': params.get('series_uid'),
        'olderThan': _int_or_none(params.get('older_than')),
        'newerThan': _int_or_none(params.get('newer_than')),
        'startTime': _to_iso(params.get('start_time')),
        'endTime': _to_iso(params.get('end_time')),
        'pageSize': _max_records(params),
        'tz': params.get('timezone'),
    })
    return _client(config, kwargs).make_request(
        '/device/{}/activities'.format(_device_id(params)), params=query)


# ---------------------------------------------- organizations & grouping --

def get_organizations(config, params, **kwargs):
    client = _client(config, kwargs)
    query = _build_params({'of': params.get('organization_filter')})
    orgs = client.paginate_after('/organizations', query, _max_records(params))
    return {'count': len(orgs), 'organizations': orgs}


def get_organization(config, params, **kwargs):
    org_id = _require(params, 'organization_id', 'Organization ID')
    return _client(config, kwargs).make_request('/organization/{}'.format(org_id))


def get_organization_devices(config, params, **kwargs):
    client = _client(config, kwargs)
    org_id = _require(params, 'organization_id', 'Organization ID')
    devices = client.paginate_after(
        '/organization/{}/devices'.format(org_id), {}, _max_records(params))
    return {'count': len(devices), 'organization_id': org_id, 'devices': devices}


def get_organization_locations(config, params, **kwargs):
    org_id = _require(params, 'organization_id', 'Organization ID')
    return _client(config, kwargs).make_request('/organization/{}/locations'.format(org_id))


def get_groups(config, params, **kwargs):
    return _client(config, kwargs).make_request('/groups')


def get_group_devices(config, params, **kwargs):
    group_id = _require(params, 'group_id', 'Group ID')
    return _client(config, kwargs).make_request('/group/{}/device-ids'.format(group_id))


def get_policies(config, params, **kwargs):
    return _client(config, kwargs).make_request('/policies')


def get_software_products(config, params, **kwargs):
    return _client(config, kwargs).make_request('/software-products')


def generate_installer(config, params, **kwargs):
    """Mint an agent installer download link for an organization and location.

    This is how a device gets enrolled from a playbook: the returned URL is a
    one-off, pre-tokenized installer that already carries the organization and
    location, so nothing has to be typed on the endpoint. `usage_limit` caps how
    many times that URL may be downloaded -- leave it at 1 for a single machine,
    since the link is a bearer credential for joining your tenant.
    """
    installer_type = (_text(_require(params, 'installer_type', 'Installer Type'))).strip().upper()
    if installer_type not in INSTALLER_TYPES:
        raise ConnectorError('Installer Type must be one of: {}'.format(
            ', '.join(INSTALLER_TYPES)))
    body = _build_params({
        'organizationId': _int_or_none(_require(params, 'organization_id', 'Organization ID')),
        'locationId': _int_or_none(_require(params, 'location_id', 'Location ID')),
        'installerType': installer_type,
        'usageLimit': _int_or_none(params.get('usage_limit')),
    })
    # The OpenAPI document marks `content` optional, but the server deserializes it
    # as non-nullable and rejects the request with a Jackson instantiation error
    # naming a "creator parameter content" -- which reads like a server fault, not
    # a missing field. An empty object satisfies it. (Live-verified.)
    body['content'] = _as_dict(params.get('content'), 'Content')
    return _client(config, kwargs).make_request(
        '/organization/generate-installer', method='POST', body=body)


# ----------------------------------------------------------- ticketing --

def create_ticket(config, params, **kwargs):
    body = _as_dict(params.get('additional_fields'), 'Additional Fields')
    description = params.get('description')
    body.update(_build_params({
        'clientId': _int_or_none(_require(params, 'organization_id', 'Organization ID')),
        'ticketFormId': _int_or_none(_require(params, 'ticket_form_id', 'Ticket Form ID')),
        'subject': _require(params, 'subject', 'Subject'),
        'status': _require(params, 'status', 'Status'),
        'locationId': _int_or_none(params.get('location_id')),
        'nodeId': _int_or_none(params.get('device_id')),
        'type': params.get('type'),
        'severity': params.get('severity'),
        'priority': params.get('priority'),
        'assignedAppUserId': _int_or_none(params.get('assigned_user_id')),
        'requesterUid': params.get('requester_uid'),
        'parentTicketId': _int_or_none(params.get('parent_ticket_id')),
        'tags': _as_list(params.get('tags')) or None,
    }))
    if description not in (None, ''):
        # `description` is an object, not a string -- a bare string is rejected.
        body['description'] = (description if isinstance(description, dict)
                               else {'public': bool(params.get('public')), 'body': description})
    return _client(config, kwargs).make_request('/ticketing/ticket', method='POST', body=body)


def get_ticket(config, params, **kwargs):
    ticket_id = _require(params, 'ticket_id', 'Ticket ID')
    return _client(config, kwargs).make_request('/ticketing/ticket/{}'.format(ticket_id))


def update_ticket(config, params, **kwargs):
    """Change fields on an existing ticket.

    The update endpoint is a full replace, not a merge: version, clientId,
    ticketFormId, subject, status and requesterUid are all mandatory on every
    call. Sending only the field you meant to change therefore wipes the rest,
    or is rejected outright. So the current ticket is read first and the change
    is layered on top -- and `version` is carried through from that read, which
    is also what makes NinjaOne's optimistic locking work.
    """
    ticket_id = _require(params, 'ticket_id', 'Ticket ID')
    client = _client(config, kwargs)
    current = client.make_request('/ticketing/ticket/{}'.format(ticket_id))
    if not isinstance(current, dict):
        raise ConnectorError('Could not read ticket {} before updating it.'.format(ticket_id))

    body = {
        'version': current.get('version'),
        'clientId': current.get('clientId'),
        'ticketFormId': current.get('ticketFormId'),
        'subject': current.get('subject'),
        'status': current.get('status'),
        'requesterUid': current.get('requesterUid'),
    }
    for key in ('locationId', 'nodeId', 'type', 'severity', 'priority',
                'assignedAppUserId', 'parentTicketId', 'tags'):
        if current.get(key) is not None:
            body[key] = current[key]

    body.update(_build_params({
        'subject': params.get('subject'),
        'status': params.get('status'),
        'type': params.get('type'),
        'severity': params.get('severity'),
        'priority': params.get('priority'),
        'assignedAppUserId': _int_or_none(params.get('assigned_user_id')),
        'locationId': _int_or_none(params.get('location_id')),
        'nodeId': _int_or_none(params.get('device_id')),
        'tags': _as_list(params.get('tags')) or None,
    }))
    body.update(_as_dict(params.get('additional_fields'), 'Additional Fields'))

    missing = [k for k in ('version', 'clientId', 'ticketFormId', 'subject', 'status')
               if body.get(k) in (None, '')]
    if missing:
        raise ConnectorError(
            'Ticket {} is missing fields the update endpoint requires: {}. Supply them '
            'via Additional Fields.'.format(ticket_id, ', '.join(missing)))

    return client.make_request('/ticketing/ticket/{}'.format(ticket_id), method='PUT', body=body)


def add_ticket_comment(config, params, **kwargs):
    """Append a comment to a ticket.

    This endpoint is multipart/form-data even with no file attached, and the
    comment itself is a JSON document inside one of the parts. Posting it as a
    plain JSON body returns 415.
    """
    ticket_id = _require(params, 'ticket_id', 'Ticket ID')
    comment = {
        'body': _require(params, 'body', 'Comment Body'),
        'public': bool(params.get('public')),
    }
    if params.get('html_body'):
        comment['htmlBody'] = params['html_body']
    files = {'comment': (None, json.dumps(comment), 'application/json')}
    return _client(config, kwargs).make_request(
        '/ticketing/ticket/{}/comment'.format(ticket_id), method='POST', files=files)


def get_tickets_by_board(config, params, **kwargs):
    board_id = _require(params, 'board_id', 'Board ID')
    body = _build_params({
        'pageSize': _max_records(params),
        'searchCriteria': params.get('search'),
        'lastCursorId': _int_or_none(params.get('last_cursor_id')),
        'filters': _as_list(params.get('filters')) or None,
        'sortBy': _as_list(params.get('sort_by')) or None,
        'includeColumns': _as_list(params.get('include_columns')) or None,
    })
    return _client(config, kwargs).make_request(
        '/ticketing/trigger/board/{}/run'.format(board_id), method='POST', body=body)


# ------------------------------------------------------------ ingestion --

def _normalize_patch(row, patch_kind):
    """Flatten a patch report row into a flat, mappable finding.

    The OS and software patch reports do not share a schema -- an OS patch is
    identified by KB article and CVE list, a software patch by product and
    version -- so both are folded into one shape here. Without this, a single
    ingestion playbook would need two different field mappings.
    """
    device_id = row.get('deviceId') or row.get('id')
    if patch_kind == 'os':
        unique = row.get('kbNumber') or row.get('id')
        name = row.get('title') or row.get('name')
        product = row.get('productName') or 'Operating System'
        version = None
        rating = row.get('severity')
    else:
        unique = row.get('patchId') or row.get('productIdentifier') or row.get('id')
        name = row.get('name') or row.get('productName')
        product = row.get('productName') or row.get('productIdentifier')
        version = row.get('version')
        rating = row.get('impact')
    return {
        # source_id must be stable per (device, patch) or every ingestion run
        # creates a duplicate record instead of updating the existing one.
        'source_id': '{}:{}:{}'.format(patch_kind, device_id, unique),
        'patch_kind': patch_kind,
        'device_id': device_id,
        'patch_id': unique,
        'kb_number': row.get('kbNumber'),
        'cve_ids': row.get('cveIds') or [],
        'name': name,
        'product': product,
        'version': version,
        'status': row.get('status'),
        'severity': rating,
        'type': row.get('type'),
        'impact': row.get('impact'),
        'installed_at': _epoch_to_iso(row.get('installedAt')),
        'timestamp': _epoch_to_iso(row.get('timestamp')),
        'raw': row,
    }


def fetch_patch_findings(config, params, **kwargs):
    """Pull pending/failed patches across the estate as normalized findings.

    This is the ingestion entry point. Both report endpoints are queried unless
    the caller narrows to one, and the results are merged into a single list so
    one playbook mapping covers both.
    """
    client = _client(config, kwargs)
    kinds = params.get('patch_kind') or 'Both'
    max_records = _max_records(params, DEFAULT_PAGE_SIZE)
    findings = []

    common = {
        'df': params.get('device_filter'),
        'status': _as_csv(params.get('status')),
    }
    if kinds in ('Both', 'Operating System'):
        query = _build_params(dict(common, severity=_as_csv(params.get('severity'))))
        rows, _ = client.paginate_cursor('/queries/os-patches', query, max_records)
        findings.extend(_normalize_patch(r, 'os') for r in rows)
    if kinds in ('Both', 'Third-Party Software'):
        query = _build_params(dict(common, impact=_as_csv(params.get('impact')),
                                   productIdentifier=params.get('product_identifier')))
        rows, _ = client.paginate_cursor('/queries/software-patches', query, max_records)
        findings.extend(_normalize_patch(r, 'software') for r in rows)

    findings = findings[:max_records]

    if params.get('create_pb_id') and trigger_ingest_playbook:
        trigger_ingest_playbook(findings, params['create_pb_id'],
                                parent_env=kwargs.get('env', {}), batch_size=100,
                                dedup_field=params.get('dedup_field') or 'source_id')
        return {'status': 'Success', 'ingested': len(findings)}
    return {'count': len(findings), 'findings': findings}


# --------------------------------------------------------------- health --

def _check_health(config, **kwargs):
    client = _client(config, kwargs)
    try:
        # Cheapest authenticated read that proves both the token and the region:
        # one organization is enough, and an estate of 10k does not get walked.
        response = client.make_request('/organizations', params={'pageSize': 1})
    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError('Health check failed: {}'.format(err))
    if not isinstance(response, list):
        raise ConnectorError(
            'Health check failed: NinjaOne returned an unexpected response for '
            '/v2/organizations: {}'.format(response))
    logger.info('NinjaOne health check succeeded against %s', client.server_url)
    return True


operations = {
    # devices
    'get_devices': get_devices,
    'get_devices_detailed': get_devices_detailed,
    'search_devices': search_devices,
    'get_device': get_device,
    'update_device': update_device,
    'get_device_custom_fields': get_device_custom_fields,
    'update_device_custom_fields': update_device_custom_fields,
    'get_device_dashboard_url': get_device_dashboard_url,
    # inventory
    'get_device_software': get_device_software,
    'get_device_disks': get_device_disks,
    'get_device_volumes': get_device_volumes,
    'get_device_processors': get_device_processors,
    'get_device_network_interfaces': get_device_network_interfaces,
    'get_device_last_logged_on_user': get_device_last_logged_on_user,
    'get_device_windows_services': get_device_windows_services,
    'get_software_inventory_report': get_software_inventory_report,
    'get_device_health_report': get_device_health_report,
    # patching
    'get_device_pending_os_patches': get_device_pending_os_patches,
    'get_device_installed_os_patches': get_device_installed_os_patches,
    'get_device_pending_software_patches': get_device_pending_software_patches,
    'get_device_installed_software_patches': get_device_installed_software_patches,
    'get_pending_os_patches_report': get_pending_os_patches_report,
    'get_pending_software_patches_report': get_pending_software_patches_report,
    'scan_os_patches': scan_os_patches,
    'apply_os_patches': apply_os_patches,
    'scan_software_patches': scan_software_patches,
    'apply_software_patches': apply_software_patches,
    # control
    'run_script': run_script,
    'get_automation_scripts': get_automation_scripts,
    'get_scripting_options': get_scripting_options,
    'reboot_device': reboot_device,
    'control_windows_service': control_windows_service,
    'schedule_maintenance': schedule_maintenance,
    'cancel_maintenance': cancel_maintenance,
    'get_jobs': get_jobs,
    'get_device_jobs': get_device_jobs,
    # alerts & activities
    'get_alerts': get_alerts,
    'get_device_alerts': get_device_alerts,
    'reset_alert': reset_alert,
    'get_activities': get_activities,
    'get_device_activities': get_device_activities,
    # organizations
    'get_organizations': get_organizations,
    'get_organization': get_organization,
    'get_organization_devices': get_organization_devices,
    'get_organization_locations': get_organization_locations,
    'get_groups': get_groups,
    'get_group_devices': get_group_devices,
    'get_policies': get_policies,
    'get_software_products': get_software_products,
    'generate_installer': generate_installer,
    # ticketing
    'create_ticket': create_ticket,
    'get_ticket': get_ticket,
    'update_ticket': update_ticket,
    'add_ticket_comment': add_ticket_comment,
    'get_tickets_by_board': get_tickets_by_board,
    # ingestion
    'fetch_patch_findings': fetch_patch_findings,
}

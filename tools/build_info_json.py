#!/usr/bin/env python3
"""Generate ninjaone/info.json.

55 operations of hand-written JSON drift: a tooltip gets fixed in one place and
not the sibling, a required flag goes missing, an enum falls out of step with
constants.py. Building the manifest from one description keeps the field
conventions uniform and lets the enums come straight from the connector's own
constants, which is the only copy that the runtime actually honours.

    python3 tools/build_info_json.py          # rewrite ninjaone/info.json
    python3 tools/build_info_json.py --check  # fail if it is out of date
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from ninjaone.constants import (  # noqa: E402
    ACTIVITY_CLASSES,
    CONNECTOR_VERSION,
    DEFAULT_REGION,
    DEFAULT_SCOPE,
    INSTALL_STATUSES,
    INSTALLER_TYPES,
    OS_PATCH_STATUSES,
    PATCH_IMPACTS,
    PATCH_SEVERITIES,
    PATCH_TYPES,
    REBOOT_MODES,
    REGION_HOSTS,
    SERVICE_ACTIONS,
    SERVICE_STATES,
    SOFTWARE_PATCH_STATUSES,
    TICKET_PRIORITIES,
    TICKET_SEVERITIES,
    TICKET_TYPES,
)

INFO_PATH = os.path.join(ROOT, 'ninjaone', 'info.json')


def field(name, title, ftype='text', required=False, description='', tooltip=None,
          value=None, options=None, placeholder=None):
    out = {
        'title': title,
        'name': name,
        'type': ftype,
        'required': required,
        'editable': True,
        'visible': True,
    }
    if options:
        out['options'] = options
    if value is not None:
        out['value'] = value
    if placeholder:
        out['placeholder'] = placeholder
    out['tooltip'] = tooltip or description
    out['description'] = description
    return out


# ------------------------------------------------------- shared parameters --

def p_device():
    return field('device_id', 'Device ID', 'integer', True,
                 'Numeric NinjaOne device identifier. Use Search Devices to resolve a '
                 'hostname, IP, or logged-on user to this ID.',
                 'Numeric NinjaOne device ID. Search Devices resolves a hostname to it.')


def p_device_filter():
    return field('device_filter', 'Device Filter', 'text', False,
                 'NinjaOne device filter (the "df" syntax), e.g. "org = 1", '
                 '"class = WINDOWS_WORKSTATION", or "online = true". Leave blank for the '
                 'whole estate.',
                 'NinjaOne device filter (df syntax). Blank means the whole estate.')


def p_max_records(default=200):
    return field('max_records', 'Maximum Records', 'integer', False,
                 'Hard stop on the number of records returned. The connector pages until '
                 'it reaches this many.',
                 'Hard stop on records returned; the connector pages up to this many.',
                 value=default)


def p_timezone():
    return field('timezone', 'Time Zone', 'text', False,
                 'IANA time zone used to render timestamps, e.g. "America/Los_Angeles". '
                 'Defaults to the tenant setting.',
                 'IANA time zone for rendered timestamps.')


def p_name_contains():
    return field('name_contains', 'Product Name Contains', 'text', False,
                 'Case-insensitive substring match on the product name, applied after the '
                 'results are fetched. Use it to turn an advisory\'s product name into '
                 '"which of our endpoints run this?".',
                 'Case-insensitive substring match on the product name.')


def p_installed_window():
    return [
        field('installed_after', 'Installed After', 'datetime', False,
              'Only include patches installed after this time.'),
        field('installed_before', 'Installed Before', 'datetime', False,
              'Only include patches installed before this time.'),
    ]


# ------------------------------------------------------------- operations --

def op(operation, title, description, category, parameters=None, output_schema=None):
    return {
        'operation': operation,
        'title': title,
        'description': description,
        'category': category,
        'annotation': operation,
        'enabled': True,
        'parameters': parameters or [],
        'output_schema': output_schema if output_schema is not None else {},
    }


DEVICE_SCHEMA = {
    'id': '', 'parentDeviceId': '', 'organizationId': '', 'locationId': '',
    'nodeClass': '', 'nodeRoleId': '', 'policyId': '', 'approvalStatus': '',
    'offline': '', 'displayName': '', 'systemName': '', 'dnsName': '',
    'lastContact': '', 'lastUpdate': '', 'created': '',
    'system': {'name': '', 'manufacturer': '', 'model': '', 'serialNumber': '',
               'domain': '', 'totalPhysicalMemory': ''},
    'os': {'manufacturer': '', 'name': '', 'architecture': '', 'buildNumber': '',
           'lastBootTime': ''},
    'ipAddresses': [], 'macAddresses': [],
}

OS_PATCH_SCHEMA = {
    'deviceId': '', 'id': '', 'kbNumber': '', 'title': '', 'severity': '',
    'status': '', 'type': '', 'cveIds': [], 'timestamp': '',
}

SOFTWARE_PATCH_SCHEMA = {
    'deviceId': '', 'productIdentifier': '', 'patchId': '', 'name': '',
    'productName': '', 'version': '', 'impact': '', 'status': '', 'type': '',
    'timestamp': '',
}

FINDING_SCHEMA = {
    'count': '',
    'findings': [{
        'source_id': '', 'patch_kind': '', 'device_id': '', 'patch_id': '',
        'kb_number': '', 'cve_ids': [], 'name': '', 'product': '', 'version': '',
        'status': '', 'severity': '', 'type': '', 'impact': '',
        'installed_at': '', 'timestamp': '', 'raw': {},
    }],
}

SUBMITTED_SCHEMA = {'status': '', 'device_id': '', 'action': '', 'message': ''}

TICKET_SCHEMA = {
    'id': '', 'version': '', 'clientId': '', 'ticketFormId': '', 'nodeId': '',
    'subject': '', 'status': '', 'type': '', 'severity': '', 'priority': '',
    'assignedAppUserId': '', 'requesterUid': '', 'tags': [], 'createTime': '',
}

OPERATIONS = [
    # ---------------------------------------------------------------- devices
    op('get_devices', 'Get Devices',
       'Retrieves devices from NinjaOne, optionally narrowed by a device filter. Pages '
       'automatically up to the record limit.',
       'investigation',
       [p_device_filter(), p_max_records()],
       {'count': '', 'devices': [DEVICE_SCHEMA]}),

    op('get_devices_detailed', 'Get Devices (Detailed)',
       'Retrieves devices with their full nested detail (system, OS, network, and policy '
       'information) in one call, avoiding a Get Device per row.',
       'investigation',
       [p_device_filter(), p_max_records()],
       {'count': '', 'devices': [DEVICE_SCHEMA]}),

    op('search_devices', 'Search Devices',
       'Finds devices by free-text query across name, logged-on user, and IP address. This '
       'is how you turn a hostname from an alert into the numeric device ID every other '
       'device operation needs.',
       'investigation',
       [field('query', 'Search Query', 'text', True,
              'Free text to match against device name, logged-on user, or IP address.'),
        field('limit', 'Limit', 'integer', False,
              'Maximum number of matches to return.', value=50)],
       {'devices': [{'id': '', 'name': '', 'nodeClass': ''}]}),

    op('get_device', 'Get Device Details',
       'Retrieves the full record for a single device.',
       'investigation', [p_device()], DEVICE_SCHEMA),

    op('update_device', 'Update Device',
       'Changes a device\'s display name, assigned policy, role, organization, location, or '
       'custom attributes.',
       'remediation',
       [p_device(),
        field('display_name', 'Display Name', 'text', False,
              'New user-assigned display name.'),
        field('policy_id', 'Policy ID', 'integer', False,
              'Policy to assign. Overrides the organization policy mapping; clear it to '
              'revert to the organization default.'),
        field('node_role_id', 'Node Role ID', 'integer', False, 'Device role to assign.'),
        field('organization_id', 'Organization ID', 'integer', False,
              'Move the device to this organization.'),
        field('location_id', 'Location ID', 'integer', False,
              'Move the device to this location.'),
        field('user_data', 'Custom Attributes', 'json', False,
              'Custom attributes to set, as a JSON object.'),
        field('additional_fields', 'Additional Fields', 'json', False,
              'Any other body fields, as a JSON object. Merged into the request, so this '
              'reaches fields the form above does not expose.')],
       {'status': ''}),

    op('get_device_custom_fields', 'Get Device Custom Fields',
       'Retrieves the custom field values set on a device.',
       'investigation',
       [p_device(),
        field('with_inheritance', 'With Inheritance', 'checkbox', False,
              'Resolve values through the definition scope hierarchy rather than returning '
              'only values set directly on the device.', value=False)],
       {}),

    op('update_device_custom_fields', 'Update Device Custom Fields',
       'Sets custom field values on a device. Useful for writing a FortiSOAR record ID or '
       'remediation state back onto the endpoint.',
       'remediation',
       [p_device(),
        field('fields', 'Field Values', 'json', True,
              'JSON object of field name to value, e.g. {"soarTicket": "IR-1043"}.')],
       {'status': ''}),

    op('get_device_dashboard_url', 'Get Device Dashboard URL',
       'Returns a deep link to the device in the NinjaOne console, for attaching to an alert '
       'or a case note.',
       'investigation', [p_device()], {'url': ''}),

    # -------------------------------------------------------------- inventory
    op('get_device_software', 'Get Device Software Inventory',
       'Lists the software installed on a device. This is the "does this vulnerable product '
       'exist here?" lookup.',
       'investigation', [p_device()],
       [{'name': '', 'publisher': '', 'version': '', 'installDate': '', 'productCode': ''}]),

    op('get_device_disks', 'Get Device Disks',
       'Lists the physical disk drives on a device, with SMART health where available.',
       'investigation', [p_device()], []),

    op('get_device_volumes', 'Get Device Volumes',
       'Lists storage volumes on a device, optionally including BitLocker encryption status.',
       'investigation',
       [p_device(),
        field('include_bitlocker', 'Include BitLocker Status', 'checkbox', False,
              'Include BitLocker encryption status for each volume.', value=False)],
       []),

    op('get_device_processors', 'Get Device Processors',
       'Lists the processors installed in a device.',
       'investigation', [p_device()], []),

    op('get_device_network_interfaces', 'Get Device Network Interfaces',
       'Lists the network interfaces on a device, with addresses and link state.',
       'investigation', [p_device()], []),

    op('get_device_last_logged_on_user', 'Get Last Logged-On User',
       'Returns the most recent interactive user on a device -- the person to contact about '
       'an alert or a reboot.',
       'investigation', [p_device()], {}),

    op('get_device_windows_services', 'Get Windows Services',
       'Lists Windows services on a device, optionally filtered by name or state.',
       'investigation',
       [p_device(),
        field('name', 'Service Name', 'text', False, 'Filter to services matching this name.'),
        field('state', 'State', 'select', False, 'Filter to services in this state.',
              options=SERVICE_STATES)],
       []),

    op('get_software_inventory_report', 'Get Software Inventory Report',
       'Estate-wide software inventory across every device matching the filter, rather than '
       'one device at a time. Pages automatically.',
       'investigation',
       [p_device_filter(), p_name_contains()] + p_installed_window() + [p_max_records()],
       {'count': '', 'cursor': {}, 'results': []}),

    op('get_device_health_report', 'Get Device Health Report',
       'Estate-wide device health report, for triaging which endpoints are unhealthy before '
       'acting on them.',
       'investigation',
       [p_device_filter(),
        field('health', 'Health Status', 'text', False,
              'Filter to a health status, e.g. "HEALTHY" or "UNHEALTHY".'),
        p_max_records()],
       {'count': '', 'cursor': {}, 'results': []}),

    # --------------------------------------------------------------- patching
    op('get_device_pending_os_patches', 'Get Device Pending OS Patches',
       'Lists pending, failed, and rejected operating system patches for one device.',
       'investigation',
       [p_device(),
        field('status', 'Status', 'multiselect', False,
              'Filter to these patch statuses.', options=OS_PATCH_STATUSES),
        field('severity', 'Severity', 'multiselect', False,
              'Filter to these severities.', options=PATCH_SEVERITIES),
        field('type', 'Type', 'multiselect', False, 'Filter to these patch types.',
              options=PATCH_TYPES)],
       [OS_PATCH_SCHEMA]),

    op('get_device_installed_os_patches', 'Get Device Installed OS Patches',
       'OS patch installation history for one device -- what landed, what failed, and when. '
       'Use it to prove a remediation actually took.',
       'investigation',
       [p_device(),
        field('status', 'Status', 'multiselect', False, 'Filter to these statuses.',
              options=INSTALL_STATUSES)] + p_installed_window(),
       []),

    op('get_device_pending_software_patches', 'Get Device Pending Software Patches',
       'Lists pending, failed, and rejected third-party software patches for one device.',
       'investigation',
       [p_device(),
        field('status', 'Status', 'multiselect', False, 'Filter to these patch statuses.',
              options=SOFTWARE_PATCH_STATUSES),
        field('impact', 'Impact', 'multiselect', False, 'Filter to these impact levels.',
              options=PATCH_IMPACTS),
        field('type', 'Type', 'multiselect', False, 'Filter to these patch types.',
              options=PATCH_TYPES),
        field('product_identifier', 'Product Identifier', 'text', False,
              'Restrict to a single product, as listed by Get Software Products.')],
       [SOFTWARE_PATCH_SCHEMA]),

    op('get_device_installed_software_patches', 'Get Device Installed Software Patches',
       'Third-party software patch history for one device.',
       'investigation',
       [p_device(),
        field('status', 'Status', 'multiselect', False, 'Filter to these statuses.',
              options=INSTALL_STATUSES),
        field('impact', 'Impact', 'multiselect', False, 'Filter to these impact levels.',
              options=PATCH_IMPACTS),
        field('type', 'Type', 'multiselect', False, 'Filter to these patch types.',
              options=PATCH_TYPES),
        field('product_identifier', 'Product Identifier', 'text', False,
              'Restrict to a single product.')] + p_installed_window(),
       []),

    op('get_pending_os_patches_report', 'Get Pending OS Patches Report',
       'Estate-wide pending, failed, and rejected OS patches across every device matching '
       'the filter. Pages automatically.',
       'investigation',
       [p_device_filter(),
        field('status', 'Status', 'multiselect', False, 'Filter to these patch statuses.',
              options=OS_PATCH_STATUSES),
        field('severity', 'Severity', 'multiselect', False, 'Filter to these severities.',
              options=PATCH_SEVERITIES),
        field('type', 'Type', 'multiselect', False, 'Filter to these patch types.',
              options=PATCH_TYPES),
        field('timestamp_filter', 'Timestamp Filter', 'text', False,
              'NinjaOne monitoring timestamp filter ("ts" syntax).'),
        p_max_records()],
       {'count': '', 'cursor': {}, 'results': [OS_PATCH_SCHEMA]}),

    op('get_pending_software_patches_report', 'Get Pending Software Patches Report',
       'Estate-wide pending, failed, and rejected third-party software patches. This is the '
       '"who else is exposed?" query for a product-specific advisory.',
       'investigation',
       [p_device_filter(),
        field('status', 'Status', 'multiselect', False, 'Filter to these patch statuses.',
              options=SOFTWARE_PATCH_STATUSES),
        field('impact', 'Impact', 'multiselect', False, 'Filter to these impact levels.',
              options=PATCH_IMPACTS),
        field('type', 'Type', 'multiselect', False, 'Filter to these patch types.',
              options=PATCH_TYPES),
        field('product_identifier', 'Product Identifier', 'text', False,
              'Restrict to a single product, as listed by Get Software Products.'),
        field('timestamp_filter', 'Timestamp Filter', 'text', False,
              'NinjaOne monitoring timestamp filter ("ts" syntax).'),
        p_name_contains(), p_max_records()],
       {'count': '', 'cursor': {}, 'results': [SOFTWARE_PATCH_SCHEMA]}),

    op('scan_os_patches', 'Scan OS Patches',
       'Triggers an operating system patch scan on a device so its pending-patch list is '
       'refreshed before you read it.',
       'remediation', [p_device()], SUBMITTED_SCHEMA),

    op('apply_os_patches', 'Apply OS Patches',
       'Triggers installation of approved operating system patches on a device. NinjaOne '
       'returns no job identifier, so poll Get Device Jobs or re-read the pending list to '
       'confirm completion.',
       'remediation', [p_device()], SUBMITTED_SCHEMA),

    op('scan_software_patches', 'Scan Software Patches',
       'Triggers a third-party software patch scan on a device.',
       'remediation', [p_device()], SUBMITTED_SCHEMA),

    op('apply_software_patches', 'Apply Software Patches',
       'Triggers installation of approved third-party software patches on a device. This is '
       'the actual remediation step for a vulnerable application.',
       'remediation', [p_device()], SUBMITTED_SCHEMA),

    # ---------------------------------------------------------------- control
    op('run_script', 'Run Script',
       'Runs a saved automation script, or a built-in action, on a device. Supply exactly '
       'one of Script ID or Action UID -- NinjaOne rejects both together.',
       'remediation',
       [p_device(),
        field('script_id', 'Script ID', 'integer', False,
              'Numeric ID of a script from the automation library, as listed by Get '
              'Automation Scripts.'),
        field('action_uid', 'Action UID', 'text', False,
              'String UID of a built-in action. Use instead of Script ID, never alongside it.'),
        field('parameters', 'Parameters', 'text', False,
              'Command-line parameters passed to the script or action.'),
        field('run_as', 'Run As', 'text', False,
              'Credential role to run under, e.g. "system" or "loggedonuser".')],
       {'jobUid': ''}),

    op('get_automation_scripts', 'Get Automation Scripts',
       'Lists the automation scripts available in the tenant, with the IDs that Run Script '
       'takes.',
       'investigation',
       [field('language', 'Language', 'text', False, 'Language tag for localized names.')],
       [{'id': '', 'name': '', 'description': '', 'language': '', 'operatingSystems': []}]),

    op('get_scripting_options', 'Get Device Scripting Options',
       'Lists the scripts, built-in actions, and credential roles that are valid for one '
       'specific device.',
       'investigation',
       [p_device(),
        field('language', 'Language', 'text', False, 'Language tag for localized names.')],
       {}),

    op('reboot_device', 'Reboot Device',
       'Reboots a device, either gracefully or forcibly.',
       'remediation',
       [p_device(),
        field('mode', 'Reboot Mode', 'select', True,
              'NORMAL asks the operating system to reboot cleanly. FORCED does not wait for '
              'applications to close and can lose unsaved work.',
              value='NORMAL', options=REBOOT_MODES),
        field('reason', 'Reason', 'text', False,
              'Reason recorded against the reboot in the device activity log.')],
       {'status': '', 'device_id': '', 'mode': ''}),

    op('control_windows_service', 'Control Windows Service',
       'Starts, stops, pauses, or restarts a Windows service on a device.',
       'remediation',
       [p_device(),
        field('service_id', 'Service ID', 'text', True,
              'Service identifier, as returned by Get Windows Services.'),
        field('action', 'Action', 'select', True, 'Action to take on the service.',
              options=SERVICE_ACTIONS)],
       {'status': '', 'device_id': '', 'service_id': '', 'action': ''}),

    op('schedule_maintenance', 'Schedule Maintenance',
       'Suppresses monitoring on a device for a window. End Time is mandatory -- NinjaOne has '
       'no open-ended maintenance mode.',
       'remediation',
       [p_device(),
        field('end_time', 'End Time', 'datetime', True,
              'When the maintenance window ends. Required.'),
        field('start_time', 'Start Time', 'datetime', False,
              'When the maintenance window begins. Defaults to now.'),
        field('disabled_features', 'Disabled Features', 'text', False,
              'Features to suspend during the window, comma-separated, e.g. '
              '"ALERTS,PATCHING,AVSCANS,TASKS".'),
        field('reason', 'Reason', 'text', False, 'Reason recorded for the window.')],
       {'status': '', 'device_id': '', 'end': ''}),

    op('cancel_maintenance', 'Cancel Maintenance',
       'Ends an active maintenance window on a device and resumes monitoring.',
       'remediation', [p_device()], {'status': '', 'device_id': ''}),

    op('get_jobs', 'Get Active Jobs',
       'Lists jobs currently running across the estate -- the way to see whether a patch '
       'apply or script run is still in flight.',
       'investigation',
       [field('job_type', 'Job Type', 'text', False,
              'Filter to these job types, comma-separated.'),
        p_device_filter(), p_timezone()],
       []),

    op('get_device_jobs', 'Get Device Jobs',
       'Lists jobs currently running on one device. Poll this after Apply Patches or Run '
       'Script, which return no job identifier of their own.',
       'investigation', [p_device(), p_timezone()], []),

    # ---------------------------------------------------- alerts & activities
    op('get_alerts', 'Get Alerts',
       'Lists active alerts (triggered conditions) across the estate.',
       'investigation',
       [p_device_filter(),
        field('source_type', 'Source Type', 'text', False,
              'Filter to alerts from this source type, e.g. "CONDITION".'),
        p_timezone()],
       [{'uid': '', 'deviceId': '', 'message': '', 'sourceType': '', 'severity': '',
         'createTime': ''}]),

    op('get_device_alerts', 'Get Device Alerts',
       'Lists active alerts for one device.',
       'investigation', [p_device(), p_timezone()], []),

    op('reset_alert', 'Reset Alert',
       'Clears a triggered condition. Supplying Activity Data records that data on the '
       'resulting activity entry, which is how you write a FortiSOAR case reference back '
       'into NinjaOne.',
       'remediation',
       [field('alert_uid', 'Alert UID', 'text', True,
              'UID of the alert to reset, as returned by Get Alerts.'),
        field('activity_data', 'Activity Data', 'json', False,
              'Optional JSON object recorded against the reset activity.')],
       {'status': '', 'alert_uid': ''}),

    op('get_activities', 'Get Activities',
       'Retrieves the activity log across the estate, filtered by class, type, status, time '
       'window, or device.',
       'investigation',
       [field('activity_class', 'Activity Class', 'select', False,
              'Restrict to system, device, or user activities.',
              value='ALL', options=ACTIVITY_CLASSES),
        p_device_filter(),
        field('type', 'Activity Type', 'text', False, 'Restrict to this activity type.'),
        field('status', 'Status', 'text', False,
              'Restrict to these statuses, comma-separated.'),
        field('user', 'User', 'text', False, 'Restrict to these users, comma-separated.'),
        field('series_uid', 'Alert Series UID', 'text', False,
              'Restrict to activities belonging to one alert series.'),
        field('start_time', 'Start Time', 'datetime', False,
              'Only activities recorded at or after this time.'),
        field('end_time', 'End Time', 'datetime', False,
              'Only activities recorded at or before this time.'),
        field('newer_than', 'Newer Than Activity ID', 'integer', False,
              'Only activities with an ID greater than this. The reliable cursor for '
              'polling, since it cannot skip entries that share a timestamp.'),
        field('older_than', 'Older Than Activity ID', 'integer', False,
              'Only activities with an ID lower than this.'),
        p_max_records(), p_timezone()],
       {'lastActivityId': '', 'activities': [
           {'id': '', 'activityTime': '', 'deviceId': '', 'activityType': '',
            'statusCode': '', 'message': '', 'seriesUid': ''}]}),

    op('get_device_activities', 'Get Device Activities',
       'Retrieves the activity log for one device -- the audit trail of what NinjaOne did to '
       'it and when.',
       'investigation',
       [p_device(),
        field('type', 'Activity Type', 'text', False, 'Restrict to this activity type.'),
        field('status', 'Status', 'text', False,
              'Restrict to these statuses, comma-separated.'),
        field('series_uid', 'Alert Series UID', 'text', False,
              'Restrict to activities belonging to one alert series.'),
        field('start_time', 'Start Time', 'datetime', False,
              'Only activities recorded at or after this time.'),
        field('end_time', 'End Time', 'datetime', False,
              'Only activities recorded at or before this time.'),
        field('newer_than', 'Newer Than Activity ID', 'integer', False,
              'Only activities with an ID greater than this.'),
        field('older_than', 'Older Than Activity ID', 'integer', False,
              'Only activities with an ID lower than this.'),
        p_max_records(), p_timezone()],
       {}),

    # --------------------------------------------------------- organizations
    op('get_organizations', 'Get Organizations',
       'Lists the organizations (tenants) in NinjaOne.',
       'investigation',
       [field('organization_filter', 'Organization Filter', 'text', False,
              'NinjaOne organization filter ("of" syntax).'),
        p_max_records()],
       {'count': '', 'organizations': [
           {'id': '', 'name': '', 'description': '', 'nodeApprovalMode': ''}]}),

    op('get_organization', 'Get Organization',
       'Retrieves a single organization by ID.',
       'investigation',
       [field('organization_id', 'Organization ID', 'integer', True,
              'Numeric organization identifier.')],
       {'id': '', 'name': '', 'description': ''}),

    op('get_organization_devices', 'Get Organization Devices',
       'Lists every device belonging to one organization. Pages automatically.',
       'investigation',
       [field('organization_id', 'Organization ID', 'integer', True,
              'Numeric organization identifier.'),
        p_max_records()],
       {'count': '', 'organization_id': '', 'devices': [DEVICE_SCHEMA]}),

    op('get_organization_locations', 'Get Organization Locations',
       'Lists the locations configured for an organization.',
       'investigation',
       [field('organization_id', 'Organization ID', 'integer', True,
              'Numeric organization identifier.')],
       [{'id': '', 'name': '', 'organizationId': '', 'address': ''}]),

    op('get_groups', 'Get Groups',
       'Lists groups (saved device searches). A group is the usual way to express "all '
       'servers" or "all laptops missing patches" once and reuse it.',
       'investigation', [],
       [{'id': '', 'name': '', 'description': ''}]),

    op('get_group_devices', 'Get Group Devices',
       'Returns the device IDs that currently match a group\'s saved search.',
       'investigation',
       [field('group_id', 'Group ID', 'integer', True, 'Numeric group identifier.')],
       []),

    op('get_policies', 'Get Policies',
       'Lists the policies defined in the tenant, with the IDs that Update Device takes.',
       'investigation', [],
       [{'id': '', 'name': '', 'description': '', 'nodeClass': ''}]),

    op('get_software_products', 'Get Software Products',
       'Lists the third-party products NinjaOne can patch, with the product identifiers the '
       'software patch operations filter on.',
       'investigation', [],
       [{'id': '', 'vendorName': '', 'productName': '', 'installable': ''}]),

    op('generate_installer', 'Generate Agent Installer',
       'Mints a pre-tokenized agent installer download link for an organization and '
       'location. This is how a device gets enrolled from a playbook: the URL already '
       'carries the organization and location, so nothing has to be typed on the endpoint.',
       'remediation',
       [field('organization_id', 'Organization ID', 'integer', True,
              'Organization the enrolled device will belong to.'),
        field('location_id', 'Location ID', 'integer', True,
              'Location within that organization, as listed by Get Organization Locations.'),
        field('installer_type', 'Installer Type', 'select', True,
              'Agent package to build. WINDOWS_MSI for Windows guests; LINUX_RPM for a '
              'Rocky/RHEL host, LINUX_DEB for Debian/Ubuntu.',
              value='WINDOWS_MSI', options=INSTALLER_TYPES),
        field('usage_limit', 'Usage Limit', 'integer', False,
              'How many times the link may be downloaded. The URL is a bearer credential '
              'for joining your tenant, so keep this at 1 for a single machine.',
              value=1)],
       {'url': '', 'installerType': '', 'organizationId': '', 'locationId': ''}),

    # -------------------------------------------------------------- ticketing
    op('create_ticket', 'Create Ticket',
       'Creates a NinjaOne ticket, optionally linked to a device. Requires the Ninja '
       'Ticketing add-on to be enabled on the tenant.',
       'remediation',
       [field('organization_id', 'Organization ID', 'integer', True,
              'Organization (client) the ticket belongs to.'),
        field('ticket_form_id', 'Ticket Form ID', 'integer', True,
              'Ticket form to create against, as listed by the ticketing configuration.'),
        field('subject', 'Subject', 'text', True, 'Ticket subject line.'),
        field('status', 'Status', 'text', True,
              'Ticket status, e.g. "NEW". Must be a status defined on the tenant.'),
        field('description', 'Description', 'text', False,
              'Ticket body. Sent as the description document.'),
        field('public', 'Public Description', 'checkbox', False,
              'Make the description visible to the end user rather than internal-only.',
              value=False),
        field('device_id', 'Device ID', 'integer', False,
              'Device to associate the ticket with.'),
        field('location_id', 'Location ID', 'integer', False, 'Location for the ticket.'),
        field('type', 'Type', 'select', False, 'Ticket type.', options=TICKET_TYPES),
        field('severity', 'Severity', 'select', False, 'Ticket severity.',
              options=TICKET_SEVERITIES),
        field('priority', 'Priority', 'select', False, 'Ticket priority.',
              options=TICKET_PRIORITIES),
        field('assigned_user_id', 'Assigned Technician ID', 'integer', False,
              'Technician to assign the ticket to.'),
        field('requester_uid', 'Requester UID', 'text', False,
              'UID of the requesting contact or end user.'),
        field('parent_ticket_id', 'Parent Ticket ID', 'integer', False,
              'Parent ticket, to create this as a child.'),
        field('tags', 'Tags', 'text', False, 'Tags to apply, comma-separated.'),
        field('additional_fields', 'Additional Fields', 'json', False,
              'Any other body fields, as a JSON object.')],
       TICKET_SCHEMA),

    op('get_ticket', 'Get Ticket',
       'Retrieves a ticket by ID, including the version number that Update Ticket needs.',
       'investigation',
       [field('ticket_id', 'Ticket ID', 'integer', True, 'Numeric ticket identifier.')],
       TICKET_SCHEMA),

    op('update_ticket', 'Update Ticket',
       'Changes fields on an existing ticket. NinjaOne\'s update endpoint is a full replace, '
       'so this operation reads the ticket first and layers your changes on top -- supply '
       'only the fields you want changed.',
       'remediation',
       [field('ticket_id', 'Ticket ID', 'integer', True, 'Numeric ticket identifier.'),
        field('status', 'Status', 'text', False, 'New ticket status.'),
        field('subject', 'Subject', 'text', False, 'New subject line.'),
        field('type', 'Type', 'select', False, 'New ticket type.', options=TICKET_TYPES),
        field('severity', 'Severity', 'select', False, 'New severity.',
              options=TICKET_SEVERITIES),
        field('priority', 'Priority', 'select', False, 'New priority.',
              options=TICKET_PRIORITIES),
        field('assigned_user_id', 'Assigned Technician ID', 'integer', False,
              'Reassign to this technician.'),
        field('location_id', 'Location ID', 'integer', False, 'New location.'),
        field('device_id', 'Device ID', 'integer', False, 'Associate with this device.'),
        field('tags', 'Tags', 'text', False,
              'Replacement tags, comma-separated. Replaces the existing set.'),
        field('additional_fields', 'Additional Fields', 'json', False,
              'Any other body fields, as a JSON object. Applied last, so it overrides '
              'everything above.')],
       TICKET_SCHEMA),

    op('add_ticket_comment', 'Add Ticket Comment',
       'Appends a comment to a ticket, either internal or visible to the end user.',
       'remediation',
       [field('ticket_id', 'Ticket ID', 'integer', True, 'Numeric ticket identifier.'),
        field('body', 'Comment Body', 'text', True, 'Comment text.'),
        field('public', 'Public Comment', 'checkbox', False,
              'Make the comment visible to the end user rather than internal-only.',
              value=False),
        field('html_body', 'HTML Body', 'text', False,
              'Optional HTML rendering of the comment.')],
       {'id': '', 'ticketId': ''}),

    op('get_tickets_by_board', 'Get Tickets by Board',
       'Runs a ticketing board and returns the tickets it matches -- the way to list tickets, '
       'since NinjaOne has no flat ticket search.',
       'investigation',
       [field('board_id', 'Board ID', 'integer', True, 'Numeric board identifier.'),
        field('search', 'Search Criteria', 'text', False, 'Free-text search within the board.'),
        field('filters', 'Filters', 'json', False, 'Board filters, as a JSON array.'),
        field('sort_by', 'Sort By', 'json', False, 'Sort specification, as a JSON array.'),
        field('include_columns', 'Include Columns', 'text', False,
              'Columns to return, comma-separated.'),
        field('last_cursor_id', 'Last Cursor ID', 'integer', False,
              'Cursor from a previous page, to continue paging.'),
        p_max_records()],
       {}),

    # -------------------------------------------------------------- ingestion
    op('fetch_patch_findings', 'Fetch Patch Findings',
       'Pulls pending, failed, and rejected patches across the estate and normalizes OS and '
       'third-party patches into one flat finding shape, so a single playbook mapping covers '
       'both. This is the ingestion entry point.',
       'investigation',
       [field('patch_kind', 'Patch Kind', 'select', False,
              'Which patch sources to pull.', value='Both',
              options=['Both', 'Operating System', 'Third-Party Software']),
        p_device_filter(),
        field('status', 'Status', 'multiselect', False,
              'Filter to these patch statuses.', options=OS_PATCH_STATUSES),
        field('severity', 'OS Severity', 'multiselect', False,
              'Severity filter, applied to operating system patches only.',
              options=PATCH_SEVERITIES),
        field('impact', 'Software Impact', 'multiselect', False,
              'Impact filter, applied to third-party software patches only.',
              options=PATCH_IMPACTS),
        field('product_identifier', 'Product Identifier', 'text', False,
              'Restrict third-party results to a single product.'),
        p_max_records()],
       FINDING_SCHEMA),
]


CONFIGURATION = {
    'fields': [
        field('region', 'Region', 'select', True,
              'NinjaOne instance your tenant lives in. NinjaOne is region-isolated: an API '
              'client created in one region does not exist in any other, and the token '
              'endpoint reports that as "Client app not exist" rather than an authentication '
              'error. Match this to the hostname you log in to.',
              'NinjaOne region. Must match where the API client app was created.',
              value=DEFAULT_REGION, options=sorted(REGION_HOSTS)),
        field('client_id', 'Client ID', 'text', True,
              'Client ID of the API application, from Administration > Apps > API > Client '
              'App IDs. The application platform must be "API Services '
              '(machine-to-machine)".',
              'Client ID of the NinjaOne API application.'),
        field('client_secret', 'Client Secret', 'password', True,
              'Client secret issued with the Client ID. Shown once at creation.',
              'Client secret of the NinjaOne API application.'),
        field('scope', 'Scope', 'text', False,
              'Space-separated OAuth scopes to request. "monitoring" covers reads, '
              '"management" covers writes, and "control" is required for script execution '
              'and reboots. The app must already be granted each scope requested here.',
              'Space-separated OAuth scopes. Must be a subset of what the app is granted.',
              value=DEFAULT_SCOPE),
        field('server_url', 'Custom Server URL', 'text', False,
              'Overrides the Region above. Only needed for a non-standard endpoint; leave '
              'blank otherwise.',
              'Overrides Region. Leave blank unless pointed at a non-standard endpoint.',
              placeholder='https://app.ninjarmm.com'),
        field('verify_ssl', 'Verify SSL', 'checkbox', False,
              'Verify the TLS certificate of the NinjaOne endpoint.',
              value=True),
    ]
}

INGESTION_CONFIG_SCHEMA = [
    field('patch_kind', 'Patch Kind', 'select', False,
          'Which patch sources to ingest.', value='Both',
          options=['Both', 'Operating System', 'Third-Party Software']),
    p_device_filter(),
    field('status', 'Status', 'multiselect', False,
          'Restrict to these patch statuses. Leave blank for all pending, failed, and '
          'rejected patches.', options=OS_PATCH_STATUSES),
    field('severity', 'OS Severity', 'multiselect', False,
          'Severity filter, applied to operating system patches only.',
          options=PATCH_SEVERITIES),
    field('impact', 'Software Impact', 'multiselect', False,
          'Impact filter, applied to third-party software patches only.',
          options=PATCH_IMPACTS),
    field('max_records', 'Maximum Records per Pull', 'integer', False,
          'Hard stop on findings per run, per patch kind.', value=500),
]

INFO = {
    'name': 'ninjaone',
    'label': 'NinjaOne',
    'description': (
        'NinjaOne (formerly NinjaRMM) is a unified endpoint management, patching, and '
        'ticketing platform. This connector inventories devices and installed software, '
        'reads and applies operating system and third-party patches, runs automation '
        'scripts, controls Windows services, reboots and schedules maintenance on '
        'endpoints, manages alerts and tickets, and ingests pending patches as findings so '
        'playbooks can drive remediation end to end.'),
    'publisher': 'Community',
    'cs_approved': False,
    'cs_compatible': True,
    'version': CONNECTOR_VERSION,
    'category': 'Endpoint Management',
    'icon_small_name': 'small_icon.png',
    'icon_large_name': 'large_icon.png',
    'vendor_version': 'Public API 2.0',
    'help_online': 'https://app.ninjarmm.com/apidocs/',
    'ingestion_supported': True,
    'ingestion_modes': ['scheduled'],
    'tags': ['RMM', 'Endpoint', 'Patching', 'Vulnerability Management'],
    'ingestion_config_schema': INGESTION_CONFIG_SCHEMA,
    'configuration': CONFIGURATION,
    'operations': OPERATIONS,
}


def render():
    return json.dumps(INFO, indent=2, ensure_ascii=False) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true',
                        help='exit non-zero if info.json is out of date')
    args = parser.parse_args()

    rendered = render()
    if args.check:
        current = open(INFO_PATH, encoding='utf-8').read() if os.path.exists(INFO_PATH) else ''
        if current != rendered:
            print('info.json is out of date; run: python3 tools/build_info_json.py')
            return 1
        print('info.json is up to date')
        return 0

    with open(INFO_PATH, 'w', encoding='utf-8') as handle:
        handle.write(rendered)
    print(f'wrote {INFO_PATH} ({len(OPERATIONS)} operations)')
    return 0


if __name__ == '__main__':
    sys.exit(main())

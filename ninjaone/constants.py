"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

CONNECTOR_NAME = 'ninjaone'
CONNECTOR_VERSION = '1.0.0'

# NinjaOne runs one isolated instance per region. A client app minted in one
# region does not exist in any other -- the token endpoint answers
# "Client app not exist" rather than an auth error, which reads like a bad
# secret and sends you looking in the wrong place. Picking the region is
# therefore the first thing the configuration asks for.
REGION_HOSTS = {
    'North America (app.ninjarmm.com)': 'https://app.ninjarmm.com',
    'North America 2 (us2.ninjarmm.com)': 'https://us2.ninjarmm.com',
    'Europe (eu.ninjarmm.com)': 'https://eu.ninjarmm.com',
    'Canada (ca.ninjarmm.com)': 'https://ca.ninjarmm.com',
    'Oceania (oc.ninjarmm.com)': 'https://oc.ninjarmm.com',
}
DEFAULT_REGION = 'North America (app.ninjarmm.com)'

# Both '/v2' and '/api/v2' are served. '/v2' is what the OpenAPI document uses.
API_PATH = '/v2'
TOKEN_PATH = '/ws/oauth/token'

DEFAULT_SCOPE = 'monitoring management control'

# Refresh a little before the server-stated expiry so a long operation does not
# die on a token that lapsed between the freshness check and the call.
TOKEN_EXPIRY_SKEW_SECONDS = 120

# /v2/devices and /v2/organizations page on a "last id seen" cursor (`after`),
# while every /v2/queries/* report pages on an opaque cursor object. They are
# not interchangeable, and the report endpoints return the cursor nested under
# `cursor.name` rather than at the top level.
MAX_PAGE_SIZE = 1000
DEFAULT_PAGE_SIZE = 200

# Ceiling on pages a single paginating operation will walk. A device filter that
# matches a whole estate can otherwise run until the playbook step times out,
# which surfaces as a dead step rather than as "too much data".
MAX_PAGES = 100

REBOOT_MODES = ['NORMAL', 'FORCED']
SERVICE_ACTIONS = ['START', 'PAUSE', 'STOP', 'RESTART']
SERVICE_STATES = ['UNKNOWN', 'STOPPED', 'START_PENDING', 'RUNNING', 'STOP_PENDING',
                  'PAUSE_PENDING', 'PAUSED', 'CONTINUE_PENDING']
ACTIVITY_CLASSES = ['ALL', 'SYSTEM', 'DEVICE', 'USER']
TICKET_TYPES = ['PROBLEM', 'QUESTION', 'INCIDENT', 'TASK', 'CHANGE_REQUEST',
                'SERVICE_REQUEST', 'PROJECT', 'APPOINTMENT', 'MISCELLANEOUS']
TICKET_SEVERITIES = ['NONE', 'MINOR', 'MODERATE', 'MAJOR', 'CRITICAL']
TICKET_PRIORITIES = ['NONE', 'LOW', 'MEDIUM', 'HIGH']

# Patch status vocabularies, as the report endpoints use them.
OS_PATCH_STATUSES = ['MANUAL', 'APPROVED', 'FAILED', 'REJECTED']
SOFTWARE_PATCH_STATUSES = ['MANUAL', 'APPROVED', 'FAILED', 'REJECTED']
INSTALL_STATUSES = ['INSTALLED', 'FAILED']
PATCH_SEVERITIES = ['UNKNOWN', 'LOW', 'MODERATE', 'IMPORTANT', 'CRITICAL', 'OPTIONAL']
PATCH_TYPES = ['UNKNOWN', 'PATCH', 'INSTALLER']
PATCH_IMPACTS = ['UNKNOWN', 'OPTIONAL', 'RECOMMENDED', 'CRITICAL']

ERROR_MESSAGES = {
    400: 'Bad Request: the parameters sent to NinjaOne are invalid.',
    401: 'Unauthorized: the access token is missing, expired, or revoked.',
    # Deliberately does NOT name a cause. A 403 here is just as often a feature
    # the tenant has not licensed (ticketing) as a missing scope, and asserting
    # "you lack the scope" over the top of NinjaOne's own "Ninja Ticketing
    # Integration is not enabled" sends the reader to the wrong place entirely.
    # SCOPE_HINT below is appended only when the body explains nothing.
    403: 'Forbidden.',
    404: 'Not Found: the requested device, organization, or record does not exist.',
    405: 'Method Not Allowed.',
    409: 'Conflict: the record changed since it was read. Re-read it and retry.',
    415: 'Unsupported Media Type.',
    422: 'Unprocessable Entity: NinjaOne rejected the request body.',
    429: 'Rate limit exceeded. Slow the schedule down and retry after the reset window.',
    500: 'Internal Server Error at NinjaOne.',
    502: 'Bad Gateway.',
    503: 'Service Unavailable at NinjaOne.',
    504: 'Gateway Timeout.',
    'time_out': 'The request timed out while trying to connect to NinjaOne.',
    'ssl_error': 'SSL certificate validation failed.',
}

# Appended to a 403 only when NinjaOne's body gives no reason of its own.
SCOPE_HINT = (' The client app may lack the scope this operation needs: reads need '
              '"monitoring", writes need "management", and script execution and reboots '
              'need "control". A 403 can also mean the tenant has not licensed the '
              'feature -- ticketing is the common one.')

# The token endpoint answers these two very differently, and telling them apart
# is the whole diagnosis when a configuration will not authenticate.
TOKEN_ERROR_HINTS = {
    'Client app not exist':
        'NinjaOne does not know this Client ID in the selected region. NinjaOne is '
        'region-isolated, so check the Region field matches the instance the API '
        'client app was created in.',
    'unauthorized_client':
        'The Client ID exists in this region but is not permitted to use the '
        'client_credentials grant. In NinjaOne go to Administration > Apps > API > '
        'Client App IDs, and confirm the app\'s platform is "API Services '
        '(machine-to-machine)" and that Client Credentials is an allowed grant type.',
    'invalid_client':
        'The Client Secret is wrong, or the app was deleted.',
    'invalid_scope':
        'The app is not authorized for one of the requested scopes. Reduce the Scope '
        'field to only what the app is granted.',
}

# Agent installer flavours. Fabric Studio's LXC base is Rocky 9, so LINUX_RPM;
# the Windows guests take WINDOWS_MSI.
INSTALLER_TYPES = [
    'WINDOWS_MSI', 'WINDOWS_ARM64_MSI',
    'MAC_DMG', 'MAC_PKG',
    'LINUX_DEB', 'LINUX_RPM',
    'LINUX_ARM64_DEB', 'LINUX_ARMV7A_DEB',
    'LINUX_ARM64_RPM', 'LINUX_ARMV7A_RPM',
]

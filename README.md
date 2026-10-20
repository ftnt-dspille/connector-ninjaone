# FortiSOAR NinjaOne connector

Endpoint inventory, OS and third-party patching, script execution, alerts, and
ticketing over the [NinjaOne Public API v2](https://app.ninjarmm.com/apidocs/).

NinjaOne (formerly NinjaRMM) is a unified endpoint management platform. This
connector is aimed squarely at the remediation half of a vulnerability workflow:
find which endpoints run a vulnerable product, apply the patch, and prove it
landed.

- **56 operations** across devices, inventory, patching, control, alerts,
  organizations, and ticketing
- **Scheduled ingestion** of pending patches as normalized findings
- No third-party client library -- the API client is ~200 lines of `requests`

## Installation

Package the `ninjaone/` directory as a `.tgz` and import it through **Content
Hub > Manage > Import**. The tarball must contain exactly one top-level
directory, and that directory must be named `ninjaone` to match `info.json`'s
`name`.

Because `cs_approved` is `false`, the appliance needs its custom-connector gate
enabled first:

```python
client.system_settings.set_development_mode(connectors=True)
```

## Configuration

| Field | Required | Notes |
|---|---|---|
| Region | yes | Which NinjaOne instance your tenant lives in |
| Client ID | yes | From **Administration > Apps > API > Client App IDs** |
| Client Secret | yes | Shown once, at creation |
| Scope | no | Defaults to `monitoring management control` |
| Custom Server URL | no | Overrides Region; leave blank normally |
| Verify SSL | no | Defaults to on |

Create the API client with **Application Platform = API Services
(machine-to-machine)** and **Client Credentials** as an allowed grant type.
Grant it the scopes you intend to use: `monitoring` for reads, `management` for
writes, `control` for script execution and reboots.

### Two authentication failures worth recognising

NinjaOne's token endpoint reports these very differently, and neither remedy is
guessable from the message. The connector appends the explanation to the error.

| Response | What it actually means |
|---|---|
| `{"resultCode": "Client app not exist"}` | **Wrong region.** NinjaOne is region-isolated: an API client created in `ca` does not exist in `app`. The client ID is fine. |
| `{"error": "unauthorized_client"}` | **Right region, wrong grant.** The app exists but is not permitted to use `client_credentials` -- usually because it was created as a Web / Authorization Code app. |

Omitting the scope entirely returns `invalid_scope`, so a scope is always sent.

## Operations

**Devices** -- Get Devices, Get Devices (Detailed), Search Devices, Get Device
Details, Update Device, Get/Update Device Custom Fields, Get Device Dashboard URL

**Inventory** -- Software, Disks, Volumes (with BitLocker), Processors, Network
Interfaces, Windows Services, Last Logged-On User, plus estate-wide Software
Inventory and Device Health reports

**Patching** -- pending and installed OS patches, pending and installed software
patches, both per-device and estate-wide; Scan/Apply OS Patches; Scan/Apply
Software Patches

**Control** -- Run Script, Get Automation Scripts, Get Device Scripting Options,
Reboot Device, Control Windows Service, Schedule/Cancel Maintenance, Get Active
Jobs, Get Device Jobs

**Alerts & activities** -- Get Alerts, Get Device Alerts, Reset Alert, Get
Activities, Get Device Activities

**Organizations** -- Get Organizations, Get Organization, Get Organization
Devices, Get Organization Locations, Get Groups, Get Group Devices, Get Policies,
Get Software Products

**Ticketing** -- Create Ticket, Get Ticket, Update Ticket, Add Ticket Comment,
Get Tickets by Board

**Ingestion** -- Fetch Patch Findings

### Things the API does that the operations paper over

- **Patch scan and apply return `204` with no job identifier.** There is nothing
  to poll by handle, so these operations report `Submitted` rather than
  pretending otherwise. Confirm with **Get Device Jobs** or by re-reading the
  pending patch list.
- **Update Ticket is a full replace, not a merge.** `version`, `clientId`,
  `ticketFormId`, `subject`, `status` and `requesterUid` are mandatory on every
  call, so sending only the field you changed would blank the rest. The
  operation reads the ticket first and layers your changes on top.
- **Add Ticket Comment is `multipart/form-data`** even with no attachment; a
  plain JSON body returns `415`.
- **Two incompatible pagination schemes.** `/devices` and `/organizations` page
  on `after` (the last id seen); every `/queries/*` report pages on an opaque
  cursor nested under `cursor.name`. Mixing them silently re-reads page one.
- **`Run Script` does not work with a client-credentials token.** NinjaOne
  answers `403 Access key does not have user context which is required for this
  request`: it attributes a script run to a person, and a machine-to-machine app
  has none. No scope lifts this -- it needs an authorization-code token. Note
  that **Reboot Device** and **Control Windows Service** look like the same
  class of operation and are *not* restricted; both are live-verified working on
  the very same token.
- **Patch scan/apply need patching enabled in the device's POLICY first.**
  Otherwise they fail `400 OS patching is not enabled. Process can not start.`
  (and the same for software patching). This is a tenant policy setting, not a
  permission or a connector fault, and the public API has **no** endpoint for
  it -- `/v2/policies` covers conditions and org mappings only. Enable it in the
  console under **Administration > Policies > <the device's policy> > Patching**.
- **`Search Devices` is how you get a device ID.** Every device operation takes
  the numeric NinjaOne ID, not a hostname; passing a hostname raises an error
  that says so.

## Ingestion

**Fetch Patch Findings** pulls pending, failed, and rejected patches across the
estate and flattens the OS and third-party patch reports -- which do not share a
schema -- into one finding shape, so a single playbook mapping covers both:

```
source_id, patch_kind, device_id, patch_id, kb_number, cve_ids, name,
product, version, status, severity, type, impact, installed_at, timestamp, raw
```

`source_id` is `<kind>:<device_id>:<patch>`, stable across runs. Use it as the
dedup field, or every run creates duplicate records instead of updating.

## Sample playbooks

The connector ships a **NinjaOne** collection with five playbooks, all built from
operations that are live-verified working (see `COVERAGE.md`):

| Playbook | What it does |
|---|---|
| **Enrich Asset** | Resolves a hostname, IP, or user to a device and returns its identity, owner, and a console deep link. Every other flow needs the numeric device ID this produces. |
| **Find Exposed Endpoints** | Given a product name from an advisory, answers "does this exist here, and where is it unpatched?" from the estate-wide reports -- no per-device iteration. |
| **Patch Endpoint with Approval** | Shows what is pending, asks an analyst, then scans and applies, and confirms via install history rather than trusting the API response. |
| **Reboot Endpoint with Approval** | Suppresses monitoring first so the reboot does not page the SOC, reboots, confirms the endpoint returned, then lifts the window. |
| **Restart Windows Service** | Restarts a named service and verifies it came back running -- the usual answer to a "service stopped" alert. |

Nothing here calls `Run Script`: it cannot work on a client-credentials token
(see above), so a sample built on it would fail for everyone who imported it.

`ninjaone/playbooks/playbooks.json` is a **build artifact**. Author
`playbooks/ninjaone.yaml` and regenerate:

```bash
./tools/build_playbooks.sh          # needs the fsrpb compiler; FSRPB_HOME to override
```

The build provisions this connector into the compiler's catalog first, so a
mistyped operation or parameter fails at compile time rather than in a live run.

## Deploying a change

Two things bit hard enough to be worth writing down:

- **Reinstalling the same version does NOT reload the Python.** `install_from_file(replace=True)`
  reports success, the operation list updates, and `operations.py` keeps running
  the *old* code -- a new filter silently does nothing while the same call works
  perfectly off-box. Call `connectors.republish("ninjaone")` after an in-place
  reinstall, or bump the version.
- **Validate playbook Jinja against the live renderer, not a linter.**
  `pyfsr.jinja_validate` reports this collection clean because it checks filter
  *names*; the bug that actually broke a run was an invalid *test*
  (`selectattr(..., 'search', ...)`, an Ansible-ism FortiSOAR does not have).
  `tools/validate_playbook_jinja.py` renders all 52 expressions through
  `POST /api/wf/api/jinja-editor/` and catches it -- along with expressions that
  parse but raise on real data, such as `json_query`'s `contains()` on a row
  whose field is null.

## Development

```bash
python3 -m pytest -q                  # 66 offline tests, no network
python3 -m pytest -m live -q          # 10 read-only tests against a real tenant
python3 tools/live_check.py           # drive every read operation, print a summary
python3 tools/live_check.py --device 42
python3 tools/build_info_json.py      # regenerate info.json
python3 tools/build_info_json.py --check
python3 tools/make_icons.py           # regenerate the icons
python3 tools/live_matrix.py --device 1              # coverage matrix + fixtures
python3 tools/live_matrix.py --device 1 --disruptive # includes reboot/service/script
python3 tools/live_matrix.py --resanitize            # rebuild fixtures from .cache/live
./tools/build_playbooks.sh                           # compile the playbook collection
```

`info.json` is generated. Edit `tools/build_info_json.py`, not the JSON -- 56
operations of hand-maintained manifest drift, and the enums there come straight
from `ninjaone/constants.py` so the manifest and the runtime cannot disagree.

Live credentials go in `.env.ninjaone` (gitignored); copy
`.env.ninjaone.example`. The live tests and `live_check.py` are read-only --
nothing in the repo reboots a machine or applies a patch on its own.

## Layout

```
ninjaone/            the FortiSOAR package (this is what gets tarred)
  connector.py       Connector subclass: execute() + check_health()
  operations.py      API client, pagination, and all 56 operations
  constants.py       regions, enums, error messages
  info.json          generated manifest
  images/            generated icons
  playbooks/         generated playbook collection
playbooks/           playbook SOURCE (YAML, compiled into the package)
tests/               offline suite, opt-in live suite, sanitized fixtures
tools/               info.json builder, icon builder, live check, coverage matrix
COVERAGE.md          which operations are actually verified, and why the rest are not
```

## Status

Verified against a live NinjaOne tenant with a real enrolled Windows endpoint:
authentication, region resolution, token caching, both pagination schemes, the
health check, installer generation, and **all 32 read operations** including
every device-scoped one (`tools/live_check.py --device 1`: 32 passed, 0 failed).

Inventory reads return real data from the enrolled endpoint: 58 software
products, 241 Windows services, 4 processors, 1 disk, 1 volume, 10 NICs.

Not yet verified:

- patch scan/apply -- reachable and correctly authenticated, but the tenant
  policy has patching disabled, so they return `400 ... patching is not
  enabled`. Enable it in the console (see above) to exercise them.
- the other state-changing operations -- run script, reboot, service control,
  maintenance, alert reset
- all ticketing operations, because the tenant answers `403 Ninja Ticketing
  Integration is not enabled`; the add-on is not licensed on a trial

### Enrolling a test endpoint

`Generate Agent Installer` returns a pre-tokenized MSI/RPM URL, so enrollment is
two commands on the guest with nothing typed by hand:

```powershell
curl.exe -sSL -o "$env:TEMP\NinjaOne-Agent.msi" "<url from generate_installer>"
Start-Process msiexec.exe -ArgumentList '/i',"$env:TEMP\NinjaOne-Agent.msi",'/qn','/norestart' -Wait
Get-Service NinjaRMMAgent      # Running
```

The device appears in **Get Devices** within about a minute and reports
`offline: false` shortly after. Hardware and software inventory arrive on the
agent's first full check-in, which is later -- so an inventory read taken
immediately after install correctly returns an empty list rather than an error.
Patch data only exists once a scan has run.

## License

MIT

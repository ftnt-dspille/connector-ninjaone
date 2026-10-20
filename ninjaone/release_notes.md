### 1.0.0

Initial release.

**Added**

- OAuth 2.0 client-credentials authentication with token caching, a region
  selector covering all five NinjaOne instances (app, us2, eu, ca, oc), and an
  optional custom server URL.
- 56 operations across devices, hardware and software inventory, operating
  system and third-party patching, script execution, Windows service control,
  reboot and maintenance, alerts, activities, organizations, and ticketing.
- Scheduled ingestion of pending, failed, and rejected patches as normalized
  findings, merging the operating system and third-party patch reports into one
  shape so a single playbook mapping covers both.
- A sample **NinjaOne** playbook collection: asset enrichment, product exposure
  hunting, gated patch remediation, gated reboot, and Windows service restart.

**Known limitations**

- Ticketing operations require the Ninja Ticketing add-on. On a tenant without
  it, every ticketing endpoint answers `403 Ninja Ticketing Integration is not
  enabled`; the connector surfaces that message verbatim.
- Patch scan and apply return `204` with no job identifier, so they cannot be
  correlated to a specific job. Poll **Get Device Jobs**, or re-read the pending
  patch list, to confirm completion.
- `Run Script` cannot be used with a client-credentials configuration: NinjaOne
  requires a user-context token for script execution. Reboot and Windows service
  control are not affected.
- Patch scan and apply require patching to be enabled in the policy the device
  inherits; the public API cannot enable it.

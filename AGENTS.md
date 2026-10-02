# Cloud VPN connection test

This project verifies whether a Codex Cloud executor can authenticate to a user-specified VPN and reach the user-specified HTTP command services.

Run `python3 probe.py` for preflight observations. The probe deliberately does not log into the VPN. Report these observations separately from an actual VPN authentication result.

Use `HNC_VPN_PASSWORD` only for VPN authentication, and `HNC_HTTP_PASSWORD` only for the HTTP command services. Supply them as personal environment values. Never print them, include them in process arguments, commit them, or save authentication headers, cookies, or client diagnostic logs containing credentials.

Gateway addresses, accounts, certificate fingerprints, target URLs, expected hosts and project paths are supplied in the private Cloud task or environment configuration. Keep organization-specific connection data out of this public repository. Reports are ignored by Git and remain in the private task.

Before authenticating, identify a genuinely compatible VPN client and validate the gateway certificate with a trusted company CA or the documented certificate pin. An OpenConnect installation alone does not establish Huawei gateway compatibility.

Perform one authentication attempt. Stop if it is rejected. If establishing a tunnel requires unsupported runtime capabilities, record the actual error and runtime evidence.

Once connected, verify `/health` on each target and compare the returned host and user to the requested target. Read-only identity checks are sufficient for this task. Do not launch EDA applications, modify business project files, restart existing server services, or change the user's laptop VPN.

Clean up only VPN processes and connections created by this test. Keep any pre-existing clients or VPN sessions intact.

Verify code changes with `python3 -m unittest -v test_probe.py`.

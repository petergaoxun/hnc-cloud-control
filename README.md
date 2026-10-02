# Codex Cloud VPN test

Generic, read-only diagnostics for testing a real Cloud executor's VPN connectivity and HTTP service identity. Gateway addresses, accounts, certificate fingerprints and credentials are supplied in the private task or environment settings, not in this repository.

## Cloud setup

Select this repository when creating a Codex Cloud environment. Python 3 and its standard library are sufficient for the probe. Complete setup and publish the environment. Allow the user-specified gateway destination in the environment's network settings.

An allowed destination does not establish a VPN tunnel. This project does not contain a VPN implementation; a compatible client must be identified and tested in the actual runtime.

## Credentials

Supply direct personal environment values through the Codex Cloud personal vault or setup flow:

| Key | Meaning |
|---|---|
| `HNC_VPN_PASSWORD` | Password used by the VPN client |
| `HNC_HTTP_PASSWORD` | Separate HTTP command-service password |
| `HNC_HTTP_USER` | HTTP service username, or pass `--expected-user` |

A VPN client needs the actual VPN credential. A network-secret placeholder substituted only on HTTPS port 443 may not work for a client connecting on another port.

## Preflight

Run the probe inside the actual Cloud task, substituting the private task's connection values:

```bash
python3 probe.py --origin codex-cloud --gateway "$VPN_GATEWAY" --port "$VPN_PORT" --cert-sha256 "$VPN_CERT_SHA256" --targets "$SERVICE_URL_A" "$SERVICE_URL_B" --output report-preflight.json
```

Use a certificate pin obtained through a trusted source. With no pin supplied, the probe uses the system CA store and hostname verification. A certificate mismatch stops the TLS probe; no VPN credentials are sent by this script.

The report records runtime capabilities, proxy presence, available clients, direct gateway TCP/TLS reachability, an HTTPS gateway request using configured proxy settings, and target TCP/HTTP reachability. Both gateway and service HTTP probes respect the configured cloud proxy. A missing TUN device or capability is evidence to investigate, not proof that all possible clients are unsupported.

The script does not authenticate a VPN. A public gateway response or an HTTP 401 is not evidence of a successful VPN login. `--origin` records the caller's declared execution location; it does not attest to that location, so retain the actual Cloud task ID alongside the report.

## Authentication and acceptance

Identify a client genuinely compatible with the requested gateway. For Huawei gateways, Linux SecoClient or UniVPN is a candidate requiring compatibility and runtime checks. Do not assume every SSL VPN supports the OpenConnect protocol.

Make one authentication attempt with the supplied VPN credential. If successful, run the probe again with `--authenticated-health`, `--expected-hosts "$HOST_A" "$HOST_B"`, and `--expected-user "$SERVICE_USER"`.

Acceptance requires authenticated `/health` responses with the expected service, host and user. Record VPN authentication and internal service access as distinct results. Clean up only this test's own connections and processes.

If the custom client cannot run in the runtime, retain the concrete limitation. Codex Cloud's documented built-in private-network provider is Tailscale, which requires a separately configured route to the target network.

## Verification

```bash
python3 -m unittest -v test_probe.py
```

Checks cover certificate substitution rejection on both direct and proxy-capable HTTPS transports, malformed pins, credential redaction, missing credentials, embedded-password URLs, and wrong host/user identities. Local checks validate this diagnostic script, not a Cloud VPN connection.

## References

- [Official Cloud environment setup and private networking](https://learn.chatgpt.com/docs/environments/cloud-environments)
- [Huawei VPN client package documentation](https://info.support.huawei.com/hedex/api/pages/EDOC1100149311/AZJ0713J/17/resources/admin/sec_admin_vpnupdate_0006.html)
- [Example source for a headless UniVPN integration](https://github.com/jesusdf/huawei-vpn): third-party source to inspect, not proof that this runtime or gateway is compatible.

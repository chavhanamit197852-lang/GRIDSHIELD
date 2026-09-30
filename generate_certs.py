from pathlib import Path
from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE = Path(__file__).resolve().parent
CERT_DIR = BASE / "certs"
CERT_DIR.mkdir(exist_ok=True)


def save_private_key(path, key):
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def save_certificate(path, cert):
    path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )


# ============================================================
# 1. CREATE ROOT CA
# ============================================================

ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GridShield"),
    x509.NameAttribute(NameOID.COMMON_NAME, "GridShield Root CA"),
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    )
    .add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=None,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)

save_private_key(CERT_DIR / "ca.key", ca_key)
save_certificate(CERT_DIR / "ca.crt", ca_cert)


# ============================================================
# 2. CREATE MQTT SERVER KEY
# ============================================================

server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

server_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GridShield"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])


# ============================================================
# 3. CREATE MQTT SERVER CERTIFICATE
# ============================================================

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_cert.subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(
                ipaddress.ip_address("127.0.0.1")
            ),
        ]),
        critical=False,
    )
    .add_extension(
        x509.BasicConstraints(
            ca=False,
            path_length=None,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)

save_private_key(CERT_DIR / "server.key", server_key)
save_certificate(CERT_DIR / "server.crt", server_cert)


print()
print("========================================")
print(" GridShield TLS certificates generated")
print("========================================")
print()
print(f"Certificate directory: {CERT_DIR}")
print()
print("Created:")
print("  ca.crt")
print("  ca.key")
print("  server.crt")
print("  server.key")
print()
print("TLS certificate generation complete.")
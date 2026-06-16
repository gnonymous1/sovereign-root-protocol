#!/usr/bin/env python3
"""
=============================================================================
  SOVEREIGN ROOT PROTOCOL (SRP) — mTLS CERTIFICATE GENERATOR
=============================================================================
  System Authority : Universal Root Authority
  Version          : 2026.4.2-Production

  Generates a self-signed CA and per-node mTLS certificates for the SRP
  cluster mesh.  All certificates use ECDSA P-256 (default) or RSA 4096
  (with --rsa) and are valid for 10 years.

  Output layout (cluster/certs/):

      ca.crt                  CA certificate (PEM)
      ca.key                  CA private key (PEM)
      node-us-east-01.crt     Node certificate (PEM)
      node-us-east-01.key     Node private key (PEM)
      node-eu-west-01.crt     ...
      node-eu-west-01.key
      node-ap-southeast-01.crt
      node-ap-southeast-01.key
      local.crt               Local self-reference certificate (PEM)
      local.key               Local self-reference private key (PEM)
      certs.md5               Checksum manifest

  On success, cluster_nodes.json is updated with relative paths pointing
  into cluster/certs/.

  Usage:
      python cluster/generate_certs.py                          # ECDSA P-256
      python cluster/generate_certs.py --rsa                     # RSA 4096
      python cluster/generate_certs.py --output-dir /etc/srp/certs  # custom dir
      python cluster/generate_certs.py --openssl                 # use openssl CLI
=============================================================================
"""

import os
import sys
import json
import hashlib
import ipaddress
import argparse
import subprocess
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
import ipaddress
NODE_IDS = [
    "srp-node-us-east-01",
    "srp-node-eu-west-01",
    "srp-node-ap-southeast-01",
]
LOCAL_ID = "srp-node-local"

CA_CN = "SRP Cluster Root CA"
CA_DAYS = 3650  # ~10 years
NODE_DAYS = 3650
RSA_KEY_SIZE = 4096
EC_CURVE = "secp256r1"

OUTPUT_REL = "certs"  # relative to script dir
CONFIG_REL = "cluster_nodes.json"

logger = None  # set by main


def log(msg: str):
    print(f"  [CERT] {msg}")


# ============================================================================
#  OpenSSL-based generation (subprocess)
# ============================================================================

def _run_openssl(args: list[str], desc: str):
    log(f"  running: openssl {' '.join(str(a) for a in args[:4])} ...")
    result = subprocess.run(
        ["openssl"] + args,
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log(f"OpenSSL error during {desc}: {result.stderr.strip()}")
        sys.exit(1)
    return result


def generate_via_openssl(output_dir: Path, use_rsa: bool):
    """Generate all certificates using the openssl CLI."""
    log("Using OpenSSL CLI for certificate generation...")

    # --- CA ---
    ca_key = output_dir / "ca.key"
    ca_cert = output_dir / "ca.crt"
    ca_ext = output_dir / "_ca_ext.cnf"

    key_type = "ec" if not use_rsa else "rsa"
    key_params = ["-pkeyopt", f"ec_paramgen_curve:{EC_CURVE}"] if not use_rsa else []
    genpkey_args = ["genpkey", "-algorithm", key_type.upper()] + key_params + \
                   ["-out", str(ca_key)]
    _run_openssl(genpkey_args, f"CA private key ({key_type})")

    # CA config for extensions
    with open(ca_ext, "w") as f:
        f.write(f"""[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
CN = {CA_CN}

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
""")
    _run_openssl([
        "req", "-x509", "-new",
        "-key", str(ca_key),
        "-out", str(ca_cert),
        "-days", str(CA_DAYS),
        "-config", str(ca_ext),
        "-extensions", "v3_ca",
    ], "CA certificate")

    # --- Per-node certs ---
    for node_id in NODE_IDS + [LOCAL_ID]:
        short_name = node_id.replace("srp-node-", "")
        node_key = output_dir / f"{short_name}.key"
        node_csr = output_dir / f"{short_name}.csr"
        node_cert = output_dir / f"{short_name}.crt"
        node_ext = output_dir / f"_{short_name}_ext.cnf"

        _run_openssl(
            genpkey_args + ["-out", str(node_key)],
            f"node key {short_name} ({key_type})",
        )

        with open(node_ext, "w") as f:
            f.write(f"""[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = {node_id}

[v3_req]
subjectAltName = DNS:{node_id}, DNS:localhost, IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
""")

        _run_openssl([
            "req", "-new",
            "-key", str(node_key),
            "-out", str(node_csr),
            "-config", str(node_ext),
            "-extensions", "v3_req",
        ], f"CSR for {short_name}")

        _run_openssl([
            "x509", "-req",
            "-in", str(node_csr),
            "-CA", str(ca_cert),
            "-CAkey", str(ca_key),
            "-CAcreateserial",
            "-out", str(node_cert),
            "-days", str(NODE_DAYS),
            "-extfile", str(node_ext),
            "-extensions", "v3_req",
        ], f"cert for {short_name}")

        node_csr.unlink(missing_ok=True)
        node_ext.unlink(missing_ok=True)

    ca_ext.unlink(missing_ok=True)
    serial = output_dir / "ca.srl"
    serial.unlink(missing_ok=True)

    log("OpenSSL generation complete.")


# ============================================================================
#  Pure-Python cryptography-based generation
# ============================================================================

def _py_gen_key(use_rsa: bool):
    """Generate a private key using the cryptography library."""
    if use_rsa:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
        )
    else:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePrivateKey, SECP256R1,
        )
        key = ec.generate_private_key(SECP256R1())
    return key


def _py_csr(key, cn: str, use_rsa: bool):
    """Generate a CSR for the given key."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            key_agreement=False,
            content_commitment=False,
            data_encipherment=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    )

    hash_algo = hashes.SHA256()
    csr = builder.sign(key, hash_algo)
    return csr


def generate_via_cryptography(output_dir: Path, use_rsa: bool):
    """Generate all certificates using the cryptography library (pure Python)."""
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

    log("Using cryptography library for certificate generation...")
    hash_algo = hashes.SHA256()

    # --- Root CA ---
    log("  generating CA key...")
    ca_key = _py_gen_key(use_rsa)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)])

    ca_cert_builder = x509.CertificateBuilder()
    ca_cert_builder = ca_cert_builder.subject_name(ca_subject)
    ca_cert_builder = ca_cert_builder.issuer_name(ca_subject)
    ca_cert_builder = ca_cert_builder.public_key(ca_key.public_key())
    ca_cert_builder = ca_cert_builder.serial_number(x509.random_serial_number())
    ca_cert_builder = ca_cert_builder.not_valid_before(datetime.now(timezone.utc))
    ca_cert_builder = ca_cert_builder.not_valid_after(
        datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 10)
    )
    ca_cert_builder = ca_cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    )
    ca_cert_builder = ca_cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False, key_encipherment=False,
            key_cert_sign=True, key_agreement=False,
            content_commitment=False, data_encipherment=False,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    ca_cert_builder = ca_cert_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
        critical=False,
    )

    ca_cert = ca_cert_builder.sign(ca_key, hash_algo)

    with open(output_dir / "ca.key", "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(output_dir / "ca.crt", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    log(f"  CA: {output_dir / 'ca.crt'}")

    # --- Per-node certs ---
    for node_id in NODE_IDS + [LOCAL_ID]:
        short_name = node_id.replace("srp-node-", "")
        log(f"  generating cert for {short_name}...")

        node_key = _py_gen_key(use_rsa)
        csr = _py_csr(node_key, node_id, use_rsa)

        node_cert_builder = x509.CertificateBuilder()
        node_cert_builder = node_cert_builder.subject_name(csr.subject)
        node_cert_builder = node_cert_builder.issuer_name(ca_subject)
        node_cert_builder = node_cert_builder.public_key(csr.public_key())
        node_cert_builder = node_cert_builder.serial_number(x509.random_serial_number())
        node_cert_builder = node_cert_builder.not_valid_before(
            datetime.now(timezone.utc))
        node_cert_builder = node_cert_builder.not_valid_after(
            datetime.now(timezone.utc).replace(
                year=datetime.now(timezone.utc).year + 10)
        )

        # Copy extensions from CSR
        for ext in csr.extensions:
            node_cert_builder = node_cert_builder.add_extension(
                ext.value, critical=ext.critical,
            )

        # Add Authority Key Identifier
        node_cert_builder = node_cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )

        node_cert = node_cert_builder.sign(ca_key, hash_algo)

        with open(output_dir / f"{short_name}.key", "wb") as f:
            f.write(node_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(output_dir / f"{short_name}.crt", "wb") as f:
            f.write(node_cert.public_bytes(serialization.Encoding.PEM))

        log(f"  cert: {output_dir / f'{short_name}.crt'}")

    log("Cryptography library generation complete.")


# ============================================================================
#  Checksum manifest
# ============================================================================

def write_checksums(output_dir: Path):
    """Write an MD5 manifest for all generated cert files."""
    md5_path = output_dir / "certs.md5"
    hashes = []
    for fname in sorted(output_dir.iterdir()):
        if fname.suffix in (".crt", ".key") and fname.is_file():
            md5 = hashlib.md5(fname.read_bytes()).hexdigest()
            hashes.append(f"{md5}  {fname.name}")
    with open(md5_path, "w") as f:
        f.write("\n".join(hashes) + "\n")
    log(f"Checksum manifest: {md5_path}")


# ============================================================================
#  Update cluster_nodes.json
# ============================================================================

def update_config(output_dir: Path, config_abs_path: Path, relative_base: Path):
    """Rewrite tls_cert/tls_key/tls_ca paths in cluster_nodes.json."""
    if not config_abs_path.exists():
        log(f"Config not found at {config_abs_path}, skipping update.")
        return

    rel = os.path.relpath(output_dir, relative_base).replace("\\", "/")

    with open(config_abs_path, "r") as f:
        config = json.load(f)

    # Determine path strings
    def p(name: str) -> str:
        return f"{rel}/{name}"

    ca_cert = p("ca.crt")

    # Update nodes section
    for node in config.get("nodes", []):
        node_id = node.get("id", "")
        short = node_id.replace("srp-node-", "")
        node["tls_cert"] = p(f"{short}.crt")
        node["tls_key"] = p(f"{short}.key")
        node["tls_ca"] = ca_cert

    # Update self section
    self_sec = config.get("self", {})
    self_sec["tls_cert"] = p("local.crt")
    self_sec["tls_key"] = p("local.key")
    self_sec["tls_ca"] = ca_cert

    # Write back
    with open(config_abs_path, "w") as f:
        json.dump(config, f, indent=4)
        f.write("\n")

    log(f"Updated TLS paths in {config_abs_path}")


# ============================================================================
#  Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SRP mTLS Certificate Generator",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory for certificates (default: cluster/certs/)",
    )
    parser.add_argument(
        "--rsa", action="store_true", default=False,
        help="Use RSA 4096 instead of ECDSA P-256",
    )
    parser.add_argument(
        "--openssl", action="store_true", default=False,
        help="Use openssl CLI instead of cryptography library",
    )
    parser.add_argument(
        "--no-config-update", action="store_true", default=False,
        help="Skip updating cluster_nodes.json paths",
    )
    args = parser.parse_args()

    # Determine script directory
    script_dir = Path(__file__).parent.resolve()
    config_path = script_dir / CONFIG_REL

    # Output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = script_dir / OUTPUT_REL

    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"Certificate output directory: {output_dir}")
    log(f"Algorithm: {'RSA 4096' if args.rsa else 'ECDSA P-256 (secp256r1)'}")

    # Generate
    if args.openssl:
        generate_via_openssl(output_dir, args.rsa)
    else:
        # Try cryptography first, fall back to openssl
        try:
            generate_via_cryptography(output_dir, args.rsa)
        except ImportError as e:
            log(f"cryptography library not available ({e}).")
            log("Falling back to openssl CLI...")
            generate_via_openssl(output_dir, args.rsa)

    write_checksums(output_dir)

    if not args.no_config_update:
        update_config(output_dir, config_path, script_dir)

    log("Done. All certificates generated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

import socket
import ssl
from datetime import datetime
import json
import os

RESULTS_DIR = "results"
TXT_REPORT = os.path.join(RESULTS_DIR, "report.txt")
JSON_REPORT = os.path.join(RESULTS_DIR, "report.json")

os.makedirs(RESULTS_DIR, exist_ok=True)


def get_ssl_certificate(hostname):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

                return cert, tls_version

    except Exception as e:
        print(f"[ERROR] {hostname} -> {e}")
        return None, None


def analyze_certificate(hostname):
    cert, tls_version = get_ssl_certificate(hostname)

    if not cert:
        return None

    issuer = dict(x[0] for x in cert['issuer'])
    subject = dict(x[0] for x in cert['subject'])

    issued_to = subject.get('commonName', 'N/A')
    issued_by = issuer.get('organizationName', 'N/A')

    valid_from = cert['notBefore']
    valid_until = cert['notAfter']

    expiry_date = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
    remaining_days = (expiry_date - datetime.utcnow()).days

    status = "VALID"

    if remaining_days < 0:
        status = "EXPIRED"
    elif remaining_days < 30:
        status = "EXPIRING SOON"

    result = {
        "domain": hostname,
        "issued_to": issued_to,
        "issued_by": issued_by,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "remaining_days": remaining_days,
        "tls_version": tls_version,
        "status": status
    }

    return result


def save_txt(results):
    with open(TXT_REPORT, "w", encoding="utf-8") as file:
        for r in results:
            file.write("=" * 50 + "\n")
            file.write(f"Domain         : {r['domain']}\n")
            file.write(f"Issued To      : {r['issued_to']}\n")
            file.write(f"Issued By      : {r['issued_by']}\n")
            file.write(f"Valid From     : {r['valid_from']}\n")
            file.write(f"Valid Until    : {r['valid_until']}\n")
            file.write(f"Days Remaining : {r['remaining_days']}\n")
            file.write(f"TLS Version    : {r['tls_version']}\n")
            file.write(f"Status         : {r['status']}\n")
            file.write("=" * 50 + "\n\n")


def save_json(results):
    with open(JSON_REPORT, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)


def main():
    try:
        with open("targets.txt", "r") as file:
            domains = [line.strip() for line in file if line.strip()]

    except FileNotFoundError:
        print("[ERROR] targets.txt not found")
        return

    all_results = []

    for domain in domains:
        print(f"\n[+] Scanning {domain} ...")

        result = analyze_certificate(domain)

        if result:
            all_results.append(result)

            print(f"    Issued To      : {result['issued_to']}")
            print(f"    Issued By      : {result['issued_by']}")
            print(f"    Expiry         : {result['valid_until']}")
            print(f"    Remaining Days : {result['remaining_days']}")
            print(f"    TLS Version    : {result['tls_version']}")
            print(f"    Status         : {result['status']}")

    save_txt(all_results)
    save_json(all_results)

    print("\n[+] Reports saved in results/ folder")


if __name__ == "__main__":
    main()
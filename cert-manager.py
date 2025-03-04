#!/opt/homebrew/bin/python3.13

import os
import time
import schedule
import docker
import subprocess
from pathlib import Path
import re
from flask import Flask, request, jsonify
import threading
import OpenSSL
from datetime import datetime, timedelta

app = Flask(__name__)

class CertificateManager:
    def __init__(self):
        self.docker_client = docker.from_env()
        self.cert_path = Path('/etc/letsencrypt/live')
        self.self_signed_path = Path('/etc/ssl/self-signed')
        self.staging = os.getenv('CERTBOT_STAGING', '1') == '1'

    def is_valid_tld(self, domain):
        """Check if domain has a valid TLD for Certbot"""
        # This is a simplified check - you might want to use a proper TLD library
        return not domain.endswith(('.local', '.internal', '.test', '.example', '.invalid'))

    def get_container_domains(self):
        """Get domains from running containers via labels"""
        domains = set()
        containers = self.docker_client.containers.list()

        for container in containers:
            labels = container.labels
            # Check for SSL-related labels
            ssl_domains = labels.get('ssl.domains', '').split(',')
            domains.update(domain.strip() for domain in ssl_domains if domain.strip())

            # Check for individual domain label
            if 'ssl.domain' in labels:
                domains.add(labels['ssl.domain'])

        return list(domains)

    def ensure_certificate(self, domain):
        """Ensure certificate exists for domain using appropriate method"""
        if self.is_valid_tld(domain):
            return self.ensure_certbot_certificate(domain)
        else:
            return self.ensure_self_signed_certificate(domain)

    def ensure_certbot_certificate(self, domain):
        """Generate certificate using Certbot"""
        cert_path = self.cert_path / domain
        if cert_path.exists():
            # Check if renewal is needed
            return {"status": "exists", "domain": domain, "type": "certbot"}

        cmd = [
            'certbot', 'certonly',
            '--standalone',
            '--preferred-challenges', 'http',
            '--agree-tos',
            '--email', 'admin@localhost',
            '-d', domain
        ]

        if self.staging:
            cmd.append('--staging')

        try:
            subprocess.run(cmd, check=True)
            return {"status": "generated", "domain": domain, "type": "certbot"}
        except subprocess.CalledProcessError as e:
            print(f"Certbot error for {domain}: {e}")
            return {"status": "error", "domain": domain, "error": str(e)}

    def ensure_self_signed_certificate(self, domain):
        """Generate self-signed certificate"""
        cert_dir = self.self_signed_path / domain
        cert_path = cert_dir / 'fullchain.pem'
        key_path = cert_dir / 'privkey.pem'

        if cert_path.exists() and key_path.exists():
            # Check if renewal is needed (e.g., expires in less than 30 days)
            return {"status": "exists", "domain": domain, "type": "self-signed"}

        cert_dir.mkdir(parents=True, exist_ok=True)

        # Generate private key
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        # Generate certificate
        cert = OpenSSL.crypto.X509()
        cert.get_subject().CN = domain
        cert.set_serial_number(int(datetime.now().timestamp()))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for one year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        # Save certificate and private key
        with open(cert_path, 'wb') as f:
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

        with open(key_path, 'wb') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

        return {"status": "generated", "domain": domain, "type": "self-signed"}

    def run(self):
        """Main certificate management routine"""
        print("Starting certificate check...")
        results = []

        # Check container labels
        domains = self.get_container_domains()
        for domain in domains:
            result = self.ensure_certificate(domain)
            results.append(result)

        print(f"Certificate check completed. Results: {results}")
        return results

# API Routes
@app.route('/generate-cert', methods=['POST'])
def generate_cert():
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    result = cert_manager.ensure_certificate(domain)
    return jsonify(result)

@app.route('/certificates', methods=['GET'])
def list_certificates():
    certbot_certs = list(cert_manager.cert_path.glob('*'))
    self_signed_certs = list(cert_manager.self_signed_path.glob('*'))

    certificates = {
        "certbot": [cert.name for cert in certbot_certs],
        "self_signed": [cert.name for cert in self_signed_certs]
    }

    return jsonify(certificates)

def run_flask():
    app.run(host='0.0.0.0', port=5000)

def run_scheduler():
    cert_manager = CertificateManager()

    # Schedule regular updates
    interval = os.getenv('CERT_RENEWAL_INTERVAL', '12h')
    schedule.every().interval = interval
    schedule.every().interval.do(cert_manager.run)

    # Initial run
    cert_manager.run()

    # Keep the scheduler running
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    cert_manager = CertificateManager()

    # Start Flask API in a separate thread
    api_thread = threading.Thread(target=run_flask)
    api_thread.start()

    # Run the scheduler in the main thread
    run_scheduler()
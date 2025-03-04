#!/opt/homebrew/bin/python3.13

import os
import time
import schedule
import docker
import kubernetes as k8s
import subprocess
from pathlib import Path
import re
from flask import Flask, request, jsonify
import threading
import OpenSSL
from datetime import datetime, timedelta
import yaml
import logging
from prometheus_client import start_http_server, Counter, Gauge
import json

# Initialize Flask app
app = Flask(__name__)

# Initialize metrics
CERT_REQUESTS = Counter('cert_requests_total', 'Total certificate requests', ['type', 'status'])
ACTIVE_CERTS = Gauge('active_certificates', 'Number of active certificates', ['type'])
CERT_EXPIRY = Gauge('certificate_expiry_days', 'Days until certificate expiry', ['domain', 'type'])

class CertificateManager:
    def __init__(self):
        self.load_config()
        self.setup_logging()
        self.initialize_clients()
        self.setup_paths()

    def load_config(self):
        """Load configuration from file"""
        config_path = os.getenv('CONFIG_PATH', '/app/config/config.yaml')
        try:
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            self.config = {}

    def setup_logging(self):
        """Configure logging"""
        log_level = os.getenv('LOG_LEVEL', 'INFO')
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('CertManager')

    def initialize_clients(self):
        """Initialize Docker and Kubernetes clients"""
        self.kubernetes_mode = os.getenv('KUBERNETES_MODE', 'false').lower() == 'true'

        if self.kubernetes_mode:
            try:
                k8s.config.load_incluster_config()
                self.k8s_client = k8s.client.CoreV1Api()
                self.logger.info("Initialized Kubernetes client")
            except Exception as e:
                self.logger.error(f"Failed to initialize Kubernetes client: {e}")

        try:
            self.docker_client = docker.from_env()
            self.logger.info("Initialized Docker client")
        except Exception as e:
            self.logger.error(f"Failed to initialize Docker client: {e}")

    def setup_paths(self):
        """Setup certificate paths"""
        self.cert_path = Path('/etc/letsencrypt/live')
        self.self_signed_path = Path('/etc/ssl/self-signed')
        self.cert_path.mkdir(parents=True, exist_ok=True)
        self.self_signed_path.mkdir(parents=True, exist_ok=True)

    def get_domains(self):
        """Get domains from both Docker and Kubernetes"""
        domains = set()

        # Get domains from Docker containers
        if hasattr(self, 'docker_client'):
            try:
                containers = self.docker_client.containers.list()
                for container in containers:
                    domains.update(self.get_container_domains(container))
            except Exception as e:
                self.logger.error(f"Error getting Docker domains: {e}")

        # Get domains from Kubernetes
        if self.kubernetes_mode:
            try:
                domains.update(self.get_kubernetes_domains())
            except Exception as e:
                self.logger.error(f"Error getting Kubernetes domains: {e}")

        return list(domains)

    def get_container_domains(self, container):
        """Extract domains from container labels"""
        domains = set()
        labels = container.labels

        # Check SSL-related labels
        ssl_domains = labels.get('ssl.domains', '').split(',')
        domains.update(domain.strip() for domain in ssl_domains if domain.strip())

        if 'ssl.domain' in labels:
            domains.add(labels['ssl.domain'])

        return domains

    def get_kubernetes_domains(self):
        """Get domains from Kubernetes resources"""
        domains = set()

        try:
            # Check ingresses
            networking_api = k8s.client.NetworkingV1Api()
            ingresses = networking_api.list_ingress_for_all_namespaces()

            for ingress in ingresses.items:
                if ingress.spec.tls:
                    for tls in ingress.spec.tls:
                        domains.update(tls.hosts)

            # Check services with SSL annotations
            services = self.k8s_client.list_service_for_all_namespaces()
            for service in services.items:
                annotations = service.metadata.annotations or {}
                if 'ssl.domain' in annotations:
                    domains.add(annotations['ssl.domain'])
                if 'ssl.domains' in annotations:
                    domains.update(annotations['ssl.domains'].split(','))

        except Exception as e:
            self.logger.error(f"Error getting Kubernetes domains: {e}")

        return domains

    def is_valid_tld(self, domain):
        """Check if domain has a valid TLD for Certbot"""
        return not any(domain.endswith(suffix) for suffix in ['.local', '.internal', '.test', '.example', '.invalid'])

    def ensure_certificate(self, domain):
        """Ensure certificate exists using appropriate method"""
        try:
            if self.is_valid_tld(domain):
                result = self.ensure_certbot_certificate(domain)
            else:
                result = self.ensure_self_signed_certificate(domain)

            # Update metrics
            CERT_REQUESTS.labels(
                type='certbot' if self.is_valid_tld(domain) else 'self-signed',
                status=result['status']
            ).inc()

            return result
        except Exception as e:
            self.logger.error(f"Error ensuring certificate for {domain}: {e}")
            return {"status": "error", "domain": domain, "error": str(e)}

    def ensure_certbot_certificate(self, domain):
        """Generate or renew Certbot certificate"""
        cert_path = self.cert_path / domain

        try:
            cmd = [
                'certbot', 'certonly',
                '--standalone',
                '--preferred-challenges', 'http',
                '--agree-tos',
                '--email', os.getenv('CERTBOT_EMAIL', 'admin@local'),
                '-d', domain
            ]

            if os.getenv('CERTBOT_STAGING', '1') == '1':
                cmd.append('--staging')

            subprocess.run(cmd, check=True)

            # Update metrics
            self.update_certificate_metrics(domain, 'certbot')

            return {"status": "success", "domain": domain, "type": "certbot"}
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Certbot error for {domain}: {e}")
            return {"status": "error", "domain": domain, "error": str(e)}

    def ensure_self_signed_certificate(self, domain):
        """Generate self-signed certificate"""
        cert_dir = self.self_signed_path / domain
        cert_path = cert_dir / 'fullchain.pem'
        key_path = cert_dir / 'privkey.pem'

        try:
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

            # Update metrics
            self.update_certificate_metrics(domain, 'self-signed')

            return {"status": "success", "domain": domain, "type": "self-signed"}
        except Exception as e:
            self.logger.error(f"Error generating self-signed certificate for {domain}: {e}")
            return {"status": "error", "domain": domain, "error": str(e)}

    def update_certificate_metrics(self, domain, cert_type):
        """Update Prometheus metrics for certificates"""
        ACTIVE_CERTS.labels(type=cert_type).inc()

        # Calculate days until expiry
        if cert_type == 'certbot':
            cert_path = self.cert_path / domain / 'fullchain.pem'
        else:
            cert_path = self.self_signed_path / domain / 'fullchain.pem'

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
            expiry = datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
            days_until_expiry = (expiry - datetime.now()).days
            CERT_EXPIRY.labels(domain=domain, type=cert_type).set(days_until_expiry)
        except Exception as e:
            self.logger.error(f"Error updating metrics for {domain}: {e}")

    def run(self):
        """Main certificate management routine"""
        self.logger.info("Starting certificate check...")
        results = []

        domains = self.get_domains()
        for domain in domains:
            result = self.ensure_certificate(domain)
            results.append(result)

        self.logger.info(f"Certificate check completed. Results: {json.dumps(results, indent=2)}")
        return results

# API Routes
@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

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
    certbot_certs = [p.name for p in cert_manager.cert_path.glob('*')]
    self_signed_certs = [p.name for p in cert_manager.self_signed_path.glob('*')]

    return jsonify({
        "certbot": certbot_certs,
        "self_signed": self_signed_certs
    })

def run_flask():
    """Run Flask API server"""
    app.run(host='0.0.0.0', port=5000)

def run_metrics():
    """Start Prometheus metrics server"""
    start_http_server(9090)

def run_scheduler():
    """Run certificate management scheduler"""
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

    # Start Prometheus metrics server
    metrics_thread = threading.Thread(target=run_metrics)
    metrics_thread.start()

    # Start Flask API in a separate thread
    api_thread = threading.Thread(target=run_flask)
    api_thread.start()

    # Run the scheduler in the main thread
    run_scheduler()
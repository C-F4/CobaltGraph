# Encrypted Credentials Guide - CobaltGraph Phase 3

## Overview

CobaltGraph Phase 3 implements a HYBRID approach:
- **Phase 3A:** Documentation + best practices for encrypted env vars
- **Phase 3B:** Example code for future encryption layer (cryptography library)
- **Phase 4:** Active encryption implementation (future)

## Current Approach: Environment Variables (Recommended)

### Using HashiCorp Vault

**Installation:**
```bash
curl https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip -o vault.zip
unzip vault.zip
sudo mv vault /usr/local/bin/
vault --version
```

**Setup Vault with Secrets:**
```bash
# Start Vault in dev mode
vault server -dev

# In another terminal, set token
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='...' # From dev startup

# Store CobaltGraph credentials
vault kv put secret/cobaltgraph/auth \
  password="MyStrongPa$$word1" \
  username="admin"

vault kv put secret/cobaltgraph/threat-intel \
  virustotal_key="..." \
  abuseipdb_key="..."
```

**Retrieve in CobaltGraph:**
```bash
# Before starting CobaltGraph
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='...'

# Retrieve and export for CobaltGraph
export SUARON_AUTH_PASSWORD=$(vault kv get -field=password secret/cobaltgraph/auth)
export SUARON_VIRUSTOTAL_KEY=$(vault kv get -field=virustotal_key secret/cobaltgraph/threat-intel)
export SUARON_ABUSEIPDB_KEY=$(vault kv get -field=abuseipdb_key secret/cobaltgraph/threat-intel)

# Start CobaltGraph (env vars will be cleared by SEC-007)
python start.py
```

### Using AWS Secrets Manager (Production)

**IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "arn:aws:secretsmanager:region:account:secret:cobaltgraph/*"
  }]
}
```

**Store Secrets:**
```bash
aws secretsmanager create-secret \
  --name cobaltgraph/auth-credentials \
  --secret-string '{"password":"...","username":"admin"}'

aws secretsmanager create-secret \
  --name cobaltgraph/threat-intel-keys \
  --secret-string '{"virustotal":"...","abuseipdb":"..."}'
```

**Retrieve in CobaltGraph:**
```bash
# Install boto3
pip install boto3

# Retrieve (implement in config.py as future enhancement)
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='cobaltgraph/auth-credentials')
```

### Using Docker Secrets (Containerized)

```bash
# Create secrets
echo "MyStrongPa$$word1" | docker secret create cobaltgraph_auth_password -
echo "api-key-xxx" | docker secret create cobaltgraph_virustotal_key -

# In docker-compose.yml
services:
  cobaltgraph:
    secrets:
      - cobaltgraph_auth_password
      - cobaltgraph_virustotal_key
    environment:
      - SUARON_AUTH_PASSWORD_FILE=/run/secrets/cobaltgraph_auth_password
```

## Future: Phase 4 Encryption Implementation

When ready to implement active encryption, follow this pattern:

```python
# Example: Using cryptography.fernet
from cryptography.fernet import Fernet
import os

class EncryptedConfig:
    def __init__(self, master_key=None):
        # Load from environment if not provided
        self.master_key = master_key or os.environ.get('SUARON_MASTER_KEY')
        self.cipher = Fernet(self.master_key.encode())

    def encrypt_secret(self, secret: str) -> str:
        """Encrypt a secret value"""
        return self.cipher.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted: str) -> str:
        """Decrypt a secret value"""
        return self.cipher.decrypt(encrypted.encode()).decode()

    def load_encrypted_config(self, config_file):
        """Load encrypted config file"""
        with open(config_file, 'r') as f:
            encrypted_data = f.read()
        return self.decrypt_secret(encrypted_data)
```

## Security Checklist

- [ ] Never store secrets in config files (unencrypted)
- [ ] Always use environment variables or secrets manager
- [ ] Rotate credentials every 90 days
- [ ] Use strong master keys (32+ bytes, random)
- [ ] Enable secret audit logging
- [ ] Monitor for unauthorized secret access
- [ ] Use TLS/HTTPS for all secret transmission
- [ ] Implement network segmentation for secret servers

## Compliance

- OWASP A02:2021 (Cryptographic Failures)
- CWE-312 (Cleartext Storage of Sensitive Information)
- NIST SP 800-53: SC-28 (Protection of Information at Rest)
- PCI DSS 3.2 (Strong Cryptography)

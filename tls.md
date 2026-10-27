# HTTPS Self-Signed Certificate Configuration

## 1. Overview

This guide explains how to configure HTTPS communication between the server and client using OpenSSL and Flask.

The configuration addresses the certificate verification errors encountered when connecting to the server at `192.168.1.254`.

### Network configuration

| Component | Address / Configuration |
|---|---|
| Server VM (VM2) | `192.168.1.254` |
| HTTPS port | `443` |
| API URL | `https://192.168.1.254:443/api` |
| HTTPS server certificate | `cert.pem` |
| HTTPS server private key | `key.pem` |
| Client's trusted server certificate | `certificate/certificate_server.pem` |
| Application-level RSA private key | `private_server_key.pem` |
| Application-level RSA public key | `public_server_key.key` |

**Important:** The HTTPS certificate and the application-level RSA key pair serve different purposes. Do not substitute one for the other.

---

# Part A — Server Configuration (VM2)

## 2. Install OpenSSL

Install OpenSSL on the server:

```bash
sudo apt update
sudo apt install openssl
```

Check the installed version:

```bash
openssl version
```

## 3. Create the OpenSSL configuration

Create a file named `server_cert.cnf` in the directory where you will generate the HTTPS certificate:

```bash
nano server_cert.cnf
```

Add the following configuration:

```ini
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_server

[dn]
C = PT
ST = Some-State
O = Internet Widgits Pty Ltd
CN = 192.168.1.254

[v3_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 192.168.1.254
```

Save the file.

The most important setting is:

```ini
IP.1 = 192.168.1.254
```

It adds the server's IP address to the certificate's Subject Alternative Name (SAN), which is required for proper IP-address verification.

## 4. Generate the HTTPS certificate and private key

On VM2, execute:

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
    -out certificate_server.pem \
    -keyout private_key_server.pem \
    -days 365 \
    -sha256 \
    -config server_cert.cnf \
    -extensions v3_server
```

This generates the following files:

- `cert.pem`: The self-signed HTTPS server certificate.
- `key.pem`: The corresponding HTTPS server private key.

These filenames preserve your original Flask configuration.

Restrict access to the private key:

```bash
chmod 600 key.pem
```

**Security note:** The `-nodes` option creates an unencrypted private key. Keep `key.pem` on the server and restrict access to it.

## 5. Verify the generated certificate

Check the certificate's SAN:

```bash
openssl x509 -in certificate_server.pem -noout -subject -issuer -ext subjectAltName
```

The output should contain:

```text
X509v3 Subject Alternative Name:
    IP Address:192.168.1.254
```

Inspect the certificate extensions:

```bash
openssl x509 -in certificate_server.pem -noout -text
```

Confirm that the certificate contains:

- `CA:FALSE`
- `TLS Web Server Authentication`
- `IP Address:192.168.1.254`

The SAN is essential because your clients connect using the server's IP address rather than a DNS hostname.

## 6. Start the Flask HTTPS server

Start Flask using the same filenames as in your original setup:

```bash
flask run --host 0.0.0.0 --port 443 --cert cert.pem --key key.pem
```

Run this command from the directory containing your Flask application and the certificate files, or supply the correct file paths.

If Flask cannot bind to port 443 because of insufficient privileges, use an appropriate deployment configuration or a reverse proxy.

**Note:** Flask's development server is intended for development and testing. For production, use a production WSGI server or reverse proxy configured with the same certificate and private key.

---

# Part B — Application-Level RSA Key Pair

## 7. Generate the server's RSA private key

Your application uses a separate RSA key pair for application-level cryptographic operations.

Generate the private key:

```bash
openssl genpkey \
    -algorithm RSA \
    -out private_server_key.pem
```

This creates:

```text
private_server_key.pem
```

Keep this private key on the server.

## 8. Extract the public key

Generate the corresponding public key:

```bash
openssl rsa \
    -pubout \
    -in private_server_key.pem \
    -out public_server_key.key
```

This creates:

```text
public_server_key.key
```

Distribute the public key only to the components that need it.

The application-level RSA key pair is independent of the HTTPS certificate and private key.

| File | Purpose | Distribution |
|---|---|---|
| `private_server_key.pem` | Application-level RSA private key | Server only |
| `public_server_key.key` | Application-level RSA public key | Clients/components that need it |
| `cert.pem` | HTTPS server certificate | Server and clients |
| `key.pem` | HTTPS server private key | Server only |

---

# Part C — Client Configuration

## 9. Copy the server certificate to the client

Your existing Python program expects the trusted server certificate at:

```text
certificate/certificate_server.pem
```

Therefore, **do not rename this path in the application**.

Copy the public certificate generated on VM2 (`cert.pem`) to the client, using the expected filename `certificate_server.pem`.

For example, from the client VM:

```bash
scp username@192.168.1.254:/path/to/cert.pem \
    ~/Project/certificate/certificate_server.pem
```

Replace `username` and `/path/to/cert.pem` with the correct server account and path.

The client's directory structure should preserve your existing filenames:

```text
Project/
├── interface.py
├── certificate/
│   ├── certificate_server.pem
│   ├── cert.pem
│   └── key.pem
└── keys/
    └── public_server_key.key
```

In this example:

- `certificate/certificate_server.pem` is the trusted server certificate used to verify HTTPS.
- `certificate/cert.pem` and `certificate/key.pem` should be the client's own credentials only if mutual TLS is enabled.
- `keys/public_server_key.key` is the application-level RSA public key.

**Do not overwrite the client's own certificate or private key with the server's credentials.** If mutual TLS is not enabled, the client does not need a client certificate or private key for the HTTPS connection.

## 10. Configure the Python application

Preserve the existing certificate paths in your application:

```python
if __name__ == "__main__":
    base_url = "https://192.168.1.254:443/api"

    certificate_server_path = "certificate/certificate_server.pem"
    certificate_client_path = "certificate/cert.pem"
    key_path = "certificate/key.pem"
    server_public_key_path = "keys/public_server_key.key"

    username = input("Enter your username: ")

    client = ClientInterface(
        base_url,
        username,
        certificate_server_path,
        certificate_client_path,
        key_path,
        server_public_key_path
    )

    client.InterfaceMenu()
```

This keeps the filenames and paths expected by your current program.

Relative paths are resolved from the current working directory. Run the application from the project directory unless your code explicitly resolves paths relative to `interface.py`.

## 11. Configure the HTTPS POST request

Your request function should continue to use the trusted server certificate:

```python
response = requests.post(
    url,
    json=data,
    cert=(certificate_client_path, key_path),
    verify=certificate_server_path,
    timeout=10
)
```

The parameters have distinct purposes:

- `verify=certificate_server_path` validates the server certificate using `certificate/certificate_server.pem`.
- `cert=(certificate_client_path, key_path)` presents the client's certificate and private key if the server requires mutual TLS.
- `timeout=10` sets a request timeout.

If your server does not require mutual TLS, omit the `cert` parameter:

```python
response = requests.post(
    url,
    json=data,
    verify=certificate_server_path,
    timeout=10
)
```

Never use `verify=False` to bypass the certificate error.

---

# Part D — Testing

## 12. Verify the certificate served by Flask

From the client VM, execute:

```bash
openssl s_client \
    -connect 192.168.1.254:443 \
    -CAfile certificate/certificate_server.pem \
    -verify_ip 192.168.1.254 \
    -verify_return_error
```

Because the server certificate is self-signed, the client must trust that exact certificate.

The expected output is:

```text
Verify return code: 0 (ok)
```

If the test reports `IP address mismatch`, check the SAN and ensure Flask is serving the new certificate.

If it reports `invalid CA certificate`, inspect the certificate extensions and verify that the file supplied with `-CAfile` is the certificate currently served by Flask.

## 13. Inspect the certificate presented by the server

Run:

```bash
openssl s_client \
    -connect 192.168.1.254:443 \
    -showcerts </dev/null 2>/dev/null |
openssl x509 -noout -subject -issuer -ext subjectAltName
```

Confirm that the certificate presented by the server contains:

```text
X509v3 Subject Alternative Name:
    IP Address:192.168.1.254
```

If the SAN is missing, Flask may still be serving an old certificate or using a different certificate file.

## 14. Run the client application

Activate the virtual environment, if applicable:

```bash
cd ~/Project
source .venv/bin/activate
```

Run:

```bash
python interface.py
```

Try the API operation that previously failed.

If a request fails, inspect the reported exception:

| Error | Possible cause |
|---|---|
| `IP address mismatch` | The certificate's SAN does not match `192.168.1.254`. |
| `invalid CA certificate` | Certificate extensions or trust configuration are incorrect. |
| `Connection refused` | Flask or another HTTPS service is not listening on port 443. |
| `Connection timed out` | Network routing or firewall configuration may be blocking access. |
| `401` or `403` | The HTTPS connection may have succeeded, but application authentication or authorization failed. |

## 15. Security checklist

- [ ] `server_cert.cnf` contains `IP.1 = 192.168.1.254`.
- [ ] The generated `cert.pem` includes the correct SAN.
- [ ] `cert.pem` matches `key.pem`.
- [ ] Flask serves the newly generated certificate.
- [ ] The client trusts the server certificate at `certificate/certificate_server.pem`.
- [ ] The application-level RSA keys remain separate from the HTTPS credentials.
- [ ] Server private keys are not distributed to clients.
- [ ] Client credentials are not overwritten by server credentials.
- [ ] Certificate verification remains enabled.
- [ ] OpenSSL reports `Verify return code: 0 (ok)`.

## Conclusion

The original HTTPS certificate did not include a Subject Alternative Name matching `192.168.1.254`, causing certificate verification to fail.

The updated procedure retains the existing filenames expected by the programs:

- `cert.pem`
- `key.pem`
- `certificate_server.pem`
- `private_server_key.pem`
- `public_server_key.key`

Only the certificate-generation procedure and deployment steps need to change. This preserves compatibility with the existing application while correcting the HTTPS certificate verification problem.


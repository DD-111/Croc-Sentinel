# MQTT TLS Certificates

Place these files in this folder for Mosquitto TLS:

- `ca.crt`
- `server.crt`
- `server.key`

Example self-signed setup (for staging/testing):

```bash
cd certs

# 1) CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=Croc-Sentinel-CA" -out ca.crt

# 2) Server key + CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=your.vps.domain" -out server.csr

# 3) Sign server cert
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256
```

Production recommendation:

- Use a proper internal PKI or managed CA.
- Restrict key permissions: `chmod 600 server.key`.
- Rotate cert before expiry, then deploy dual-CA transition in firmware.

# Production Readiness Checklist

Use this as a go-live gate. All items should be checked.

## Security

- [ ] `MQTT_USE_TLS=1` in firmware and broker exposed on `8883` only.
- [ ] Firmware `PROD_ENFORCE=1`.
- [ ] Firmware keys/tokens are non-default (`CMD_AUTH_KEY`, `BOOTSTRAP_BIND_KEY`, `OTA_TOKEN`).
- [ ] API `.env` has strong values (no placeholders, long `API_TOKEN`).
- [ ] `CLAIM_RESPONSE_INCLUDE_SECRETS=0` in production.
- [ ] Broker credentials rotated from bootstrap defaults.
- [ ] `server.key` permissions restricted (`chmod 600 certs/server.key`).

## Certificates and Rotation

- [ ] `certs/ca.crt`, `certs/server.crt`, `certs/server.key` deployed.
- [ ] Firmware primary CA matches current broker cert chain.
- [ ] Secondary CA set when preparing CA rotation.
- [ ] CA rotation drill executed on staging.

## Reliability and Overload

- [ ] API scheduler running (`/health`, logs show scheduler thread active).
- [ ] Message retention configured (`MESSAGE_RETENTION_DAYS`).
- [ ] Bulk command limit configured (`MAX_BULK_TARGETS`) and validated.
- [ ] Offline queue behavior validated under broker outage.
- [ ] Scheduled reboot survives power cycle (NVS restore path verified).

## Functional

- [ ] Bootstrap claim flow verified (`/provision/pending` -> `/provision/claim`).
- [ ] Device metadata visible (`chip_target`, `board_profile`, `fw`, `net_type`).
- [ ] Alert control works for all/multi/single scopes (`/alerts`).
- [ ] Self-test endpoint verified (`/devices/{id}/self-test`).
- [ ] OTA update and rollback path verified on staging.

## Observability

- [ ] `/logs/messages` returns recent device traffic.
- [ ] `/logs/file` returns API logs.
- [ ] Alerts/commands auditable by topic and timestamp.

## Deployment

- [ ] `docker compose up -d --build` clean startup on VPS.
- [ ] `docker compose ps` all services healthy.
- [ ] `docker compose logs --tail 200` has no recurring error loops.

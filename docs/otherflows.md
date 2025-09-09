## Other OAuth / OIDC Flows

### Client Credentials
Client authentication is optional (this server accepts any `client_id`; secrets are ignored for local convenience).
```bash
curl -X POST http://localhost:18888/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=any-local-client' \
  -d 'scope=read write'
```

### Device Authorization
Step 1: request device/user codes (`device_authorization_endpoint`)
```bash
curl -X POST http://localhost:18888/device_authorization \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=device-flow-cli' \
  -d 'scope=openid profile email'
```
Response (example):
```json
{
  "device_code": "<opaque>",
  "user_code": "ABCD-EFGH",
  "verification_uri": "http://localhost:18888/device",
  "expires_in": 600,
  "interval": 5
}
```
Step 2: User opens `verification_uri` (or `verification_uri_complete` if provided), selects a test user, and approves or denies.
Step 3: poll
```bash
curl -X POST http://localhost:18888/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'device_code=XXXX' \
  -d 'client_id=device-flow-cli'
```
Polling returns `authorization_pending` until approved (or `access_denied` if denied). On success you'll receive standard token response.

### Refresh Token
Returned only when `offline_access` is requested and `refresh_token_enabled: true`.
```bash
curl -X POST http://localhost:18888/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=XXXX' \
  -d 'client_id=any-local-client'
```

### Logout Endpoint
`/end_session` (if `end_session_enabled: true`) supports: `id_token_hint`, `post_logout_redirect_uri`, `state`. Hidden from discovery when `end_session_endpoint_visible: false`.

### Response Modes
| Mode | Use |
|------|-----|
| query | Authorization Code Flow (default) |
| fragment | Implicit / Some legacy SPA & Azure MSAL compatibility |

### Troubleshooting
| Issue | Hint |
|-------|------|
| authorization_pending loops | Continue polling until user approves; check `interval` respect |
| access_denied on poll | User denied at verification screen |
| invalid_client | `client_id` missing (any value accepted) |
| Missing refresh token | Add `offline_access` and ensure refresh enabled in config |
| No device_authorization endpoint | Using older config/version – regenerate config |

Back: `config.md` · Main README.

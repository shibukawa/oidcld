## 他の OAuth / OIDC フロー

### クライアントクレデンシャル
`client_id` は任意値、`client_secret` はローカル利便性のため不要です。
```bash
curl -X POST http://localhost:18888/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=local-client' \
  -d 'scope=read write'
```

### デバイス認可フロー
1. コード取得 (`/device_authorization`)
```bash
curl -X POST http://localhost:18888/device_authorization \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=device-flow-cli' \
  -d 'scope=openid profile email'
```
例:
```json
{
  "device_code": "<opaque>",
  "user_code": "ABCD-EFGH",
  "verification_uri": "http://localhost:18888/device",
  "expires_in": 600,
  "interval": 5
}
```
2. ユーザーが `verification_uri` を開きコード入力→ユーザー選択→承認/拒否。
3. ポーリング (`authorization_pending` 継続 / 承認後トークン / `access_denied` 拒否)。
```bash
curl -X POST http://localhost:18888/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'device_code=XXXX' \
  -d 'client_id=device-flow-cli'
```

### リフレッシュトークン
`offline_access` スコープ + 設定で refresh 有効時のみ付与。
```bash
curl -X POST http://localhost:18888/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=XXXX' \
  -d 'client_id=local-client'
```

### ログアウトエンドポイント
`/end_session` (有効時) で `id_token_hint`, `post_logout_redirect_uri`, `state` をサポート。`end_session_endpoint_visible: false` でディスカバリ非掲載。

### レスポンスモード
| モード | 用途 |
|--------|------|
| query | Authorization Code (標準) |
| fragment | Implicit / 一部 SPA / MSAL 互換 |

### トラブルシュート
| 事象 | ヒント |
|------|--------|
| authorization_pending 続く | ユーザー未承認 / interval 未遵守 |
| access_denied | 検証画面で拒否 |
| invalid_client | client_id 未指定 (任意文字列可) |
| refresh_token なし | offline_access 要 + 設定で有効化 |
| endpoint 不足 | 古い設定。`init` で再生成 |

戻る: `config.ja.md` · メイン README。
## 設定ガイド

実装と初期化ウィザードの最新仕様に基づく包括的リファレンスです。README では最小限の説明のみを行います。

## クイックスタート

```bash
./oidcld init                        # 対話ウィザード
./oidcld init --template entraid-v2  # 非対話テンプレート
./oidcld --watch                     # 設定ファイル変更をホットリロード
./oidcld                             # HTTP (18888) で起動
```

## 設定ファイル構造

### 主ファイル
| ファイル | 目的 |
|----------|------|
| oidcld.yaml | メイン設定 |
| localhost.pem / localhost-key.pem | 手動 / mkcert で用意する証明書 |

### セクション概要

#### 1. OIDC 基本設定 (`oidcld`)
```yaml
oidcld:
  iss: "http://localhost:18888"          # モードとHTTPS有無で初期値変化
  pkce_required: false
  nonce_required: false
  expired_in: 3600                        # アクセストークン有効秒数
  valid_scopes:                           # 追加カスタムスコープ (標準は自動付与)
    - admin
    - read
    - write
  refresh_token_enabled: true
  refresh_token_expiry: 86400             # リフレッシュトークン TTL (秒)
  end_session_enabled: true
  end_session_endpoint_visible: true
  verbose_logging: false
  tls_cert_file: ""                       # 手動証明書利用時のみ
  tls_key_file: ""
```
標準スコープ `openid, profile, email, offline_access` (EntraID 以外では address, phone も) は自動付与。RSA-2048 鍵は起動時にオンメモリ生成されます。

#### 2. EntraID 互換設定 (`entraid`)
```yaml
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"   # v1 / v2
```
テンプレート既定: v1: tenant_id=common, v2: 固定 UUID。

#### 3. CORS (`cors`)
```yaml
cors:
  enabled: true
  # allowed_* を省略すると開発向け寛容デフォルト (全許可) 振る舞い
```

#### 4. 自動証明書 (`autocert`)
```yaml
autocert:
  enabled: true
  domains:
    - localhost
  email: admin@example.com
  agree_tos: true
  cache_dir: ./autocert-cache
  acme_server: http://localhost:14000
  staging: false
  renewal_threshold: 1
  challenge:
    port: 80
    path: /.well-known/acme-challenge/
    timeout: 30s
  rate_limit:
    requests_per_second: 10
    burst: 20
  retry:
    max_attempts: 3
    initial_delay: 1s
    max_delay: 30s
```
`insecure_skip_verify` はテンプレートには出力しません (ローカル ACME 用途向け内部フラグ)。

#### 5. ユーザー (`users`)
EntraID テンプレート時は `oid, tid, preferred_username, upn, roles, groups, app_displayname` を自動追加。

## CLI フラグ
`init`, `serve`, `health` コマンドは README を参照。

## 環境変数
| 変数 | 説明 | 既定 |
|------|------|------|
| PORT | ポート上書き | 18888 |

### ACME / autocert 上書き
設定ファイルより優先され、存在すると `enabled: true` に強制。
| 変数 | 説明 |
|------|------|
| OIDCLD_ACME_DIRECTORY_URL | acme_server URL |
| OIDCLD_ACME_EMAIL | 登録メール |
| OIDCLD_ACME_DOMAIN | カンマ区切りドメイン一覧 |
| OIDCLD_ACME_CACHE_DIR | キャッシュディレクトリ |
| OIDCLD_ACME_AGREE_TOS | TOS 同意 (true) |

## ランタイム挙動 (ホットリロード)
即時反映: users, valid_scopes, expired_in, pkce/nonce, refresh_token 設定, cors。
再起動必要: iss, ポート, TLS/Autocert有効化や構造, EntraID テンプレ/tenant, autocert のドメイン/サーバー/レート制御/チャレンジ/リトライ。

## HTTPS モード
| モード | 用途 | メモ |
|--------|------|------|
| HTTP | 最速試行 | 18888 |
| 手動 HTTPS | SPA セキュアオリジン | cert/key 指定 |
| mkcert | ブラウザ信頼 | 手動 HTTPS の一形態 |
| ACME | ライフサイクル再現 | autocert + env |

## 初期化ウィザードフロー (概要)
1. テンプレ選択 (standard / entraid-v1 / entraid-v2)
2. EntraID 選択時: tenant 入力 + HTTPS 強制
3. Standard: HTTPS 有効化質問
4. HTTPS 有効化時: 証明書方式 (manual / ACME)
5. ACME 選択時: acme_server / domains / email
6. (standard のみ) port
7. issuer (任意)
8. 上書き確認

詳細フローとシーケンスは英語版 `config.md` の Mermaid 図を参照。

## トラブルシュート例
| 症状 | 原因候補 | 対処 |
|------|----------|------|
| 401 | redirect_uri / scope 問題 | リクエスト再確認 |
| CORS ブロック | origin 未許可 | cors.allowed_origins 追加 |
| MSAL が拒否 | HTTPS / 証明書 | mkcert か ACME 利用 |
| refresh_token 無 | scope / 設定無効 | offline_access + refresh 有効 |
| 証明書エラー | 期限 / パス | 再発行 or パス修正 |

プロトコル別の利用例は `otherflows.ja.md` を参照。
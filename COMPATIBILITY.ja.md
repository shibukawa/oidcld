# OIDCLD 0.1.x から 0.2 への互換性

このドキュメントは、0.1.x 系列の最新 (`v0.1.8`) と現在の 0.2 設定モデルのあいだにある、ユーザーから見える設定差分をまとめたものです。

現在の挙動の一次情報は [`internal/config/config.go`](/Users/shibukawayoshiki/.codex/worktrees/7974/oidcld/internal/config/config.go) です。この比較における旧レイアウトの一次情報は、`v0.1.8` の README / config docs / template 出力です。

## 概要

0.2 は 0.1.x からの drop-in upgrade ではありません。

- トップレベルの `oidcld:` セクションは `oidc:` に変更されました
- `access_filter` はトップレベルへ移動しました
- トップレベルの `cors:` はサポートされなくなりました
- `console`、`certificate_authority`、`reverse_proxy` が新しいトップレベル section として追加されました
- 一部の legacy な certificate authority key は `certificate_authority.domains` に整理されました

## トップレベル key の変更

| 0.1.x | 0.2 | 補足 |
|---|---|---|
| `oidcld` | `oidc` | 必須の rename です。旧 `oidcld:` は `ErrLegacyOIDCLDConfig` で失敗します。 |
| `entraid` | `entraid` | トップレベル section 名は変更なし。 |
| `autocert` | `autocert` | section 名は変更なし。 |
| `users` | `users` | section 名は変更なし。 |
| `cors` | removed | `oidc.cors` または `reverse_proxy.hosts[].cors` へ移動します。旧トップレベル `cors:` は `ErrLegacyTopLevelCORS` で失敗します。 |
| nested `oidcld.access_filter` | `access_filter` | トップレベルへ移動しました。 |
| not available | `console` | 0.2 で新規追加。 |
| not available | `certificate_authority` | 0.2 で新規追加。 |
| not available | `reverse_proxy` | 0.2 で新規追加。 |

## 移動 / rename された設定

| 0.1.x path | 0.2 path | 補足 |
|---|---|---|
| `oidcld.iss` | `oidc.iss` | 意味は同じで、親 section だけ変更。 |
| `oidcld.pkce_required` | `oidc.pkce_required` | 意味は同じで、親 section だけ変更。 |
| `oidcld.nonce_required` | `oidc.nonce_required` | 意味は同じで、親 section だけ変更。 |
| `oidcld.expired_in` | `oidc.expired_in` | 意味は同じで、親 section だけ変更。 |
| `oidcld.aud_claim_format` | `oidc.aud_claim_format` | 意味は同じで、親 section だけ変更。 |
| `oidcld.valid_scopes` | `oidc.valid_scopes` | 意味は同じで、親 section だけ変更。 |
| `oidcld.login_ui.*` | `oidc.login_ui.*` | 意味は同じで、親 section だけ変更。 |
| `oidcld.refresh_token_enabled` | `oidc.refresh_token_enabled` | 意味は同じで、親 section だけ変更。 |
| `oidcld.refresh_token_expiry` | `oidc.refresh_token_expiry` | 意味は同じで、親 section だけ変更。 |
| `oidcld.end_session_enabled` | `oidc.end_session_enabled` | 意味は同じで、親 section だけ変更。 |
| `oidcld.end_session_endpoint_visible` | `oidc.end_session_endpoint_visible` | 意味は同じで、親 section だけ変更。 |
| `oidcld.verbose_logging` | `oidc.verbose_logging` | 意味は同じで、親 section だけ変更。 |
| `oidcld.tls_cert_file` | `oidc.tls_cert_file` | 意味は同じで、親 section だけ変更。 |
| `oidcld.tls_key_file` | `oidc.tls_key_file` | 意味は同じで、親 section だけ変更。 |
| `oidcld.access_filter.enabled` | `access_filter.enabled` | トップレベルへ移動。 |
| `oidcld.access_filter.extra_allowed_ips` | `access_filter.extra_allowed_ips` | トップレベルへ移動。 |
| `oidcld.access_filter.max_forwarded_hops` | `access_filter.max_forwarded_hops` | トップレベルへ移動。 |
| top-level `cors.enabled` | `oidc.cors` or `reverse_proxy.hosts[].cors` | 0.2 では対象 section 配下に `bool` または object 形式で書きます。 |
| top-level `cors.allowed_origins` | `oidc.cors.origins` or `reverse_proxy.hosts[].cors.origins` | field 名が `allowed_origins` から `origins` に変わりました。 |
| top-level `cors.allowed_methods` | `oidc.cors.methods` or `reverse_proxy.hosts[].cors.methods` | field 名が `allowed_methods` から `methods` に変わりました。 |
| top-level `cors.allowed_headers` | `oidc.cors.headers` or `reverse_proxy.hosts[].cors.headers` | field 名が `allowed_headers` から `headers` に変わりました。 |

## 0.2 で新しく導入された section

| Section | 目的 | 主な field |
|---|---|---|
| `console` | Developer Console listener | `port`, `bind_address` |
| `certificate_authority` | ローカル開発用の managed CA | `ca_dir`, `domains`, `ca_cert_ttl`, `leaf_cert_ttl` |
| `reverse_proxy` | virtual host、proxy、static hosting、OpenAPI mock、request log retention | `log_retention`, `ignore_log_paths`, `hosts[]` |

## 削除された legacy key

| Removed key | Replacement | 現在の挙動 |
|---|---|---|
| top-level `oidcld` | `oidc`。必要に応じてトップレベル `access_filter`、`console`、`certificate_authority` も追加 | 現在の parser は旧トップレベル key を reject します。 |
| top-level `cors` | `oidc.cors` または `reverse_proxy.hosts[].cors` | 現在の parser は旧トップレベル key を reject します。 |
| `certificate_authority.domain_suffix` | `certificate_authority.domains` | 現在の parser は旧 key を reject します。 |
| `certificate_authority.server_names` | `certificate_authority.domains` | 現在の parser は旧 key を reject します。 |

## 移行例

### 0.1.x 形式の例

```yaml
oidcld:
  iss: "https://oidc.localhost:8443"
  pkce_required: true
  access_filter:
    enabled: true
    max_forwarded_hops: 0
  login_ui:
    env_title: "Local"

cors:
  enabled: true
  allowed_origins:
    - "https://app.localhost:8443"
  allowed_methods:
    - "GET"
    - "POST"
  allowed_headers:
    - "Content-Type"
    - "Authorization"

users:
  admin:
    display_name: "Administrator"
```

### 0.2 形式の例

```yaml
access_filter:
  enabled: true
  max_forwarded_hops: 0

oidc:
  iss: "https://oidc.localhost:8443"
  pkce_required: true
  login_ui:
    env_title: "Local"
  cors:
    origins:
      - "https://app.localhost:8443"
    methods:
      - "GET"
      - "POST"
    headers:
      - "Content-Type"
      - "Authorization"

console:
  port: "18889"
  bind_address: "127.0.0.1"

certificate_authority:
  ca_dir: "./tls"
  domains:
    - "oidc.localhost"
    - "app.localhost"

users:
  admin:
    display_name: "Administrator"
```

## 運用面で移行に影響する点

- 0.2 の README 例と Compose sample は、IdP 単体トポロジーではなく、HTTPS + console + reverse-proxy を統合したトポロジーを前面に出しています。
- Compose sample では Developer Console と metadata companion に `http://localhost:18889` を使い、browser-facing の TLS traffic は `https://*.localhost:8443` で公開されます。
- OIDCLD を IdP としてだけ使い続けることは 0.2 でも可能ですが、旧設定ファイルは新しい section 構成に合わせて更新が必要です。

## 確認チェックリスト

- `oidcld:` を `oidc:` に rename する
- `access_filter` を OIDC section の外へ移す
- トップレベル `cors:` は `oidc.cors` または `reverse_proxy.hosts[].cors` に置き換える
- certificate authority の legacy host key を `certificate_authority.domains` に置き換える
- `console`、`certificate_authority`、`reverse_proxy` は 0.2 の機能を使うときだけ追加する

現行 schema 全体は [docs/config.ja.md](docs/config.ja.md) を参照してください。

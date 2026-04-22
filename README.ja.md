# OIDCLD

ローカル開発向けの identity、TLS、edge routing を 1 つの runtime にまとめたツールです。

[![CI](https://github.com/shibukawa/oidcld/actions/workflows/ci.yml/badge.svg)](https://github.com/shibukawa/oidcld/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shibukawa/oidcld)](https://github.com/shibukawa/oidcld/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shibukawa/oidcld)](go.mod)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE.md)
[![Container](https://img.shields.io/badge/GHCR-oidcld-0f5fff?logo=docker)](https://github.com/shibukawa/oidcld/pkgs/container/oidcld)

English: see [README.md](README.md)

クイックリンク: [設定ガイド](docs/config.ja.md) | [0.1.x から 0.2 への互換性](COMPATIBILITY.ja.md) | [llms.txt](llms.txt)

OIDCLD はもともとテスト用の fake OpenID Connect Identity Provider として始まりました。0.2 では、ローカル開発向け edge platform と捉えるのが適切です。OIDC / EntraID 互換 IdP として動作し、ローカル開発用 CA を管理し、複数ホストの TLS を終端し、frontend と API を reverse proxy し、静的配信と OpenAPI モックを提供し、さらに Developer Console で reverse proxy のログも確認できます。

このプロジェクトは引き続き開発 / テスト専用です。本番環境では使用しないでください。

![console](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/console.png)

## フル構成トポロジー

![OIDCLD 全体構成図](docs/oidcld-components.ja.svg)

この図は 0.2 の全体像を示しています。OIDCLD は browser から見て identity provider と edge router の両方として振る舞い、OIDCLD が発行した token を reverse-proxy route 側で検証でき、managed local CA が browser-facing host 全体をカバーします。統合 Compose サンプルでは、`oidc.localhost`、`app.localhost`、`app2.localhost` が container 側 `443`、host 側 `8443` を共有し、Developer Console と metadata companion は別 listener の `8888` を使います。

`--proxy-port` または `PROXY_PORT` を使った split listener mode でも論理構成は同じですが、OIDC と reverse proxy の browser-facing traffic を 1 本の listener ではなく別ポートに分離して公開します。

## OIDCLD 0.2 でできること

OIDCLD 0.2 は大きく 3 つの役割を持ちます。

### 1. OIDC / EntraID 互換 Identity Provider

- Authorization Code、Client Credentials、Device Flow、Refresh Token、PKCE、RP-Initiated Logout をサポート
- OIDC discovery と JWKS endpoint を提供
- MSAL 向けに EntraID / Azure 風の claim と endpoint alias を再現可能
- パスワード入力ではなくユーザー選択中心の高速ログインを維持

### 2. ローカル開発用 CA と TLS ツール

- `certificate_authority.ca_dir` 配下にローカル root CA を生成して保持
- OIDC issuer host と reverse-proxy host 向けの leaf certificate を発行
- Developer Console から root CA や install / uninstall script を配布
- 必要なら manual TLS cert や `autocert` も利用可能

### 3. Reverse proxy / static hosting / mock API

- `reverse_proxy.hosts[]` で virtual host と path route を定義
- frontend / backend への reverse proxy
- SPA fallback 付き静的配信
- OpenAPI ベースの mock response
- OIDCLD 発行 bearer token に対する route 単位の API gateway 検証
- Developer Console 上で設定と request log を確認

## クイックスタート

### シンプルなローカル OIDC サーバー

IdP だけ欲しい場合はバイナリを直接実行します。

```bash
./oidcld init
./oidcld
open http://localhost:8080/.well-known/openid-configuration
```

既定では HTTP `8080` で起動します。必要になったら `--cert-file` / `--key-file` で manual HTTPS を追加できます。

### Managed local TLS + Developer Console

ローカル証明書管理と console を使いたい場合は、`oidcld.yaml` の `certificate_authority` と `console` を設定します。listener port は `--port`、`PORT`、`--console-port`、`CONSOLE_PORT` で runtime に指定します。`access_filter` を省略した場合、host では既定 `true`、container runtime 検知時は既定 `false` になります。明示した `access_filter` 設定はそのまま尊重されます。

discovery の `issuer` は `oidc.iss` に固定されますが、返却する公開 endpoint URL はリクエスト時の host に追従します。これにより、browser は `https://oidc.localhost:8443`、container 内クライアントは `http://oidcld:8888` をそのまま使えます。

```yaml
access_filter:
  enabled: true

oidc:
  iss: "https://oidc.localhost:8443"
  pkce_required: true
  login_ui:
    env_title: "Local Compose"
    info_markdown_file: "./login-info.md"
  cors: true

console:
  bind_address: "127.0.0.1"

certificate_authority:
  ca_dir: "./tls"
  domains:
    - "oidc.localhost"
    - "app.localhost"
    - "app2.localhost"
```

このモードが下記のフル構成サンプルの土台になります。

## 統合 Compose サンプル

リポジトリ直下の [`compose.yaml`](/Users/shibukawayoshiki/.codex/worktrees/7974/oidcld/compose.yaml) と [`examples/reverseproxy/config/oidcld.yaml`](/Users/shibukawayoshiki/.codex/worktrees/7974/oidcld/examples/reverseproxy/config/oidcld.yaml) が、0.2 の統合トポロジーを示しています。

- HTTPS listener は container 側 `443`、host 側 `https://*.localhost:8443`
- Developer Console と metadata companion は `http://localhost:8888`
- `app.localhost` は upstream build 済み frontend と `/api/*` backend を reverse proxy
- `app2.localhost` は OIDCLD 自身が static file を配信し、`/apimock/*` を OpenAPI mock に接続
- ローカル CA は `oidcld-managed-ca` volume に保存されるため、volume を消さない限り root CA は安定

起動:

```bash
docker compose up --build
```

利用 URL:

- OIDC issuer: `https://oidc.localhost:8443`
- Reverse-proxy frontend: `https://app.localhost:8443`
- Static-hosted frontend: `https://app2.localhost:8443`
- Developer Console: `http://localhost:8888/console/`

Console では root CA をダウンロードでき、reverse-proxy route と request log も確認できます。補足は [examples/reverseproxy/README.md](examples/reverseproxy/README.md) を参照してください。

`*.localhost` の wildcard 解決に頼れない環境では、split listener mode を使えます。

```bash
./oidcld serve --port 8443 --proxy-port 19080
```

このモードでは `--port` または `PORT` が OIDC listener、`--proxy-port` または `PROXY_PORT` が reverse-proxy 専用 listener になります。Developer Console と metadata companion の第3ポートは `--console-port` または `CONSOLE_PORT` で制御します。`--proxy-port` と `PROXY_PORT` の両方が無い場合、reverse proxy は main listener を共有します。

## EntraID 互換

OIDCLD は MSAL を使うローカル開発向けに Azure AD / EntraID 互換の振る舞いを再現できます。

- `./oidcld init --template entraid-v2` で EntraID 用設定を生成
- EntraID モードでは issuer 形式と Azure 風 claims を採用
- 単一 audience の `aud` は既定で `aud_claim_format: string`
- `/{tenant}/v2.0/.well-known/openid-configuration` のような Microsoft 風 alias に対応
- ブラウザでの MSAL テストには HTTPS が必要

最小例:

```bash
./oidcld init --template entraid-v2
./oidcld --cert-file localhost.pem --key-file localhost-key.pem
curl -k https://localhost:8443/.well-known/openid-configuration
```

## 設定上の注意

OIDCLD 0.2 の設定モデルは次の通りです。

- `oidc:` が IdP 設定
- `access_filter:` はトップレベル
- `oidc.cors` は IdP endpoint 向け CORS
- `reverse_proxy.hosts[].cors` は reverse-proxy host 向け CORS
- `console`、`certificate_authority`、`reverse_proxy` はトップレベル section

0.1.x の設定ファイルを流用する場合は、先に [COMPATIBILITY.ja.md](COMPATIBILITY.ja.md) を確認してください。

## CLI サマリー

- `oidcld init`: template から設定を生成
- `oidcld serve`: runtime を起動
- `oidcld serve --proxy-port <port>`: OIDC と reverse proxy を別 listener に分離して起動 (`PROXY_PORT` が env 相当)
- `oidcld health`: readiness / liveness を確認
- `oidcld mcp`: MCP server mode で起動

フラグ、環境変数、既定値、runtime 挙動の詳細は [docs/config.ja.md](docs/config.ja.md) を参照してください。

## セキュリティ上の制約

OIDCLD はローカル開発の速度を優先して、意図的に厳密性を下げています。

- `client_id` は allowlist されません
- `redirect_uri` は動的に受け付けます
- client secret は必須ではありません
- 署名鍵は起動時生成で永続化しません
- ローカル限定アクセス制御は `access_filter` が担います
- SPA 開発を容易にするため CORS の既定値は緩めです

これらは開発 / テスト向けの設計であり、本番利用を意図していません。

## 追加ドキュメント

- [設定ガイド](docs/config.ja.md)
- [0.1.x から 0.2 への互換性](COMPATIBILITY.ja.md)
- [他の OAuth / OIDC フロー](docs/otherflows.ja.md)
- [examples/reverseproxy/README.md](examples/reverseproxy/README.md)

## ライセンス

このプロジェクトは GNU Affero General Public License v3.0 (AGPL-3.0) の下でライセンスされています。

# ローカル開発用 OpenID Connect: OIDCLD

テストと開発のために設計されたフェイクな OpenID Connect アイデンティティプロバイダー (IdP)。

[![CI](https://github.com/shibukawa/oidcld/actions/workflows/ci.yml/badge.svg)](https://github.com/shibukawa/oidcld/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shibukawa/oidcld)](https://github.com/shibukawa/oidcld/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shibukawa/oidcld)](go.mod)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE.md)
[![Container](https://img.shields.io/badge/GHCR-oidcld-0f5fff?logo=docker)](https://github.com/shibukawa/oidcld/pkgs/container/oidcld)

English: see [README.md](README.md)

## 目次
- [用語](#用語)
- [主な機能](#主な機能)
- [ユースケース](#ユースケース)
- [3. EntraID 互換モード (MSAL / Azure スタイルのクレーム)](#3-entraid-互換モード-msal--azure-スタイルのクレーム)
- [HTTPS 設定](#https-設定)
- [OIDCLD 向けの MSAL 設定例](#oidcld-向けの-msal-設定例)
- [CLI サマリー](#cli-サマリー)
- [セキュリティ上の制約](#セキュリティ上の制約)
- [追加ドキュメント](#追加ドキュメント)
- [ライセンス](#ライセンス)

![console](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/console.png)

## 用語

このプロジェクトは xUnit テストパターンの用語を用いて目的と機能を明確にしています。

### フェイク vs モック
- フェイク: 簡略化された動作を持つ実用的な実装でテストに適します。実際のビジネスロジックは持ちますが、インメモリ保管などのショートカットを取ります。
- モック: 相互作用を記録し期待値で検証するテスト用オブジェクト。

### このプロジェクトは「フェイク」です
この OpenID Connect アイデンティティプロバイダーは以下の理由からフェイク実装です:
- 実際のプロトコル準拠を満たす機能的な OIDC サーバーを提供
- 簡略化された構成 (インメモリ、テスト証明書、ユーザー選択 UI)
- テスト目的で実際の認証フローを有効化
- モックのように特定の相互作用検証や期待値アサートは行わない

----

![screenshot](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/login-screen.png)

ログイン画面: パスワード不要—クリックでログイン。テストに便利。開発環境だけのログイン回避はもう不要です。

----

## 主な機能
- ローカルテスト環境向けの OpenID Connect IdP (❌ 本番環境では使用しないでください)
  - 複数フロー: Authorization Code / Client Credentials / Device / Refresh Token
  - PKCE 対応: セキュリティ強化のための Proof Key for Code Exchange
  - リフレッシュトークン: 長期セッション向けに任意で発行/検証
  - End Session: RP-Initiated Logout (ディスカバリ掲載は設定可能)
  - OpenID ディスカバリ: `/.well-known/openid-configuration`
- ローカルテストに最適
  - Docker との相性良好: DB などの永続ストレージ不要。単一の設定ファイルで動作
  - 迅速なログイン: ユーザー名をクリックするだけ (パスワード不要)
  - カスタム JWT クレーム: YAML で追加クレームを付与可能
- EntraID/AzureAD 互換:
  - MSAL.js でのテストに対応

## ユースケース

起動スタイルは「単体バイナリ / コンテナ」の 2 種類、API は「標準 OIDC / EntraID 互換」の 2 モードがあります。

### 1. シンプルなローカルサーバー (標準 OIDC)

ローカルに `oidcld` バイナリをそのまま実行。最速の反復と最小の構成で試せます。

```mermaid
flowchart TB
  DevApp["Local App (React/Vite, Go, Node, etc)"] -->|Auth Code / Device / Client Credentials| OIDCLD[oidcld Binary<br/>http://localhost:18888]
  OIDCLD --> Config[(oidcld.yaml)]
  OIDCLD --> Users[In-Memory Users]
```

ポイント:
- デフォルトは HTTP (ポート 18888)
- 必要なのは YAML (`oidcld.yaml`) + 生成される鍵ペアのみ
- クリックログインのユーザー選択 UI (パスワード不要)
- プロトタイピングやユニット/統合テストに最適

クイックスタート:
```bash
./oidcld init            # 設定と鍵を生成
./oidcld                 # http://localhost:18888 で起動
open http://localhost:18888/.well-known/openid-configuration
```

HTTPS は後から mkcert で証明書を作成し、`--cert-file/--key-file` で指定して有効化できます。

インストール (Option 1: Go install; Go 1.24+):
```bash
go install github.com/shibukawa/oidcld@latest
```
`$GOBIN` を `PATH` に通してください。

インストール (Option 2: GitHub Releases からダウンロード)
1. [GitHub Releases](https://github.com/shibukawa/oidcld/releases) へアクセス
2. ご利用の OS/アーキテクチャ向けアーカイブをダウンロード
3. (Unix 系) 実行権限付与: `chmod +x oidcld`

現在のリリースバイナリ配布ターゲット:
- `oidcld-linux-amd64.tar.gz`
- `oidcld-linux-arm64.tar.gz`
- `oidcld-darwin-arm64.tar.gz`
- `oidcld-windows-amd64.zip`
- `oidcld-windows-arm64.zip`

チェックサム検証:
```bash
# Linux AMD64 アーカイブの例
archive="oidcld-linux-amd64.tar.gz"
curl -fsSL "https://github.com/shibukawa/oidcld/releases/latest/download/${archive}" -o "${archive}"
curl -fsSL "https://github.com/shibukawa/oidcld/releases/latest/download/SHA256SUMS.txt" -o SHA256SUMS.txt
grep " ${archive}$" SHA256SUMS.txt | sha256sum -c -
```

macOS Gatekeeper 対応 (ダウンロードしたバイナリ向け):
```bash
chmod +x oidcld
xattr -l ./oidcld
xattr -d com.apple.quarantine ./oidcld
```

他リポジトリの GitHub Actions から利用する例 (latest release):

```yaml
- name: oidcld を取得 (Linux/macOS)
  if: runner.os != 'Windows'
  shell: bash
  run: |
    set -euo pipefail
    case "${RUNNER_OS}-${RUNNER_ARCH}" in
      Linux-X64)   archive="oidcld-linux-amd64.tar.gz" ;;
      Linux-ARM64) archive="oidcld-linux-arm64.tar.gz" ;;
      macOS-ARM64) archive="oidcld-darwin-arm64.tar.gz" ;;
      *) echo "unsupported runner: ${RUNNER_OS}-${RUNNER_ARCH}"; exit 1 ;;
    esac
    curl -fsSL "https://github.com/shibukawa/oidcld/releases/latest/download/${archive}" -o "${archive}"
    tar -xzf "${archive}"
    chmod +x oidcld
    echo "${PWD}" >> "${GITHUB_PATH}"

- name: oidcld を取得 (Windows)
  if: runner.os == 'Windows'
  shell: pwsh
  run: |
    switch ("$env:RUNNER_ARCH") {
      "X64" { $archive = "oidcld-windows-amd64.zip" }
      "ARM64" { $archive = "oidcld-windows-arm64.zip" }
      default { throw "unsupported runner architecture: $env:RUNNER_ARCH" }
    }
    Invoke-WebRequest -Uri "https://github.com/shibukawa/oidcld/releases/latest/download/$archive" -OutFile $archive
    Expand-Archive -Path $archive -DestinationPath . -Force
    Add-Content -Path $env:GITHUB_PATH -Value $PWD
```

上記の後続 step で、Unix 系は `oidcld --help`、Windows は `./oidcld.exe --help` を実行できます。

### 2. Docker モード (標準 OIDC)

oidcld と SPA/API をコンテナで実行。チーム/CI で再現性のある環境を構築。

```bash
docker pull ghcr.io/shibukawa/oidcld
```

```mermaid
flowchart TB
  Browser[Browser SPA Container<br/>:5173 or :80] -->|OIDC Flows| OIDCLDContainer[oidcld Container<br/>:18888]
  OIDCLDContainer --> Volume[(Mounted oidcld.yaml)]
```

ポイント:
- `oidcld.yaml` はボリュームで共有 (その他の設定は環境変数で指定可能)
- ヘルスチェックで依存サービスの起動順制御が可能
- ローカルモードと同等のフロー。設定ファイルのホットリロードも可能

Compose 最小例 (抜粋):

```yaml
services:
  oidcld:
    image: ghcr.io/shibukawa/oidcld:latest
    ports:
      - "18888:18888"
    volumes:
      - ./oidcld.yaml:/app/oidcld.yaml:ro
    command: ["serve", "--config", "/app/oidcld.yaml"]
```

使い方:
```bash
./oidcld init                # oidcld.yaml を生成
docker compose up -d         # スタック起動
curl http://localhost:18888/health
```

### 3. EntraID 互換モード (MSAL / Azure スタイルのクレーム)

MSAL 連携向けに Azure AD (EntraID) の振る舞いを模倣します。HTTPS とフラグメントレスポンスが必要です。

```mermaid
flowchart TB
  MSALApp[MSAL-enabled App<br/>HTTPS] -->|Auth Code + PKCE + fragment| OIDCLDEntra["oidcld (entraid-v2 template)<br/>https://localhost:18888"]
  OIDCLDEntra --> Claims["Azure-like Claims<br/>(oid, tid, preferred_username, upn)"]
  OIDCLDEntra --> ConfigEntra[(entraid-v2 template yaml)]
```

ポイント:
- `./oidcld init --template entraid-v2` でスキャフォールド
- `nonce_required` と適切な issuer 形式を強制
- Azure 風のクレーム (例: `oid`, `tid`, `preferred_username`)
- MSAL ライブラリは HTTPS が必須

クイックスタート:
```bash
./oidcld init --template entraid-v2
./oidcld --cert-file localhost.pem --key-file localhost-key.pem
curl -k https://localhost:18888/.well-known/openid-configuration
```

トラブルシューティング:
- `oidcld init` が完了しても `oidcld.yaml` が生成されない (`v0.1.2` のみ) → 新しいリリースへ更新してください。暫定回避策: `oidcld init oidcld.yaml --template standard`
- 不正なオリジンの MSAL エラー → HTTPS と信頼済み証明書 (mkcert インストール) を確認
- リフレッシュトークンが無い → `offline_access` スコープを追加し、設定でリフレッシュを有効化

## CLI サマリー

ローカル開発/テスト向けのコマンドです。MCP は現時点では除外しています。

- `oidcld init`: テンプレートから設定を初期化
  - フラグ: `--template standard|entraid-v1|entraid-v2`, `--tenant-id`, `--https`, `--autocert`, `--acme-server`, `--domains`, `--email`, `--port`, `--issuer`, `--overwrite`

- `oidcld serve`: OIDC サーバーを起動
  - フラグ: `--config oidcld.yaml`, `--port 18888`, `--watch`, `--cert-file`, `--key-file`, `--verbose`
  - 備考: TLS 証明書や autocert が設定されている場合は HTTPS で起動し、issuer も適切に調整されます。`--port` を指定し、issuer のホストがローカル (`localhost`/loopback) の場合は、issuer のポートも同じ値に同期されます。

- `oidcld health`: サーバーヘルスをチェック
  - フラグ: `--url`, `--port`, `--config`, `--timeout`
  - 備考: `--url` を省略すると設定から自動検出。コンテナ環境で `OIDCLD_CONFIG` がある場合は localhost に接続し、自己署名証明書向けに TLS 検証をスキップします。

## セキュリティ上の制約

このプロジェクトは開発/テスト専用です。本番環境では使用しないでください。

- 任意の `client_id` を受け付けます: クライアント登録や許可リストはありません。
- `redirect_uri` のホワイトリストはありません: リクエストの `redirect_uri` を動的に許可します。
- クライアントシークレットは不要/未検証: ローカルテスト専用の挙動です。
- 署名鍵はエフェメラル: 起動時に RSA 鍵を生成し永続化しません。再起動後は過去のトークンは検証できません。
- デフォルトは寛容: SPA 開発を容易にするため CORS やディスカバリを緩めに設定。必要に応じて設定で絞り込んでください。

これらはローカル開発の利便性を最大化するための意図的な設計です。

## 追加ドキュメント

詳細ドキュメント (この README から分離):

- 設定ガイド: [docs/config.ja.md](docs/config.ja.md)
- 他の OAuth/OIDC フロー: [docs/otherflows.ja.md](docs/otherflows.ja.md)

具体的な統合例は `examples/` (React/MSAL, Vue, Device Flow, Client Credentials, autocert など) を参照してください。

#### HTTPS 設定

MSAL ライブラリはセキュリティ上、HTTPS が必須です。OIDCLD を HTTPS で動かすには次の 2 つの方法があります。

**Option 1: 証明書ファイルを使用**

mkcert を使って証明書を作成できます:

```bash
# mkcert で証明書を作成
brew install mkcert  # macOS
mkcert -install
mkcert localhost 127.0.0.1 ::1

# HTTPS で起動
./oidcld --cert-file localhost.pem --key-file localhost-key.pem
```

**Option 2: ACME プロトコルサーバーを使用**

ACME プロトコルにより証明書を自動取得できます。以下はローカル ACME サーバーの例です。

```yaml:compose.yaml
services:
  # myencrypt - Local ACME server for development
  myencrypt.localhost:
    image: ghcr.io/shibukawa/myencrypt:latest
    ports:
      - "14000:80"  # ACME server port
    environment:
      - MYENCRYPT_EXPOSE_PORT=14000  # Required: Host-accessible port
      - MYENCRYPT_PROJECT_NAME=oidcld  # Required: Project name for Docker mode
      - MYENCRYPT_HOSTNAME=myencrypt.localhost  # Required: Hostname for ACME directory URLs
      - MYENCRYPT_INDIVIDUAL_CERT_TTL=168h  # 7 days (7 * 24h)
      - MYENCRYPT_CA_CERT_TTL=19200h
      - MYENCRYPT_ALLOWED_DOMAINS=localhost,*.localhost
      - MYENCRYPT_CERT_STORE_PATH=/data
      - MYENCRYPT_DATABASE_PATH=/data/myencrypt.db
      - MYENCRYPT_LOG_LEVEL=info  # Enable debug logging
    volumes:
      - myencrypt-data:/data
    restart: unless-stopped
  # OIDCLD with myencrypt autocert (TLS-ALPN challenge)
  oidc.localhost:
    # image: oidcld:local
    build: .
    # image: ghcr.io/shibukawa/oidcld:latest
    ports:
      - "8443:443"     # HTTPS OIDC server port (mapped to non-privileged port)
    volumes:
      - ./examples/autocert/config/oidcld.yaml:/app/config.yaml:ro
    environment:
      - OIDCLD_CONFIG=/app/config.yaml
      # Minimal autocert environment variables (TLS-ALPN challenge)
      - OIDCLD_ACME_DOMAIN=oidc.localhost
      - OIDCLD_ACME_DIRECTORY_URL=http://myencrypt.localhost/acme/directory
      - OIDCLD_ACME_CACHE_DIR=/tmp/autocert-cache  # Temporary cache directory (no persistence)
      - OIDCLD_ACME_EMAIL=dev@localhost
      - OIDCLD_ACME_AGREE_TOS=true
      - OIDCLD_ACME_INSECURE_SKIP_VERIFY=true
      - OIDCLD_ACME_RENEWAL_THRESHOLD=1
    command: ["serve", "--config", "/app/config.yaml", "--port", "443"]
    depends_on:
      myencrypt.localhost:
        condition: service_healthy
    restart: unless-stopped
```

#### OIDCLD 向けの MSAL 設定例

```typescript
import { PublicClientApplication } from '@azure/msal-browser';

const msalConfig = {
  auth: {
    clientId: 'your-azure-app-id',
    authority: 'https://localhost:18888',  // HTTPS が必要
    redirectUri: 'https://localhost:3000/callback',
    postLogoutRedirectUri: 'https://localhost:3000/'
  },
  cache: {
    cacheLocation: 'localStorage',
    storeAuthStateInCookie: false,
  }
};

const msalInstance = new PublicClientApplication(msalConfig);

// Login リクエスト
const loginRequest = {
  scopes: ['openid', 'profile', 'email'],
  extraScopesToConsent: ['offline_access']  // リフレッシュトークン用
};
```

## ライセンス

このプロジェクトは GNU Affero General Public License v3.0 (AGPL-3.0) の下でライセンスされています。

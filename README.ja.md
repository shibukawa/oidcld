# ローカル開発用OpenID Connect: OpenID Connect テスト用アイデンティティプロバイダー

![console](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/console.png)

## 用語

このプロジェクトでは、xUnitテストパターンの用語を使用して、その目的と機能を明確に説明しています：

### **フェイク vs モック**
- **フェイク**: 簡略化された動作を持つ実用的な実装で、テストに適しています。フェイクは実際のビジネスロジックを持ちますが、ショートカット（例：データベースの代わりにインメモリストレージ）を取ります。
- **モック**: インタラクションを記録し、期待値をアサートすることで動作を検証するオブジェクト。

### **このプロジェクトは「フェイク」です**
このOpenID Connectアイデンティティプロバイダーは**フェイク**実装です。なぜなら：
- 実際のプロトコル準拠を持つ完全に機能するOpenID Connectサーバーを提供
- 簡略化された実装（インメモリストレージ、テスト証明書、ユーザー選択UI）を使用
- テスト目的で実際の認証フローを有効化
- モックのように特定のインタラクションを検証したり期待値をアサートしたりしない

「フェイク」という用語は、テストシナリオにおけるこのツールの役割を正確に表現しています - 開発およびテスト環境専用に設計された実際の動作するアイデンティティプロバイダーです。

## サービスの目的

### 概要
テストおよび開発目的で設計されたフェイクOpenID Connectアイデンティティプロバイダー（IdP）。成熟した**zitadel/oidcライブラリ**上に構築され、開発とテストに必要なシンプルさを維持しながら、エンタープライズグレードのOpenID Connect準拠を提供します。

### 主な機能
- テスト用の標準準拠OpenID Connect認証フローを提供
- 実際の認証情報なしで簡単なユーザー選択によるログインを有効化
- ローカルおよびテスト環境の開発ワークフローをサポート
- OpenID Connect認証を必要とするアプリケーションのE2Eテストを促進
- Microsoft EntraID/AzureADクライアントおよびMSALライブラリと互換

----

![screenshot](https://raw.githubusercontent.com/shibukawa/oidcld/refs/heads/main/docs/login-screen.png)

**ログイン画面:** パスワードなしのクリックのみのログイン。テストをスムーズにします。特別な**ローカル時のみのログインなしロジック**とはおさらばです。

----

### コア機能
- **標準準拠実装**: 完全なOpenID Connect Core 1.0準拠のためのzitadel/oidc v3ライブラリ上に構築
- **複数のOAuth 2.0/OpenID Connectフロー**: 認可コードフロー、クライアント認証情報フロー、デバイスフロー、リフレッシュトークンフロー
- **レスポンスモードサポート**: クエリモードとフラグメントモード（EntraID/AzureAD互換性に必要）
- **PKCEサポート**: セキュリティ強化のためのProof Key for Code Exchange実装
- **リフレッシュトークンサポート**: 長期セッション用のオプションのリフレッシュトークン生成と検証
- **エンドセッションサポート**: 設定可能なディスカバリ可視性を持つOpenID Connect RP-Initiated Logout
- **HTTPSサポート**: 信頼できるローカル証明書のためのmkcert統合を持つネイティブHTTPSサーバー
- **OpenIDディスカバリ**: 標準準拠の`/.well-known/openid-configuration`エンドポイント
- **カスタムJWTクレーム**: YAML設定でJWTトークンに追加情報をサポート
- **EntraID/AzureAD互換性**: フラグメントモードサポートによる完全なMicrosoftエコシステム統合
- **MCPサーバーモード**: 設定管理と自動化のためのModel Context Protocolサーバー
- **シンプルなユーザー管理**: スコープベースのアクセス制御を持つYAML設定ファイルで定義されたユーザー
- **エンタープライズ対応**: 実戦テスト済みの暗号化実装による本格的なセキュリティ

## デプロイメント

### 環境要件
- 単一バイナリ（Go 1.24で記述）
- データベース不要（インメモリストレージ）
- ユーザー定義用のYAML設定ファイル

### セットアップ手順

#### インストールオプション

**オプション1: Go Get Tool（Go 1.24+）**
```bash
go get -tool github.com/shibukawa/oidcld@latest
```

**オプション2: GitHub Releasesからダウンロード**
1. [GitHubリリースページ](https://github.com/shibukawa/oidcld/releases)にアクセス
2. お使いのオペレーティングシステムに適したバイナリをダウンロード
3. バイナリを実行可能にする（Unix系システムの場合）: `chmod +x oidcld`

**オプション3: Docker**
```bash
docker pull ghcr.io/shibukawa/oidcld
```

#### 設定と起動
1. キーを使用して初期設定を生成: `./oidcld init`
   - 標準OpenID、EntraID v1、またはEntraID v2のオプションを持つインタラクティブセットアップ
   - mkcert証明書生成を持つHTTPS設定
   - 暗号化キーファイル（`.oidcld.key`、`.oidcld.pub.key`）を生成
   - YAML設定ファイル（`oidcld.yaml`）を作成
2. 生成されたYAML設定ファイルでユーザーを設定
3. サービスを開始: `./oidcld` または `./oidcld --config your-config.yaml`
4. HTTPS用: `./oidcld --https`（デフォルトでlocalhost.pem/localhost-key.pemを使用）

### 設定
- **ポート**: 18888（デフォルト）
  - コマンドライン: `--port 8080`
  - 環境変数: `PORT=8080`
- **設定ファイル**: oidcld.yaml（デフォルト）
  - コマンドライン: `--config config.yaml`
- **暗号化キー**: セキュリティのための外部キーファイル
  - 秘密キー: `.oidcld.key`（デフォルト、存在しない場合は実行時に生成）
  - 公開キー: `.oidcld.pub.key`（デフォルト、存在しない場合は実行時に生成）
- **ユーザー設定**: YAML設定ファイルでユーザーを定義

#### YAML設定サンプル
```yaml
# OpenID Connect IdP設定
oidcld:
  # iss: "http://localhost:18888"
  valid_audiences:
    - "my-client-app"
    - "another-app"
  pkce_required: false
  nonce_required: false
  expired_in: 3600  # トークン有効期限（秒）
  # algorithm: "RS256"  # オプション、デフォルトはRS256
  # 標準スコープ（openid、profile、email）は常に含まれます
  valid_scopes:  # オプションのカスタムスコープ
    - "admin"
    - "read"
    - "write"
  # private_key_path: ".oidcld.key"      # オプション、空の場合は実行時に生成
  # public_key_path: ".oidcld.pub.key"   # オプション、空の場合は実行時に生成
  refresh_token_enabled: true             # リフレッシュトークンサポートを有効化
  refresh_token_expiry: 86400             # リフレッシュトークン有効期限（秒、24時間）
  end_session_enabled: true               # ログアウト/エンドセッション機能を有効化
  end_session_endpoint_visible: true      # ディスカバリでend_session_endpointを表示（オプション）

# EntraID/AzureAD互換性設定
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"

# SPA開発用のCORS（Cross-Origin Resource Sharing）設定
cors:
  enabled: true                           # CORSサポートを有効化
  allowed_origins:                        # 許可されたオリジンのリスト
    - "http://localhost:3000"             # React/Vue開発サーバー
    - "http://localhost:5173"             # Vite開発サーバー
    - "https://localhost:3000"            # HTTPS開発サーバー
  allowed_methods:                        # 許可されたHTTPメソッド
    - "GET"
    - "POST"
    - "OPTIONS"
  allowed_headers:                        # 許可されたリクエストヘッダー
    - "Content-Type"
    - "Authorization"
    - "Accept"

# ユーザー定義
users:
  user1:
    display_name: "田中太郎"
    extra_valid_scopes:
      - "admin"
      - "read"
      - "write"
    extra_claims:
      email: "tanaka@example.com"
      role: "admin"
      department: "engineering"
  user2:
    display_name: "佐藤花子"
    extra_valid_scopes:
      - "read"
    extra_claims:
      email: "sato@example.com"
      role: "user"
      department: "marketing"
  testuser:
    display_name: "テストユーザー"
    extra_claims:
      email: "test@example.com"
      groups: ["testers", "developers"]
```

### サービスの実行
```bash
./oidcld                           # OpenID Connectサーバーを開始（デフォルト設定: oidcld.yaml）
./oidcld --config config.yaml     # カスタム設定ファイルで開始
./oidcld --watch                   # ファイル変更時の自動設定リロードで開始
./oidcld -w --config config.yaml  # カスタム設定とウォッチモードで開始
./oidcld --https                   # HTTPSで開始（localhost.pem/localhost-key.pemを使用）
./oidcld --https --cert-file cert.pem --key-file key.pem  # カスタム証明書で開始
./oidcld mcp                       # MCPサーバーとして開始（stdin/stdoutモード）
./oidcld mcp --port 3001          # MCP HTTPサーバーとして開始
```

#### mkcertを使用したHTTPSセットアップ

信頼できる証明書を使用したテスト用HTTPS：

```bash
# mkcertをインストール（macOS）
brew install mkcert

# mkcertをインストール（Linux/Windows）
# 参照: https://github.com/FiloSottile/mkcert#installation

# HTTPSとmkcertで初期化
./oidcld init --https --mkcert

# mkcertを使用したEntraIDテンプレート（HTTPSは自動）
./oidcld init --template entraid-v2 --mkcert

# またはインタラクティブウィザードを使用
./oidcld init
# 選択: 標準OpenID ConnectまたはEntraIDテンプレート
# 標準の場合: HTTPSを有効化: y
# EntraIDの場合: HTTPSは自動的に有効化
# mkcert証明書を生成: y

# HTTPSサーバーを開始
./oidcld --https
```

#### ウォッチモード

`--watch`（`-w`）オプションは、設定ファイルが変更されたときの自動設定リロードを有効にします：

```bash
./oidcld --watch
# または
./oidcld -w
```

**機能:**
- **自動リロード**: ファイルが変更されると設定が自動的にリロードされます
- **デバウンス更新**: 複数の迅速な変更は過度なリロードを避けるためにデバウンスされます
- **検証**: 無効な設定は拒否され、以前の有効な設定が保持されます
- **実行時安全性**: 発行者URLや署名アルゴリズムなどの重要な設定は実行時に変更できません
- **カラー出力**: 設定詳細とともにリロード成功/失敗の明確でカラフルなフィードバック
- **詳細ログ**: より良い可読性のための視覚的インジケーターと絵文字

**実行時に変更可能なもの:**
- ユーザー定義とクレーム
- 有効なオーディエンスとスコープ
- トークン有効期限設定
- PKCEとnonce要件
- リフレッシュトークン設定

**再起動が必要なもの:**
- 発行者URL
- 署名アルゴリズム
- ポート番号
- 証明書/キーファイル

**ワークフロー例:**
1. ウォッチモードでサーバーを開始: `./oidcld --watch`
2. `oidcld.yaml`を編集して新しいユーザーを追加または設定を変更
3. ファイルを保存 - 設定が自動的にリロードされます
4. リロード確認と検証エラーのログを確認

**カラー出力例:**
- 🚀 緑色のサーバー起動メッセージ
- 🔄 シアン色の設定リロードメッセージ
- ✅ 緑色の成功メッセージ
- ❌ 赤色のエラーメッセージ
- 🌐 カラーコード化されたステータスコードを持つHTTPリクエストログ
### リフレッシュトークンサポート

リフレッシュトークンが有効な場合、トークンエンドポイントはアクセストークンとリフレッシュトークンの両方を返します：

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def50200e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### リフレッシュトークンの使用

アクセストークンをリフレッシュするには、トークンエンドポイントにPOSTリクエストを送信します：

```bash
curl -X POST http://localhost:18888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=def50200e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

#### 設定オプション

```yaml
oidcld:
  refresh_token_enabled: true    # リフレッシュトークン生成を有効/無効
  refresh_token_expiry: 86400    # リフレッシュトークン有効期限（秒、デフォルト: 24時間）
  expired_in: 3600               # アクセストークン有効期限（秒、デフォルト: 1時間）
```

### ログアウト / エンドセッションサポート

OpenID Connectテストアイデンティティプロバイダーは、OpenID Connect RP-Initiated Logout仕様に従って、エンドセッションエンドポイントを通じたログアウト機能をサポートしています。

#### 設定

```yaml
oidcld:
  end_session_enabled: true               # ログアウト/エンドセッション機能を有効化
  end_session_endpoint_visible: true      # ディスカバリでend_session_endpointを表示（オプション）
```

**設定オプション:**
- `end_session_enabled`: ログアウト機能が利用可能かどうかを制御
- `end_session_endpoint_visible`: `end_session_endpoint`が`.well-known/openid-configuration`ディスカバリドキュメントに表示されるかどうかを制御

**注意:** `end_session_endpoint_visible`が`false`に設定されていても、ログアウト機能は利用可能です。これにより、ディスカバリドキュメントで宣伝されないプライベートログアウトエンドポイントが可能になります。

#### ディスカバリエンドポイント

`end_session_endpoint_visible`が`true`の場合、ディスカバリエンドポイントには以下が含まれます：

```json
{
  "end_session_endpoint": "http://localhost:18888/end_session",
  ...
}
```

#### ログアウトエンドポイントの使用

**GETリクエスト:**
```bash
curl "http://localhost:18888/end_session?id_token_hint=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&post_logout_redirect_uri=https://example.com/logout&state=xyz123"
```

**POSTリクエスト:**
```bash
curl -X POST http://localhost:18888/end_session \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id_token_hint=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&post_logout_redirect_uri=https://example.com/logout&state=xyz123"
```

#### パラメータ

- `id_token_hint`（オプション）: 終了するユーザーセッションを識別するIDトークン
- `post_logout_redirect_uri`（オプション）: ログアウト後にリダイレクトするURI
- `state`（オプション）: ログアウトリクエストとコールバック間で状態を維持する不透明な値

#### ログアウト動作

1. **トークン無効化**: ユーザーのすべてのアクセストークン、リフレッシュトークン、認可コードが無効化されます
2. **セッション終了**: ユーザーセッションデータがクリアされます
3. **リダイレクト処理**: 
   - `post_logout_redirect_uri`が提供された場合、ユーザーはそこにリダイレクトされます
   - リダイレクトURIが提供されない場合、ログアウト成功ページが表示されます
4. **状態保持**: `state`パラメータはリダイレクトで返されます

#### セキュリティ機能

- **URI検証**: ポストログアウトリダイレクトURIはセキュリティのために検証されます
- **トークン検証**: IDトークンヒントは検証されますが、無効なトークンはログアウトを妨げません
- **エラー処理**: 無効なリクエストに対する適切なエラーレスポンス
- **HTTPSサポート**: HTTPとHTTPSの両方のリダイレクトURIをサポート

#### ログアウト成功ページの例

`post_logout_redirect_uri`が提供されない場合、ユーザーはログアウト操作を確認するスタイル付き成功ページを見ます。
### シングルページアプリケーション用のCORSサポート

OpenID Connectテストアイデンティティプロバイダーは、React、Vue.js、Angularアプリケーションなどのブラウザベースのシングルページアプリケーション（SPA）用の包括的なCross-Origin Resource Sharing（CORS）サポートを含んでいます。

#### CORSが必要な理由

異なるポートやドメインで実行されているブラウザベースのアプリケーション（例：React開発サーバー用の`http://localhost:3000`）は、OIDCサーバー（例：`http://localhost:18888`）にリクエストを送信するためにCORSヘッダーが必要です。CORSがないと、ブラウザはセキュリティ上の理由でこれらのリクエストをブロックします。

#### CORS設定

CORSは新しい設定で**デフォルトで有効**になっており、一般的な開発サーバーポートが含まれています：

```yaml
# SPA開発用のCORS（Cross-Origin Resource Sharing）設定
cors:
  enabled: true                           # CORSサポートを有効化
  allowed_origins:                        # 許可されたオリジンのリスト
    - "http://localhost:3000"             # Reactデフォルト開発サーバーポート
    - "http://localhost:5173"             # Viteデフォルト開発サーバーポート
    - "http://localhost:4173"             # Viteプレビューサーバーポート
    - "http://localhost:8080"             # 代替開発サーバーポート
    - "https://localhost:3000"            # HTTPS開発サーバー
    - "https://localhost:5173"            # HTTPS Vite開発サーバー
  allowed_methods:                        # 許可されたHTTPメソッド
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
    - "HEAD"
  allowed_headers:                        # 許可されたリクエストヘッダー
    - "Content-Type"
    - "Authorization"
    - "Accept"
    - "Origin"
    - "X-Requested-With"
```

#### CORS設定オプション

- **`enabled`**: CORSサポートを有効または無効にする（デフォルト: `true`）
- **`allowed_origins`**: リクエストを許可されたオリジンのリスト
  - セキュリティのために特定のURLを使用: `"http://localhost:3000"`
  - ワイルドカードには`"*"`を使用（テスト環境では推奨されません）
- **`allowed_methods`**: CORSリクエストで許可されたHTTPメソッド
- **`allowed_headers`**: CORSリクエストで許可されたリクエストヘッダー

#### 一般的な開発サーバーポート

デフォルト設定には一般的な開発サーバーポートが含まれています：

| フレームワーク/ツール | デフォルトポート | HTTPSポート |
|----------------|--------------|------------|
| **React** (Create React App) | `3000` | `3000` |
| **Vite** (Vue, React, etc.) | `5173` | `5173` |
| **Vite Preview** | `4173` | `4173` |
| **Webpack Dev Server** | `8080` | `8080` |
| **Angular CLI** | `4200` | `4200` |

#### カスタムオリジンの追加

独自のアプリケーションオリジンを追加するには：

```yaml
cors:
  enabled: true
  allowed_origins:
    - "http://localhost:3000"             # 既存を保持
    - "https://myapp-staging.example.com" # ステージング環境ドメインを追加
    - "http://localhost:4200"             # Angular開発サーバーを追加
    - "http://192.168.1.100:3000"         # ネットワークアクセスを追加
```

#### CORSセキュリティ機能

- **オリジン検証**: 明示的に許可されたオリジンのみがCORSヘッダーを受信
- **プリフライトサポート**: OPTIONSプリフライトリクエストを自動的に処理
- **認証情報サポート**: `Access-Control-Allow-Credentials: true`を含む
- **ヘッダー検証**: 指定されたヘッダーのみがリクエストで許可される

#### CORSのテスト

curlを使用してCORS機能をテストできます：

```bash
# プリフライトリクエストをテスト
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS \
     http://localhost:18888/.well-known/openid-configuration

# Originヘッダーを使用した実際のリクエストをテスト
curl -H "Origin: http://localhost:3000" \
     http://localhost:18888/.well-known/openid-configuration
```

#### CORSトラブルシューティング

**一般的な問題:**

1. **ブラウザコンソールでのCORSエラー**
   ```
   Access to fetch at 'http://localhost:18888/...' from origin 'http://localhost:3000' 
   has been blocked by CORS policy
   ```
   **解決策**: 設定の`allowed_origins`にオリジンを追加

2. **CORSヘッダーの欠如**
   - 設定で`cors.enabled: true`であることを確認
   - オリジンが`allowed_origins`リストにあることを確認
   - 設定変更後にサーバーを再起動

3. **プリフライトリクエストの失敗**
   - `allowed_methods`に`OPTIONS`があることを確認
   - 必要なヘッダーが`allowed_headers`にあることを確認

#### フレームワーク固有の例

**oidc-client-tsを使用したReact:**
```typescript
// Reactで追加のCORS設定は不要
// oidcld.yamlに開発サーバーポートがあることを確認するだけ
const oidcConfig = {
  authority: 'http://localhost:18888',
  client_id: 'your-client-id',
  redirect_uri: 'http://localhost:3000/callback'
};
```

**oidc-client-tsを使用したVue.js:**
```typescript
// Vite開発サーバー（ポート5173）はデフォルトで含まれています
const userManager = new UserManager({
  authority: 'http://localhost:18888',
  client_id: 'your-client-id',
  redirect_uri: 'http://localhost:5173/callback'
});
```

**Angular:**
```yaml
# oidcld.yamlにAngularのデフォルトポートを追加
cors:
  allowed_origins:
    - "http://localhost:4200"  # Angular CLIデフォルト
```

#### テスト/ステージング環境用のCORS設定

テスト/ステージング環境でのデプロイメントでは、許可されたオリジンを具体的に指定してください：

```yaml
cors:
  enabled: true
  allowed_origins:
    - "https://myapp-staging.example.com"
    - "https://test.mydomain.com"
  # ステージング/テスト環境ではlocalhostエントリを削除
```

**テスト用のセキュリティベストプラクティス:**
- `"*"`ワイルドカードの代わりに特定のオリジンを使用
- 可能な場合はHTTPSオリジンを使用
- 許可されたオリジンを定期的に確認・更新
- ステージング/テスト設定から開発オリジンを削除

## MCPサーバー統合

### MCPサーバーのインストール

OpenID Connectテストアイデンティティプロバイダーは、AIアシスタントや開発ツールに設定管理機能を提供するMCP（Model Context Protocol）サーバーとして実行できます。

#### Amazon Q Developer
MCP設定に追加：
```json
{
  "mcpServers": {
    "oidcld": {
      "command": "/path/to/oidcld",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

#### Claude Desktop
`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）または同等のファイルに追加：
```json
{
  "mcpServers": {
    "oidcld": {
      "command": "/path/to/oidcld",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

#### VS Code with MCP Extension
VS Code MCP設定に追加：
```json
{
  "mcp.servers": [
    {
      "name": "oidcld",
      "command": "/path/to/oidcld",
      "args": ["mcp"],
      "cwd": "/path/to/your/project"
    }
  ]
}
```

#### HTTPモード（Webベースツール用）
```bash
./oidcld mcp --port 3001
```
その後、MCPクライアントを`http://localhost:3001`に接続するよう設定

### 利用可能なMCPツール

MCPサーバーとして実行する場合、以下のツールが利用可能です：

- **`oidcld_init`** - OpenID Connect設定を初期化
- **`oidcld_query_config`** - 現在の設定を照会
- **`oidcld_add_user`** - 新しいテストユーザーを追加
- **`oidcld_query_users`** - 設定されたすべてのユーザーをリスト
- **`oidcld_modify_config`** - 設定を更新
- **`oidcld_generate_compose`** - Docker Compose設定を生成

### 利用可能なMCPリソース

- **`config://current`** - 現在のOpenID Connect設定
- **`users://list`** - 設定されたすべてのユーザーのリスト
- **`compose://template`** - Docker Composeテンプレート

### ヘルスチェック
- **エンドポイント**: `GET /health`
- **期待されるレスポンス**: サービスステータス確認

## CI/CDと開発

### GitHub Actionsワークフロー

このプロジェクトには包括的なCI/CDパイプラインが含まれています：

#### **継続的インテグレーション（`ci.yml`）**
- **トリガー**: プルリクエストとmain/developブランチへのプッシュ
- **ジョブ**:
  - **Test**: レース検出とカバレッジレポートを使用したすべてのユニットテストを実行
  - **Lint**: golangci-lintを使用したコード品質チェック
  - **Security**: Gosecを使用したセキュリティスキャン
- **機能**:
  - より高速なビルドのためのGoモジュールキャッシュ
  - Codecovへのカバレッジレポート
  - 静的解析とセキュリティスキャン
  - セキュリティ発見のためのSARIFアップロード

#### **リリースパイプライン（`release.yml`）**
- **トリガー**: Gitタグ（v*）
- **マルチプラットフォームバイナリビルド**:
  - Windows AMD64（.exe）
  - macOS ARM64（Apple Silicon）
  - Linux AMD64
  - Linux ARM64
- **Dockerマルチアーキテクチャイメージ**:
  - `linux/amd64`と`linux/arm64`
  - GitHub Container Registryに公開
  - 自動タグ付け（latest、semver）
- **GitHubリリース**:
  - 自動リリース作成
  - バイナリ添付（zip/tar.gz）
  - 生成されたリリースノート

#### **依存関係管理**
- **Dependabot**: 自動依存関係更新
- **自動マージ**: パッチ/マイナー更新の安全な自動マージ
- **週次スケジュール**: 依存関係を最新に保つ

### 開発ワークフロー

1. **プルリクエスト**: PRを作成 → CIがテストとチェックを実行
2. **コードレビュー**: 手動レビュー + 自動チェック
3. **マージ**: mainへのマージが追加検証をトリガー
4. **リリース**: タグを作成 → 自動ビルドとリリース

### Docker使用法

```bash
# 最新イメージをプル
docker pull ghcr.io/shibukawa/oidcld:latest

# デフォルト設定で実行
docker run -p 18888:18888 ghcr.io/shibukawa/oidcld:latest

# カスタム設定で実行
docker run -p 18888:18888 -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/shibukawa/oidcld:latest serve --config /app/config.yaml

# ヘルスチェック
docker run --rm ghcr.io/shibukawa/oidcld:latest health --url http://host.docker.internal:18888
```

### 高度なDockerビルド

プロジェクトにはBuildX機能を使用した最適化されたDockerfileが含まれています：

```bash
# ローカル開発用ビルド（単一プラットフォーム）
./scripts/build-docker.sh --load

# キャッシュを使用したマルチプラットフォームビルド
./scripts/build-docker.sh --platforms linux/amd64,linux/arm64 \
  --cache-from type=gha --cache-to type=gha,mode=max

# レジストリにビルドしてプッシュ
./scripts/build-docker.sh --name ghcr.io/shibukawa/oidcld \
  --tag v1.0.0 --push
```

**BuildX機能:**
- **キャッシュマウント**: 効率的なGoモジュールとビルドキャッシュ
- **バインドマウント**: コピーなしでマウントされたソースコード
- **マルチプラットフォーム**: ネイティブARM64とAMD64サポート
- **Distrolessベース**: 最大セキュリティを持つ安全な最小ランタイム環境
- **レイヤー最適化**: 最大セキュリティを持つ最小イメージサイズ

### ソースからビルド

```bash
# リポジトリをクローン
git clone https://github.com/shibukawa/oidcld.git
cd oidcld

# バイナリをビルド
go build -o oidcld .

# テストを実行
go test ./...

# Dockerイメージをビルド
docker build -t oidcld .
# またはビルドスクリプトを使用
./scripts/build-docker.sh --load
```

### 開発ツール

**Dockerビルドスクリプト:**
```bash
./scripts/build-docker.sh --help    # 使用法を表示
./scripts/build-docker.sh --load    # ローカル使用用にビルド
./scripts/build-docker.sh --push    # マルチプラットフォームをビルドしてプッシュ
```

## ライセンス

このプロジェクトはGNU Affero General Public License v3.0（AGPL-3.0）の下でライセンスされています。

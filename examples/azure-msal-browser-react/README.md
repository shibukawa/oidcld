# Azure MSAL Browser React Example

A comprehensive React TypeScript example demonstrating OpenID Connect authentication using Azure MSAL Browser library with the oidcld test identity provider.

## Features

- **React 18** with TypeScript and Vite
- **Azure MSAL Browser** (@azure/msal-browser) for OpenID Connect authentication
- **MSAL React** (@azure/msal-react) for React-specific hooks and components
- **Tailwind CSS** for modern, utility-first styling
- **Redirect-based authentication** flows (popup mode removed for simplicity)
- **Silent token acquisition** with fallback to interactive redirect
- **UserInfo endpoint** integration
- **Logout functionality** with redirect
- **Responsive design** with Tailwind CSS utilities
- **TypeScript** for type safety
- **EntraID v2.0 compatibility** with proper claims structure
- **HTTPS support** with mkcert certificates for proper MSAL compatibility

## Prerequisites

- Node.js 18+ and npm
- Running oidcld server with HTTPS (recommended)
- mkcert for generating trusted local certificates

### Setting up HTTPS with mkcert

For the best experience with MSAL, use HTTPS:

```bash
# Install mkcert (macOS)
brew install mkcert

# Install mkcert (Linux/Windows)
# See: https://github.com/FiloSottile/mkcert#installation

# Initialize oidcld with HTTPS and mkcert
./oidcld init --mkcert

# Or use EntraID template (HTTPS automatic, mkcert optional)
./oidcld init --template entraid-v2 --mkcert

# Or use the interactive wizard
./oidcld init
# Select: Standard OpenID Connect or EntraID/AzureAD v2.0
# For Standard: Enable HTTPS: y
# For EntraID: HTTPS is automatically enabled
# Generate mkcert certificates: y
```

## Quick Start

1. **Start the oidcld server with HTTPS:**
   ```bash
   cd ../..
    ./oidcld serve --cert-file localhost.pem --key-file localhost-key.pem
   ```
   
   Or if you have custom certificate paths:
   ```bash
    ./oidcld serve --cert-file localhost.pem --key-file localhost-key.pem
   ```
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```

4. **Open your browser:**
   Navigate to `http://localhost:5173`

## Configuration

The application is configured in `src/authConfig.ts`:

```typescript
export const msalConfig: Configuration = {
    auth: {
        clientId: "my-client-app",
        authority: "https://localhost:18888",
        redirectUri: "http://localhost:5173",
        postLogoutRedirectUri: "http://localhost:5173"
    },
    // ... additional configuration
};
```

### Key Configuration Options

- **clientId**: Must match a user in oidcld.yaml configuration
- **authority**: OIDC server URL (oidcld server)
- **redirectUri**: Where to redirect after authentication
- **scopes**: Requested permissions (openid, profile, email, read, write)

## Usage

### Authentication Flow

1. **Sign In**: Click "Sign In" to redirect to the authentication page
2. **User Selection**: Choose a user from the oidcld user selection page
3. **Profile Display**: View user information and claims after redirect back
4. **Sign Out**: Use redirect logout to clear session

### Components

#### `SignInButton`
- Provides redirect-based login
- Uses MSAL React hooks for authentication
- Configured for OIDC protocol mode

#### `SignOutButton`
- Handles logout with redirect method
- Clears authentication state and redirects to home

#### `ProfileData`
- Displays user account information from MSAL
- Fetches additional user info from UserInfo endpoint
- Shows all available claims and tokens

#### `PageLayout`
- Main layout component with navigation
- Conditional rendering based on authentication state
- Welcome message for unauthenticated users

### MSAL Integration

```typescript
// Authentication check
const { accounts, instance } = useMsal();
const account = accounts[0];

// Silent token acquisition
const response = await instance.acquireTokenSilent({
    scopes: ["openid", "profile", "email"],
    account: account
});

// Interactive token acquisition (fallback with redirect)
await instance.acquireTokenRedirect({
    scopes: ["openid", "profile", "email"],
    account: account
});
```

## API Integration

### UserInfo Endpoint

The example demonstrates calling the oidcld UserInfo endpoint:

```typescript
const userInfoResponse = await fetch("https://localhost:18888/userinfo", {
    headers: {
        Authorization: `Bearer ${accessToken}`
    }
});
```

### Token Management

- **Silent Acquisition**: Attempts to get tokens without user interaction
- **Interactive Fallback**: Uses redirect when silent acquisition fails
- **Error Handling**: Proper error handling for authentication failures
- **OIDC Protocol**: Configured for OIDC mode to work with HTTP authorities

## Default oidcld Configuration

Works with EntraID v2.0 compatible configuration:

```yaml
# EntraID v2.0 compatible mode
oidcld:
  iss: "https://localhost:18888"
  pkce_required: true
  nonce_required: true

# EntraID/AzureAD v2.0 compatibility settings
entraid:
  tenant_id: "12345678-1234-1234-1234-123456789abc"
  version: "v2"

users:
  admin:
    display_name: "Administrator"
    extra_claims:
      email: "admin@example.com"
      preferred_username: "admin@example.com"
      upn: "admin@example.com"
      oid: "00000000-0000-0000-0000-000000000001"
      tid: "12345678-1234-1234-1234-123456789abc"
      roles: ["GlobalAdmin", "UserAdmin"]
  user:
    display_name: "Regular User"
    extra_claims:
      email: "user@example.com"
      preferred_username: "user@example.com"
      upn: "user@example.com"
      oid: "00000000-0000-0000-0000-000000000002"
      roles: ["User"]
```

### EntraID v2.0 Features

This configuration provides EntraID/AzureAD v2.0 compatible claims:
- **oid**: Object ID (unique user identifier)
- **tid**: Tenant ID
- **upn**: User Principal Name
- **preferred_username**: Email-based username
- **roles**: User roles array
- **groups**: Group memberships
- **user_type**: Guest vs Member distinction

## Development

### Available Scripts

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run preview      # Preview production build
npm run lint         # Run ESLint
```

### Project Structure

```
src/
├── components/
│   ├── SignInButton.tsx     # Login functionality
│   ├── SignOutButton.tsx    # Logout functionality
│   ├── ProfileData.tsx      # User profile display
│   └── PageLayout.tsx       # Main layout component
├── authConfig.ts            # MSAL configuration
├── App.tsx                  # Main application component
├── App.css                  # Application styles
└── main.tsx                 # Application entry point
```

### TypeScript Integration

The example uses TypeScript for:
- **Type Safety**: Proper typing for MSAL objects and responses
- **IntelliSense**: Better development experience
- **Error Prevention**: Compile-time error checking
- **Interface Definitions**: Clear contracts for data structures

## Customization

### Styling

The application uses Tailwind CSS for styling:
- **Utility-first CSS**: Rapid UI development with utility classes
- **Responsive design**: Mobile-first responsive utilities
- **Component styling**: Consistent design system with Tailwind classes
- **Color-coded sections**: Visual organization of different claim types
- **Interactive elements**: Hover states and focus management
- **Modern aesthetics**: Clean, professional interface design

### Authentication Options

You can customize:
- **Scopes**: Additional permissions
- **Claims**: Extra user information
- **Logout behavior**: Post-logout redirects
- **Authority configuration**: Known authorities for HTTP development

### Error Handling

The example includes comprehensive error handling for:
- **Network failures**
- **Authentication errors**
- **Token acquisition failures**
- **API call errors**

## Standards Compliance

This example demonstrates:
- **OpenID Connect** standard compliance
- **OAuth 2.0** authorization code flow with PKCE
- **Microsoft Authentication Library** best practices
- **React** modern patterns and hooks
- **TypeScript** strict type checking

## Troubleshooting

### Common Issues

1. **Authority URI Insecure Errors**: The example is configured with `knownAuthorities` and `protocolMode: "OIDC"` to allow HTTP authorities for development
2. **Token Errors**: Check that scopes match oidcld configuration
3. **Redirect Issues**: Verify redirect URIs match exactly
4. **Network Errors**: Confirm oidcld server is running on port 18888

### Debug Mode

Enable MSAL logging in `authConfig.ts`:

```typescript
system: {
    loggerOptions: {
        loggerCallback: (level, message, containsPii) => {
            console.log(message);
        }
    }
}
```

## Dependencies

### Core Dependencies
- **@azure/msal-browser**: Microsoft Authentication Library for browsers
- **@azure/msal-react**: React wrapper for MSAL Browser
- **react**: React library
- **react-dom**: React DOM rendering

### Development Dependencies
- **@vitejs/plugin-react**: Vite React plugin
- **typescript**: TypeScript compiler
- **@types/react**: React type definitions
- **@types/react-dom**: React DOM type definitions
- **tailwindcss**: Utility-first CSS framework
- **@tailwindcss/postcss**: PostCSS plugin for Tailwind CSS
- **postcss**: CSS post-processor
- **autoprefixer**: CSS vendor prefixing

## License

This example is part of the oidcld project and follows the same AGPL-3.0 license.

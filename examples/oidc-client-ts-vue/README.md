# OpenID Connect for Local Development - Vue.js Demo with Tailwind CSS

A modern Vue.js application demonstrating OpenID Connect authentication with a beautiful, responsive design using Tailwind CSS.

## Features

- **Modern UI**: Built with Tailwind CSS for a professional, responsive design
- **OpenID Connect**: Full OIDC authentication flow implementation
- **Vue 3**: Latest Vue.js with Composition API
- **TypeScript**: Type-safe development
- **Responsive**: Mobile-first design that works on all devices
- **Glassmorphism**: Modern glass-like UI effects
- **Accessibility**: WCAG compliant with proper focus management

## Design Highlights

- **Gradient backgrounds** with glassmorphism effects
- **Professional color palette** with consistent theming
- **Smooth animations** and hover effects
- **Mobile-responsive** layout with adaptive breakpoints
- **Loading states** with progress indicators
- **Status indicators** with animated elements

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn
- OpenID Connect Identity Provider running on `http://localhost:18888`

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

### Configuration

The application is configured to work with the OpenID Connect for Local Development identity provider:

- **Authority**: `http://localhost:18888`
- **Client ID**: `test-client`
- **Redirect URI**: `http://localhost:5173/callback`
- **Scopes**: `openid profile email`

## Project Structure

```
src/
├── components/
├── views/
│   ├── HomeView.vue      # Landing page with features
│   ├── ProfileView.vue   # User profile and token info
│   └── CallbackView.vue  # Authentication callback
├── authService.ts        # OIDC client configuration
├── router.ts            # Vue Router setup
├── styles.css           # Tailwind CSS and custom styles
└── main.ts              # Application entry point
```

## Tailwind CSS Setup

This project uses Tailwind CSS v3 with PostCSS for styling:

- **Base styles**: Custom gradient backgrounds and smooth scrolling
- **Components**: Reusable glass effect and gradient utilities
- **Utilities**: Custom classes for common patterns
- **Responsive**: Mobile-first breakpoints

### Custom Utilities

- `.glass` - Glassmorphism effect with backdrop blur
- `.gradient-text` - Gradient text effect
- `.btn-gradient` - Gradient button styling

## Authentication Flow

1. **Home Page**: Welcome screen with authentication status
2. **Login**: Redirects to OpenID Connect provider
3. **Callback**: Processes authentication response
4. **Profile**: Displays user information and token details
5. **Logout**: Clears session and redirects

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Docker Setup (Recommended)

The easiest way to run this demo is using Docker Compose, which starts both the Vue.js application and the OIDC provider together.

### Quick Start with Docker

```bash
# Start the complete demo environment
./start-demo.sh

# Or manually with Docker Compose
docker compose up

# Stop the demo
docker compose down
```

This will start:
- **Vue.js Application**: http://localhost:5173
- **OIDC Provider**: http://localhost:18888
- **4 Demo Users**: admin, user, developer, and guest accounts

See [DOCKER.md](./DOCKER.md) for detailed Docker setup instructions.

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build

### Customization

The design system is built with Tailwind CSS, making it easy to customize:

1. **Colors**: Update the color palette in `tailwind.config.js`
2. **Spacing**: Modify spacing scale in Tailwind configuration
3. **Components**: Add new utility classes in `styles.css`
4. **Breakpoints**: Customize responsive breakpoints

## License

This example is part of the OpenID Connect for Local Development project.

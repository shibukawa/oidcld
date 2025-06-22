# syntax=docker/dockerfile:1

FROM node:20-alpine AS builder

WORKDIR /app

# Cache package.json and package-lock.json
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    npm ci --only=production

# Build the application
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=bind,target=. \
    npm run build

FROM nginx:alpine

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

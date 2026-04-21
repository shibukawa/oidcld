# syntax=docker/dockerfile:1

ARG NODE_VERSION=24.1.0

FROM node:${NODE_VERSION}-alpine AS build

# Re-declare build args inside the build stage so they are available to ENV and RUN
ARG VITE_OIDC_AUTHORITY
ARG VITE_OIDC_CLIENT_ID
ARG VITE_OIDC_REDIRECT_URI
ARG VITE_OIDC_SCOPES
ARG VITE_OIDC_POST_LOGOUT_REDIRECT_URI
ARG VITE_APP_MODE
ARG VITE_API_BASE_PATH
ARG VITE_PEER_APP_URL
ARG VITE_APP_TITLE
ARG VITE_APP_DESCRIPTION

# Provide VITE_* build args to the build stage so Vite can embed them
ENV VITE_OIDC_AUTHORITY=${VITE_OIDC_AUTHORITY}
ENV VITE_OIDC_CLIENT_ID=${VITE_OIDC_CLIENT_ID}
ENV VITE_OIDC_REDIRECT_URI=${VITE_OIDC_REDIRECT_URI}
ENV VITE_OIDC_SCOPES=${VITE_OIDC_SCOPES}
ENV VITE_OIDC_POST_LOGOUT_REDIRECT_URI=${VITE_OIDC_POST_LOGOUT_REDIRECT_URI}
ENV VITE_APP_MODE=${VITE_APP_MODE}
ENV VITE_API_BASE_PATH=${VITE_API_BASE_PATH}
ENV VITE_PEER_APP_URL=${VITE_PEER_APP_URL}
ENV VITE_APP_TITLE=${VITE_APP_TITLE}
ENV VITE_APP_DESCRIPTION=${VITE_APP_DESCRIPTION}

WORKDIR /usr/src/app

RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci

COPY . .

RUN npm run build

FROM nginx:alpine

COPY --from=build /usr/src/app/dist /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

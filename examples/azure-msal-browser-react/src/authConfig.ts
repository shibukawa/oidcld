import type { Configuration, RedirectRequest } from "@azure/msal-browser";
import { LogLevel, ProtocolMode } from "@azure/msal-browser";

const browserOrigin = typeof window !== "undefined" ? window.location.origin : "http://localhost:5173";
const defaultAuthority = "https://localhost:18888";
const tenantId = "12345678-1234-1234-1234-123456789abc";
const defaultRedirectUri = `${browserOrigin}/redirect.html`;
const defaultPostLogoutRedirectUri = `${browserOrigin}/`;

function buildAuthority(authorityValue: string | undefined, defaultTenantId: string): string {
    const configuredAuthority = (authorityValue || defaultAuthority).replace(/\/$/, "");
    const authorityUrl = new URL(configuredAuthority);
    const pathSegments = authorityUrl.pathname.split("/").filter(Boolean);
    const lastPathSegment = pathSegments[pathSegments.length - 1];

    if (lastPathSegment === "v2.0") {
        pathSegments.pop();
        authorityUrl.pathname = pathSegments.length === 0 ? "/" : `/${pathSegments.join("/")}`;
        return authorityUrl.toString().replace(/\/$/, "");
    }

    if (pathSegments.length === 0) {
        authorityUrl.pathname = `/${defaultTenantId}`;
        return authorityUrl.toString().replace(/\/$/, "");
    }

    return authorityUrl.toString().replace(/\/$/, "");
}

const authority = buildAuthority(import.meta.env.VITE_OIDC_AUTHORITY, tenantId);

/**
 * Configuration object to be passed to MSAL instance on creation. 
 * For a full list of MSAL.js configuration parameters, visit:
 * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-browser/docs/configuration.md 
 */
export const msalConfig: Configuration = {
    auth: {
        clientId: import.meta.env.VITE_OIDC_CLIENT_ID || "default-client-app", // This is the client ID for oidcld
        authority,
        redirectUri: import.meta.env.VITE_OIDC_REDIRECT_URI || defaultRedirectUri,
        postLogoutRedirectUri: import.meta.env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI || defaultPostLogoutRedirectUri,
        knownAuthorities: [new URL(authority).host],
    },
    cache: {
        cacheLocation: "sessionStorage", // This configures where your cache will be stored
    },
    system: {
        protocolMode: ProtocolMode.AAD, // OIDC: v1, AAD(default): v2
        loggerOptions: {
            logLevel: LogLevel.Trace,
            loggerCallback: (level, message, containsPii) => {
                if (containsPii) {
                    return;
                }
                switch (level) {
                    case 0: // LogLevel.Error
                        console.error(message);
                        return;
                    case 1: // LogLevel.Warning
                        console.warn(message);
                        return;
                    case 2: // LogLevel.Info
                        console.info(message);
                        return;
                    case 3: // LogLevel.Verbose
                        console.debug(message);
                        return;
                }
            }
        }
    }
};

/**
 * Scopes you add here will be prompted for user consent during sign-in.
 * By default, MSAL.js will add OIDC scopes (openid, profile, email) to any login request.
 * For more information about OIDC scopes, visit: 
 * https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes
 */
// Build scopes from VITE_OIDC_SCOPES (comma-separated) if provided, otherwise fall back to defaults
const envScopes = import.meta.env.VITE_OIDC_SCOPES as string | undefined;
const defaultScopes = ["openid", "profile", "email", "offline_access"];
export const parsedScopes = envScopes && envScopes.length > 0
    ? envScopes.split(',').map(s => s.trim()).filter(Boolean)
    : defaultScopes;

export const loginRequest: RedirectRequest = {
    scopes: parsedScopes
};

export type DiscoveryDocument = {
    userinfo_endpoint?: string;
};

let discoveryDocumentPromise: Promise<DiscoveryDocument> | null = null;

export function getV2DiscoveryUrl(authorityUrl: string = authority): string {
    const normalizedAuthority = authorityUrl.replace(/\/$/, "");

    if (msalConfig.system?.protocolMode === ProtocolMode.AAD && !normalizedAuthority.endsWith("/v2.0")) {
        return `${normalizedAuthority}/v2.0/.well-known/openid-configuration`;
    }

    return `${normalizedAuthority}/.well-known/openid-configuration`;
}

async function fetchDiscoveryDocument(discoveryUrl: string): Promise<DiscoveryDocument> {
    const response = await fetch(discoveryUrl);
    if (!response.ok) {
        throw new Error(`Failed to fetch discovery document: ${response.status}`);
    }

    return await response.json() as DiscoveryDocument;
}

export async function getV2DiscoveryDocument(): Promise<DiscoveryDocument> {
    if (!discoveryDocumentPromise) {
        discoveryDocumentPromise = fetchDiscoveryDocument(getV2DiscoveryUrl());
    }

    return discoveryDocumentPromise;
}

export async function getUserInfoEndpoint(): Promise<string> {
    const discoveryDocument = await getV2DiscoveryDocument();
    if (!discoveryDocument.userinfo_endpoint) {
        throw new Error("userinfo_endpoint was not present in the discovery document");
    }

    return discoveryDocument.userinfo_endpoint;
}

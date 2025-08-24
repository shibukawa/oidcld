import type { Configuration, PopupRequest } from "@azure/msal-browser";
import { LogLevel } from "@azure/msal-browser";

/**
 * Configuration object to be passed to MSAL instance on creation. 
 * For a full list of MSAL.js configuration parameters, visit:
 * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-browser/docs/configuration.md 
 */
export const msalConfig: Configuration = {
    auth: {
        clientId: "my-client-app", // This is the client ID for oidcld
        // Read authority from Vite environment variable so Docker build args or
        // runtime envs can override the target OIDC server.
        authority: import.meta.env.VITE_OIDC_AUTHORITY || "https://localhost:18888",
        redirectUri: "http://localhost:5173", // Vite dev server default port (HTTP is OK for localhost)
        postLogoutRedirectUri: "http://localhost:5173",
        knownAuthorities: [new URL(import.meta.env.VITE_OIDC_AUTHORITY || "https://localhost:18888").host],
        protocolMode: "OIDC" // Use OIDC protocol mode for better compatibility
    },
    cache: {
        cacheLocation: "sessionStorage", // This configures where your cache will be stored
        storeAuthStateInCookie: false, // Set this to "true" if you are having issues on IE11 or Edge
    },
    system: {
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
export const loginRequest: PopupRequest = {
    scopes: ["openid", "profile", "email", "read", "write"]
};

/**
 * EntraID v2.0 compatible configuration for API calls
 * Using oidcld userinfo endpoint which provides EntraID-compatible claims
 */
const authority = import.meta.env.VITE_OIDC_AUTHORITY || "https://localhost:18888";
export const graphConfig = {
    graphMeEndpoint: `${authority.replace(/\/$/, "")}/userinfo`
};

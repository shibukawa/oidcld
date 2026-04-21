import { useState } from "react";
import { AuthenticatedTemplate, UnauthenticatedTemplate, useMsal } from "@azure/msal-react";
import { SignInButton } from "./SignInButton";
import { SignOutButton } from "./SignOutButton";
import { ProfileData } from "./ProfileData";
import { ApiDemoPanel } from "./ApiDemoPanel";
import { apiBasePath, appDescription, appMode, appTitle, msalConfig, peerAppURL, loginRequest, parsedScopes } from "../authConfig";

/**
 * Renders the navbar component with a sign-in or sign-out button depending on whether or not a user is authenticated
 * @param props 
 */
export const PageLayout: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
    const { accounts } = useMsal();
    const [activeTab, setActiveTab] = useState<"user" | "api">("user");
    const peerLabel = appMode === "app" ? "app2.localhost" : "app.localhost";
    const runtimeMode = appMode === "app"
        ? "Nginx upstream + Hono backend + API Gateway"
        : "Static hosting + OpenAPI mock + API Gateway";

    return (
        <div className="min-h-screen bg-gray-50">
            <nav className="bg-blue-600 text-white shadow-md">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center py-4">
                        <div className="flex-shrink-0">
                            <h2 className="text-xl font-bold">{appTitle}</h2>
                            <p className="text-sm text-blue-100 mt-1">
                                {appDescription}
                            </p>
                        </div>
                        <div className="flex items-center space-x-4">
                            <AuthenticatedTemplate>
                                <span className="text-sm font-medium">
                                    Welcome, {accounts[0]?.name || accounts[0]?.username}!
                                </span>
                                <SignOutButton />
                            </AuthenticatedTemplate>
                            <UnauthenticatedTemplate>
                                <SignInButton />
                            </UnauthenticatedTemplate>
                        </div>
                    </div>
                </div>
            </nav>
            
            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div className="bg-white rounded-lg shadow-sm p-4 mb-6">
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                        <div>
                            <p className="text-sm font-semibold text-blue-600">Current mode</p>
                            <p className="text-gray-900 font-medium">{runtimeMode}</p>
                            <p className="text-sm text-gray-600 mt-1">
                                API base path: <code>{apiBasePath}</code>
                            </p>
                        </div>
                        <a
                            className="inline-flex items-center justify-center rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
                            href={peerAppURL}
                        >
                            Open {peerLabel}
                        </a>
                    </div>
                </div>
                <AuthenticatedTemplate>
                    <div className="space-y-6">
                        <div className="bg-white rounded-lg shadow-sm p-4">
                            <div className="flex flex-wrap gap-3">
                                <button
                                    className={`px-4 py-2 rounded-md font-medium transition-colors duration-200 ${
                                        activeTab === "user"
                                            ? "bg-blue-600 text-white"
                                            : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                                    }`}
                                    onClick={() => {
                                        setActiveTab("user");
                                    }}
                                    type="button"
                                >
                                    Login User
                                </button>
                                <button
                                    className={`px-4 py-2 rounded-md font-medium transition-colors duration-200 ${
                                        activeTab === "api"
                                            ? "bg-blue-600 text-white"
                                            : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                                    }`}
                                    onClick={() => {
                                        setActiveTab("api");
                                    }}
                                    type="button"
                                >
                                    API Access
                                </button>
                            </div>
                        </div>
                        {activeTab === "user" ? <ProfileData /> : <ApiDemoPanel />}
                    </div>
                </AuthenticatedTemplate>
                <UnauthenticatedTemplate>
                    <div className="bg-white rounded-lg shadow-sm p-8 mb-8">
                        <h3 className="text-2xl font-bold text-blue-600 mb-4">
                            Welcome to {appTitle}
                        </h3>
                        <p className="text-gray-700 mb-4">
                            This example demonstrates how to use Azure MSAL Browser library with React and TypeScript
                            to authenticate with an OpenID Connect provider configured in EntraID v2.0 compatible mode.
                        </p>
                        <p className="text-gray-700 mb-8">
                            Please sign in to see your profile information with EntraID-compatible claims.
                        </p>
                        <p className="text-gray-700 mb-8">
                            After sign-in, you can also switch to an API demo tab that exercises GET, POST, and DELETE requests through the reverse proxy.
                            This build runs in <strong>{runtimeMode}</strong>.
                        </p>
                        
                        <div className="grid md:grid-cols-2 gap-8">
                            <div className="space-y-4">
                                <h4 className="text-lg font-semibold text-gray-900">Features Demonstrated:</h4>
                                <ul className="space-y-2 text-gray-700">
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        OpenID Connect authentication flow
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        Redirect-based login and logout
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        Token acquisition (silent and interactive)
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        UserInfo endpoint integration
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        Logout functionality
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        React hooks integration (@azure/msal-react)
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-blue-500 mr-2 font-bold">★</span>
                                        <strong>EntraID v2.0 compatible claims (oid, tid, upn, roles, groups)</strong>
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-green-500 mr-2">✓</span>
                                        OIDC protocol mode for development testing
                                    </li>
                                </ul>
                            </div>

                            <div className="space-y-4">
                                <h4 className="text-lg font-semibold text-gray-900">Configuration:</h4>
                                <div className="bg-gray-50 rounded-lg p-4 space-y-2 text-sm">
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">OIDC Server:</span>
                                                <span className="text-gray-900">{msalConfig.auth.authority}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">Client ID:</span>
                                        <span className="text-gray-900">{msalConfig.auth.clientId}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">Redirect URI:</span>
                                        <span className="text-gray-900">{msalConfig.auth.redirectUri}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">Scopes:</span>
                                        <span className="text-gray-900">{Array.isArray(parsedScopes) ? parsedScopes.join(', ') : (Array.isArray(loginRequest.scopes) ? loginRequest.scopes.join(', ') : 'openid, profile, email')}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">Mode:</span>
                                        <span className="text-blue-600 font-semibold">{runtimeMode}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">Peer link:</span>
                                        <a className="text-gray-900 underline" href={peerAppURL}>{peerLabel}</a>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">PKCE:</span>
                                        <span className="text-green-600 font-semibold">✓ Enabled</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="font-medium text-gray-600">Nonce:</span>
                                        <span className="text-green-600 font-semibold">✓ Enabled</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </UnauthenticatedTemplate>
                {children}
            </main>
        </div>
    );
};

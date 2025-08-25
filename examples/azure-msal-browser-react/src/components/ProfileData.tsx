import { useState, useEffect } from "react";
import { useMsal } from "@azure/msal-react";
import { InteractionRequiredAuthError } from "@azure/msal-browser";
import { loginRequest, graphConfig } from "../authConfig";

interface UserInfo {
    sub?: string;
    name?: string;
    email?: string;
    preferred_username?: string;
    given_name?: string;
    family_name?: string;
    // EntraID v2.0 specific claims
    oid?: string;  // Object ID
    tid?: string;  // Tenant ID
    upn?: string;  // User Principal Name
    roles?: string[];
    groups?: string[];
    user_type?: string;
    job_title?: string;
    department?: string;
    company_name?: string;
    [key: string]: any;
}

/**
 * Renders information about the signed-in user or a button to retrieve data about the user
 */
export const ProfileData = () => {
    const { instance, accounts } = useMsal();
    const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const account = accounts[0];

    const getUserInfo = async () => {
        if (!account) {
            setError("No account found");
            return;
        }

        setLoading(true);
        setError(null);

        try {
            // First, try to get a token silently
            console.log("🐎")
            console.log(loginRequest)
            console.log(account)
            const response = await instance.acquireTokenSilent({
                ...loginRequest,
                account: account
            });
            console.log("🐍")

            // Call the userinfo endpoint
            const userInfoResponse = await fetch(graphConfig.graphMeEndpoint, {
                headers: {
                    Authorization: `Bearer ${response.accessToken}`
                }
            });

            if (!userInfoResponse.ok) {
                throw new Error(`HTTP error! status: ${userInfoResponse.status}`);
            }

            const userData = await userInfoResponse.json();
            setUserInfo(userData);
        } catch (error) {
            if (error instanceof InteractionRequiredAuthError) {
                // If silent token acquisition fails, try interactive redirect
                try {
                    await instance.acquireTokenRedirect({
                        ...loginRequest,
                        account: account
                    });
                } catch (redirectError) {
                    console.error("Token acquisition failed:", redirectError);
                    setError("Failed to acquire token");
                }
            } else {
                console.error("Error fetching user info:", error);
                setError("Failed to fetch user information");
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (account) {
            getUserInfo();
        }
    }, [account]);

    if (!account) {
        return (
            <div className="bg-white rounded-lg shadow-sm p-6">
                <p className="text-gray-600">No user signed in</p>
            </div>
        );
    }

    return (
        <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-2xl font-bold text-blue-600 mb-6">User Profile</h3>
            
            <div className="space-y-6">
                {/* Account Information */}
                <div className="bg-gray-50 rounded-lg p-6 border-l-4 border-blue-500">
                    <h4 className="text-lg font-semibold text-gray-900 mb-4">Account Information (from MSAL)</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                            <span className="font-medium text-gray-600">Username:</span>
                            <span className="ml-2 text-gray-900">{account.username}</span>
                        </div>
                        <div>
                            <span className="font-medium text-gray-600">Name:</span>
                            <span className="ml-2 text-gray-900">{account.name}</span>
                        </div>
                        <div>
                            <span className="font-medium text-gray-600">Local Account ID:</span>
                            <span className="ml-2 text-gray-900 font-mono text-xs">{account.localAccountId}</span>
                        </div>
                        <div>
                            <span className="font-medium text-gray-600">Home Account ID:</span>
                            <span className="ml-2 text-gray-900 font-mono text-xs">{account.homeAccountId}</span>
                        </div>
                    </div>
                </div>

                {/* User Information */}
                <div className="bg-gray-50 rounded-lg p-6 border-l-4 border-blue-500">
                    <h4 className="text-lg font-semibold text-gray-900 mb-4">User Information (from UserInfo endpoint)</h4>
                    
                    {loading && (
                        <div className="flex items-center space-x-2 text-blue-600">
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                            <span>Loading user information...</span>
                        </div>
                    )}
                    
                    {error && (
                        <div className="bg-red-50 border border-red-200 rounded-md p-4">
                            <p className="text-red-800 font-medium">Error: {error}</p>
                        </div>
                    )}
                    
                    {userInfo && (
                        <div className="space-y-6">
                            {/* Basic Claims */}
                            <div className="bg-white rounded-lg p-4 border-l-4 border-blue-400">
                                <h5 className="text-base font-semibold text-blue-600 mb-3">Basic Claims</h5>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                                    <div>
                                        <span className="font-medium text-gray-600">Subject:</span>
                                        <span className="ml-2 text-gray-900">{userInfo.sub}</span>
                                    </div>
                                    <div>
                                        <span className="font-medium text-gray-600">Name:</span>
                                        <span className="ml-2 text-gray-900">{userInfo.name}</span>
                                    </div>
                                    <div>
                                        <span className="font-medium text-gray-600">Email:</span>
                                        <span className="ml-2 text-gray-900">{userInfo.email}</span>
                                    </div>
                                    <div>
                                        <span className="font-medium text-gray-600">Preferred Username:</span>
                                        <span className="ml-2 text-gray-900">{userInfo.preferred_username}</span>
                                    </div>
                                    <div>
                                        <span className="font-medium text-gray-600">Given Name:</span>
                                        <span className="ml-2 text-gray-900">{userInfo.given_name}</span>
                                    </div>
                                    <div>
                                        <span className="font-medium text-gray-600">Family Name:</span>
                                        <span className="ml-2 text-gray-900">{userInfo.family_name}</span>
                                    </div>
                                </div>
                            </div>
                            
                            {/* EntraID Claims */}
                            {(userInfo.oid || userInfo.tid || userInfo.upn) && (
                                <div className="bg-white rounded-lg p-4 border-l-4 border-cyan-400">
                                    <h5 className="text-base font-semibold text-cyan-600 mb-3">EntraID v2.0 Claims</h5>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                                        {userInfo.oid && (
                                            <div>
                                                <span className="font-medium text-gray-600">Object ID (oid):</span>
                                                <span className="ml-2 text-gray-900 font-mono text-xs">{userInfo.oid}</span>
                                            </div>
                                        )}
                                        {userInfo.tid && (
                                            <div>
                                                <span className="font-medium text-gray-600">Tenant ID (tid):</span>
                                                <span className="ml-2 text-gray-900 font-mono text-xs">{userInfo.tid}</span>
                                            </div>
                                        )}
                                        {userInfo.upn && (
                                            <div>
                                                <span className="font-medium text-gray-600">User Principal Name (upn):</span>
                                                <span className="ml-2 text-gray-900">{userInfo.upn}</span>
                                            </div>
                                        )}
                                        {userInfo.user_type && (
                                            <div>
                                                <span className="font-medium text-gray-600">User Type:</span>
                                                <span className="ml-2 text-gray-900">{userInfo.user_type}</span>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                            
                            {/* Authorization Claims */}
                            {(userInfo.roles || userInfo.groups) && (
                                <div className="bg-white rounded-lg p-4 border-l-4 border-green-400">
                                    <h5 className="text-base font-semibold text-green-600 mb-3">Authorization Claims</h5>
                                    <div className="space-y-3 text-sm">
                                        {userInfo.roles && (
                                            <div>
                                                <span className="font-medium text-gray-600">Roles:</span>
                                                <div className="mt-1 flex flex-wrap gap-1">
                                                    {(Array.isArray(userInfo.roles) ? userInfo.roles : [userInfo.roles]).map((role, index) => (
                                                        <span key={index} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                                            {role}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                        {userInfo.groups && (
                                            <div>
                                                <span className="font-medium text-gray-600">Groups:</span>
                                                <div className="mt-1 flex flex-wrap gap-1">
                                                    {(Array.isArray(userInfo.groups) ? userInfo.groups : [userInfo.groups]).map((group, index) => (
                                                        <span key={index} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                                            {group}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                            
                            {/* Organization Claims */}
                            {(userInfo.job_title || userInfo.department || userInfo.company_name) && (
                                <div className="bg-white rounded-lg p-4 border-l-4 border-purple-400">
                                    <h5 className="text-base font-semibold text-purple-600 mb-3">Organization Claims</h5>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                                        {userInfo.job_title && (
                                            <div>
                                                <span className="font-medium text-gray-600">Job Title:</span>
                                                <span className="ml-2 text-gray-900">{userInfo.job_title}</span>
                                            </div>
                                        )}
                                        {userInfo.department && (
                                            <div>
                                                <span className="font-medium text-gray-600">Department:</span>
                                                <span className="ml-2 text-gray-900">{userInfo.department}</span>
                                            </div>
                                        )}
                                        {userInfo.company_name && (
                                            <div>
                                                <span className="font-medium text-gray-600">Company:</span>
                                                <span className="ml-2 text-gray-900">{userInfo.company_name}</span>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                            
                            {/* All Claims JSON */}
                            <details className="bg-gray-50 rounded-lg p-4">
                                <summary className="cursor-pointer font-medium text-blue-600 hover:text-blue-800 focus:outline-none">
                                    All Claims (JSON)
                                </summary>
                                <pre className="mt-3 bg-gray-100 rounded-md p-4 text-xs overflow-x-auto text-gray-800 font-mono">
                                    {JSON.stringify(userInfo, null, 2)}
                                </pre>
                            </details>
                        </div>
                    )}
                    
                    {!loading && !error && !userInfo && (
                        <button 
                            className="bg-cyan-600 hover:bg-cyan-700 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2"
                            onClick={getUserInfo}
                        >
                            Refresh User Info
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
};

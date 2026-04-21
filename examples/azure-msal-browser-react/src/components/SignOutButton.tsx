import { useMsal } from "@azure/msal-react";
import { logoutRequest } from "../authConfig";

/**
 * Renders a button which, when selected, will redirect for logout
 */
export const SignOutButton = () => {
    const { instance } = useMsal();

    const handleLogout = () => {
        instance.logoutRedirect(logoutRequest);
    }

    return (
        <button 
            className="bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
            onClick={handleLogout}
        >
            Sign Out
        </button>
    );
};

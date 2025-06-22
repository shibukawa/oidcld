import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../authConfig";

/**
 * Renders a button which, when selected, will redirect for login
 */
export const SignInButton = () => {
    const { instance } = useMsal();

    const handleLogin = () => {
        instance.loginRedirect(loginRequest).catch(e => {
            console.error(e);
        });
    }

    return (
        <button 
            className="bg-blue-700 hover:bg-blue-800 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
            onClick={handleLogin}
        >
            Sign In
        </button>
    );
};

import { MsalProvider } from "@azure/msal-react";
import { PublicClientApplication } from "@azure/msal-browser";
import { msalConfig } from "./authConfig";
import { PageLayout } from "./components/PageLayout";
import './App.css'

const msalInstance = new PublicClientApplication(msalConfig);

function App() {
  return (
    <MsalProvider instance={msalInstance}>
      <PageLayout />
    </MsalProvider>
  );
}

export default App;

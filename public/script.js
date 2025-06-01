const { startRegistration, startAuthentication, browserSupportsWebAuthn, platformAuthenticatorIsAvailable, bufferToBase64URLString } = SimpleWebAuthnBrowser;

const usernameInput = document.getElementById('username');
const btnRegister = document.getElementById('btnRegister');
const btnLogin = document.getElementById('btnLogin');
const messageArea = document.getElementById('messageArea');

let userCredentialsDb = [];

function showMessage(message, isError = false, data = null) {
    let content = message;
    if (data && isError) {
        content += `<br><pre>${JSON.stringify(data, null, 2)}</pre>`;
    }
    messageArea.innerHTML = content;
    messageArea.className = isError ? 'message error' : 'message success';
    messageArea.style.display = 'block';
}

async function loadCredentialsFromServer() {
    try {
        const response = await fetch('/api/credentials');
        if (!response.ok) {
            throw new Error(`Failed to load credentials: ${response.statusText}`);
        }
        userCredentialsDb = await response.json();
        console.log("Credentials Loaded from Server:", userCredentialsDb);
    } catch (error) {
        console.error("Error loading credentials from server:", error);
        showMessage("There was an issue retrieving data. Please try again later.", true);
        userCredentialsDb = [];
    }
}

async function saveCredentialsToServer(credentials) {
    try {
        const response = await fetch('/api/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
        });
        if (!response.ok) {
            const errData = await response.json().catch(() => ({ error: response.statusText }));
            throw new Error(errData.error || `Failed to save credentials: ${response.statusText}`);
        }
        const result = await response.json();
        console.log("Credentials saved to server:", result.message);
        console.log("Current credentials state sent to server:", credentials);
    } catch (error) {
        console.error("Error saving credentials to server:", error);
        showMessage("Could not save credentials to server.", true, error);
    }
}

(async () => {
    if (!browserSupportsWebAuthn()) {
        showMessage('This browser does not support WebAuthn.', true);
        btnRegister.disabled = true;
        btnLogin.disabled = true;
        return;
    }
    try {
        const isPAAvailable = await platformAuthenticatorIsAvailable();
         if(!isPAAvailable) {
            console.warn("Platform Authenticator Check:", "No platform authenticator available. You might need a security key.");
        }
    } catch (err) {
         console.error("Platform Authenticator Check Error:", err);
    }
    await loadCredentialsFromServer();
})();

async function generateRegistrationOptionsSim(username) {
    await loadCredentialsFromServer();
    const existingUserCredentials = userCredentialsDb
        .filter(cred => cred.username === username)
        .map(cred => ({
            id: cred.credentialID,
            type: 'public-key',
            transports: cred.transports,
        }));

    return {
        challenge: bufferToBase64URLString(crypto.getRandomValues(new Uint8Array(32))),
        rp: { name: "ClientSim WebAuthn App", id: window.location.hostname },
        user: {
            id: bufferToBase64URLString(crypto.getRandomValues(new Uint8Array(16))), 
            name: username,
            displayName: username
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: { userVerification: "preferred", residentKey: "discouraged" },
        timeout: 60000, attestation: "none",
        excludeCredentials: existingUserCredentials
    };
}

async function verifyRegistrationSimClient(username, registrationResponse) {
    const { id, rawId, response: attestationResponse, type } = registrationResponse;
    
    await loadCredentialsFromServer(); 

    const existingCredential = userCredentialsDb.find(cred => cred.credentialID === id);
    if (existingCredential) {
        return { verified: false, error: "Credential ID already exists locally." };
    }

    const newCredential = {
        username: username,
        credentialID: id,
        rawId: bufferToBase64URLString(rawId), 
        transports: attestationResponse.getTransports ? attestationResponse.getTransports() : [],
        counter: 0,
        type: type
    };

    const updatedCredentialsList = [...userCredentialsDb, newCredential];
    
    await saveCredentialsToServer(updatedCredentialsList);
    userCredentialsDb = updatedCredentialsList;

    return { verified: true, registrationInfo: { credentialID: id } };
}

async function generateAuthenticationOptionsSim(username) {
    await loadCredentialsFromServer();
    let allowCredentialsList = [];
    if (username) {
         allowCredentialsList = userCredentialsDb
            .filter(cred => cred.username === username)
            .map(cred => ({
                id: cred.credentialID,
                type: 'public-key',
                transports: cred.transports,
            }));
    }
    return {
        challenge: bufferToBase64URLString(crypto.getRandomValues(new Uint8Array(32))),
        rpId: window.location.hostname,
        allowCredentials: allowCredentialsList,
        userVerification: "preferred", timeout: 60000
    };
}

async function verifyAuthenticationSimClient(username, authenticationResponse) {
    const { id, rawId, response: assertionResponse, type } = authenticationResponse;

    await loadCredentialsFromServer();

    const credentialIndex = userCredentialsDb.findIndex(cred => cred.credentialID === id && cred.username === username);

    if (credentialIndex === -1) {
        return { verified: false, error: "User not found." };
    }
    
    const updatedCredentialsList = [...userCredentialsDb];
    const credentialToUpdate = updatedCredentialsList[credentialIndex];

    console.log(`Simulating login for credential (ID: ${credentialToUpdate.credentialID}), new counter will be: ${(credentialToUpdate.counter || 0) + 1}`);

    credentialToUpdate.counter = (credentialToUpdate.counter || 0) + 1;
    
    await saveCredentialsToServer(updatedCredentialsList); 
    userCredentialsDb = updatedCredentialsList;

    return { verified: true, authenticationInfo: { credentialID: id, newCounter: credentialToUpdate.counter } };
}

btnRegister.addEventListener('click', async () => {
    const username = usernameInput.value;
    if (!username) { showMessage('Please enter a username.', true); return; }
    messageArea.style.display = 'none';

    try {
        await loadCredentialsFromServer();

        const usernameExists = userCredentialsDb.some(cred => cred.username === username);
        if (usernameExists) {
            showMessage('Username already exists. Please choose a different one.', true);
            return;
        }

        const regOptions = await generateRegistrationOptionsSim(username);
        console.log("Simulated Registration Options:", regOptions);

        let regResponse = await startRegistration({ optionsJSON: regOptions });
        console.log("Authenticator Registration Response:", regResponse);

        const verificationResult = await verifyRegistrationSimClient(username, regResponse);
        console.log("Client Simulated Registration Verification Result:", verificationResult);

        if (verificationResult && verificationResult.verified) {
            showMessage(`Registration successful for ${username}!`);
        } else {
            showMessage(verificationResult.error || "Registration attempt failed. Please try again.", true);
        }
    } catch (error) {
        console.error('Overall registration error:', error);
        if (messageArea.style.display === 'none') { 
             showMessage("An unexpected error occurred. Please try again.", true);
        }
    }
});

btnLogin.addEventListener('click', async () => {
    const username = usernameInput.value;
    if (!username) { showMessage('Please enter a username.', true); return; }
    messageArea.style.display = 'none';

    try {
        const authOptions = await generateAuthenticationOptionsSim(username);
        console.log("Simulated Authentication Options:", authOptions);
        
        if (authOptions.allowCredentials && authOptions.allowCredentials.length === 0) {
             if (!userCredentialsDb.some(cred => cred.username === username)){
                showMessage(`User '${username}' not found. Please register.`, true);
                return;
             }
             console.warn("Login Note:", "No specific credentials for this user in allowCredentials. Relaying on discoverable credentials if authenticator supports it.");
        }

        let authResponse = await startAuthentication({ optionsJSON: authOptions });
        console.log("Authenticator Authentication Response:", authResponse);

        const verificationResult = await verifyAuthenticationSimClient(username, authResponse);
        console.log("Client Simulated Authentication Verification Result:", verificationResult);

        if (verificationResult && verificationResult.verified) {
            showMessage(`Login successful!`);
        } else {
            showMessage(verificationResult.error || "Login attempt failed. Please check your details or try again.", true);
        }
    } catch (error) {
        console.error('Overall login error:', error);
         if (messageArea.style.display === 'none') {
            showMessage("An unexpected error occurred. Please try again.", true);
        }
    }
});
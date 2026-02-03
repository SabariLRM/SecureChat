const socket = io();

// State
let currentUser = null;
let sessionToken = null;
let usersMap = {}; // email -> user object
let myPrivateKey = null; // CryptoKey
let pendingEmail = null; // For OTP verification

// UI Elements
const loginOverlay = document.getElementById('login-overlay');
const otpOverlay = document.getElementById('otp-overlay');
const appContainer = document.getElementById('app-container');

// Auth Form
const authForm = document.getElementById('auth-form');
const emailInput = document.getElementById('email-input');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const confirmPasswordInput = document.getElementById('confirm-password-input');
const authError = document.getElementById('auth-error');
const loginBtn = document.getElementById('login-btn');
const toggleRegisterBtn = document.getElementById('toggle-register-btn');
const confirmRegisterBtn = document.getElementById('confirm-register-btn');

// OTP Form
const otpInput = document.getElementById('otp-input');
const verifyOtpBtn = document.getElementById('verify-otp-btn');
const resendOtpBtn = document.getElementById('resend-otp-btn');
const otpError = document.getElementById('otp-error');

// App UI
const logoutBtn = document.getElementById('logout-btn');
const adminPanel = document.getElementById('admin-panel');
const pendingList = document.getElementById('pending-users-list');
const messagesDiv = document.getElementById('messages');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');
const connectionStatus = document.getElementById('connection-status');
const userEmailDisplay = document.getElementById('user-email-display');

// Constants
const ENC_ALGO = { name: "AES-GCM", length: 256 };
const KEY_ALGO = { name: "RSA-OAEP", hash: "SHA-256" };

// --- Auth Handling ---

let isRegisterMode = false;

toggleRegisterBtn.addEventListener('click', () => {
    isRegisterMode = !isRegisterMode;
    if (isRegisterMode) {
        usernameInput.style.display = 'block';
        usernameInput.required = true;
        confirmPasswordInput.style.display = 'block';
        confirmPasswordInput.required = true;
        loginBtn.style.display = 'none';
        confirmRegisterBtn.style.display = 'block';
        toggleRegisterBtn.textContent = "Switch to Login";
        authError.textContent = "";
    } else {
        usernameInput.style.display = 'none';
        usernameInput.required = false;
        confirmPasswordInput.style.display = 'none';
        confirmPasswordInput.required = false;
        loginBtn.style.display = 'block';
        confirmRegisterBtn.style.display = 'none';
        toggleRegisterBtn.textContent = "Switch to Register";
        authError.textContent = "";
    }
});

authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (isRegisterMode) register();
    else login();
});

// Explicit buttons
loginBtn.addEventListener('click', (e) => {
    if (authForm.checkValidity()) {
        e.preventDefault();
        login();
    }
});

confirmRegisterBtn.addEventListener('click', (e) => {
    if (authForm.checkValidity()) {
        e.preventDefault();
        register();
    }
});

verifyOtpBtn.addEventListener('click', verifyOtp);
resendOtpBtn.addEventListener('click', resendOtp);

logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('focys_token');
    location.reload();
});

async function login() {
    const email = emailInput.value;
    const password = passwordInput.value;
    authError.textContent = "Logging in...";

    try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (res.ok) {
            sessionToken = data.token;
            currentUser = data.user;

            // Decrypt Room Key
            if (data.encryptedRoomKey) {
                try {
                    // We need private key imported first to decrypt the room key
                    // But initApp imports the private key. We should probably do it here or inside initApp.
                    // Let's import private key here first just to decrypt room key, OR pass it to initApp.
                    // Actually, initApp does `importPrivateKey`. Let's wait for initApp?
                    // But `unwrapRoomKey` needs `myPrivateKey`.
                    // Let's modify the flow:
                    // 1. initApp imports User Keys.
                    // 2. Then we Unwrap Room Key.

                    // We need to store encryptedRoomKey temporarily or pass it.
                    currentUser.encryptedRoomKey = data.encryptedRoomKey;
                } catch (e) {
                    console.error("Room Key preparation failed", e);
                    alert(`Room Key Error: ${e.message}`);
                }
            }

            await initApp();
        } else {
            authError.textContent = data.error;
        }
    } catch (e) {
        authError.textContent = "Connection error";
    }
}

async function register() {
    const email = emailInput.value;
    const username = usernameInput.value;
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (password !== confirmPassword) {
        authError.textContent = "Passwords do not match";
        return;
    }

    authError.textContent = "Registering...";

    try {
        const res = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, username, password })
        });
        const data = await res.json();

        if (res.ok) {
            // Show OTP Overlay
            pendingEmail = email;
            loginOverlay.style.display = 'none';
            otpOverlay.style.display = 'flex';
        } else {
            authError.textContent = data.error;
        }
    } catch (e) {
        authError.textContent = "Connection error";
    }
}

async function verifyOtp() {
    const otp = otpInput.value;
    otpError.textContent = "Verifying...";

    try {
        const res = await fetch('/verify-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: pendingEmail, otp })
        });
        const data = await res.json();

        if (res.ok) {
            otpOverlay.style.display = 'none';
            loginOverlay.style.display = 'flex'; // Go back to login
            authError.textContent = "Verified! Please login.";
            authError.style.color = "#00b894";

            // Switch to login mode UI
            if (isRegisterMode) toggleRegisterBtn.click();
        } else {
            otpError.textContent = data.error;
        }
    } catch (e) {
        otpError.textContent = "Error verifying OTP";
    }
}

async function resendOtp() {
    otpError.textContent = "Sending new code...";
    try {
        const res = await fetch('/resend-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: pendingEmail })
        });
        const data = await res.json();
        if (res.ok) {
            otpError.textContent = "Code resent! Check your email.";
            otpError.style.color = "#00b894";
        } else {
            otpError.textContent = data.error;
            otpError.style.color = "red";
        }
    } catch (e) {
        otpError.textContent = "Connection error";
    }
}


// --- Admin Panel Logic ---
// adminPanel defined at top
const userListDiv = document.getElementById('user-list');
const closeAdminBtn = document.getElementById('close-admin-btn');
const headerRight = document.querySelector('.header-right');

// Styling Inject (or add to css file, doing here for speed)
const adminBtn = document.createElement('button');
adminBtn.textContent = 'Admin Panel';
adminBtn.id = 'admin-btn';
adminBtn.style.marginRight = '10px';
adminBtn.style.background = '#e17055';
adminBtn.style.color = 'white';
adminBtn.style.border = 'none';
adminBtn.style.padding = '8px 12px';
adminBtn.style.borderRadius = '6px';
adminBtn.style.cursor = 'pointer';
adminBtn.style.display = 'none';
headerRight.insertBefore(adminBtn, document.getElementById('logout-btn'));

adminBtn.addEventListener('click', () => {
    adminPanel.style.display = 'flex';
    fetchAdminUsers(); // Renamed to avoid conflict
});

closeAdminBtn.addEventListener('click', () => {
    adminPanel.style.display = 'none';
});

// Close on outside click
adminPanel.addEventListener('click', (e) => {
    if (e.target === adminPanel) adminPanel.style.display = 'none';
});

async function fetchAdminUsers() { // Renamed to avoid conflict
    userListDiv.innerHTML = '<p>Loading...</p>';
    try {
        const res = await fetch('/users', {
            headers: { 'token': sessionToken }
        });
        const users = await res.json();

        if (res.status !== 200) throw new Error(users.error);

        userListDiv.innerHTML = '';
        if (users.length === 0) {
            userListDiv.innerHTML = '<p>No users found.</p>';
            return;
        }

        const table = document.createElement('table');
        table.style.width = '100%';
        table.style.borderCollapse = 'collapse';
        table.style.color = 'white';

        table.innerHTML = `
            <tr style="border-bottom: 1px solid #444;">
                <th style="padding:8px; text-align:left;">Email</th>
                <th style="padding:8px; text-align:left;">Verified</th>
                <th style="padding:8px; text-align:left;">Action</th>
            </tr>
        `;

        users.forEach(u => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid #333';

            const isMe = u.email === currentUser.email;

            tr.innerHTML = `
                <td style="padding:8px;">${u.email} ${u.is_admin ? '<span style="color:#e17055; font-size:0.8em;">(ADMIN)</span>' : ''}</td>
                <td style="padding:8px;">${u.is_verified ? '✅' : '❌'}</td>
                <td style="padding:8px;">
                    ${isMe ? '' : `<button class="delete-user-btn" data-id="${u._id}" style="background:#d63031; color:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;">Delete</button>`}
                </td>
            `;
            table.appendChild(tr);
        });

        userListDiv.appendChild(table);

        // Attach listeners
        document.querySelectorAll('.delete-user-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const uid = e.target.getAttribute('data-id');
                if (confirm('Are you SURE you want to delete this user? This cannot be undone.')) {
                    await deleteUser(uid);
                }
            });
        });

    } catch (e) {
        userListDiv.innerHTML = `<p style="color:red">Error: ${e.message}</p>`;
    }
}

async function deleteUser(userId) {
    try {
        const res = await fetch(`/users/${userId}`, {
            method: 'DELETE',
            headers: { 'token': sessionToken }
        });
        const data = await res.json();
        if (res.status === 200) {
            alert('User deleted.');
            fetchAdminUsers(); // Refresh (renamed)
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

// Show Admin Button check (call in initApp or after login)
function checkAdminUI() {
    if (currentUser && currentUser.adminConfirm) {
        adminBtn.style.display = 'inline-block';
    } else {
        adminBtn.style.display = 'none';
    }
}


// --- App Initialization ---

async function initApp() {
    // Show/Hide Admin UI
    checkAdminUI();
    loginOverlay.style.display = 'none';
    appContainer.style.display = 'flex';
    userEmailDisplay.textContent = `${currentUser.username} (${currentUser.email})` + (currentUser.isAdmin ? ' [Admin]' : '');

    // Import Keys
    try {
        myPrivateKey = await importPrivateKey(currentUser.privateKey);

        // Decrypt Room Key if available
        if (currentUser.encryptedRoomKey) {
            await unwrapRoomKey(currentUser.encryptedRoomKey);
            console.log("Room Key loaded.");
        } else {
            // Attempt to fetch Room Key (Session Restore)
            console.log("Room Key missing. Fetching from server...");
            const res = await fetch('/get-room-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: sessionToken })
            });
            const data = await res.json();
            if (data.encryptedRoomKey) {
                await unwrapRoomKey(data.encryptedRoomKey);
                console.log("Room Key restored from server.");
            } else {
                console.warn("Could not retrieve Room Key. Chat may be unreadable.");
            }
        }

        // We also need public keys of others.
        await fetchUsers();

        // Connect Socket
        socket.emit('join', currentUser.email);

        // Admin UI REMOVED


    } catch (e) {
        console.error("Key Import Error:", e);
        alert("Failed to load keys. Please check browser compatibility.");
    }
}

async function fetchUsers() {
    const res = await fetch('/users');
    const users = await res.json();
    users.forEach(u => {
        usersMap[u.email] = u;
    });
    if (currentUser.isAdmin) renderPendingUsers();
}

// --- Crypto Helpers ---

function pemToArrayBuffer(pem) {
    const b64 = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s/g, '');
    const str = atob(b64);
    const buf = new ArrayBuffer(str.length);
    const view = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) view[i] = str.charCodeAt(i);
    return buf;
}

async function importPrivateKey(pem) {
    return window.crypto.subtle.importKey("pkcs8", pemToArrayBuffer(pem), KEY_ALGO, true, ["decrypt"]);
}

async function importPublicKey(pem) {
    return window.crypto.subtle.importKey("spki", pemToArrayBuffer(pem), KEY_ALGO, true, ["encrypt"]);
}

// --- Room Key Management ---
let currentRoomKey = null;

async function unwrapRoomKey(encryptedRoomKeyHex) {
    if (!myPrivateKey) throw new Error("Private Key not loaded");
    const encryptedBytes = hexToArrayBuffer(encryptedRoomKeyHex);
    // Decrypt the AES Key using RSA Private Key
    const aesKeyRaw = await window.crypto.subtle.decrypt(KEY_ALGO, myPrivateKey, encryptedBytes);
    // Import the AES Key
    currentRoomKey = await window.crypto.subtle.importKey("raw", aesKeyRaw, ENC_ALGO, false, ["encrypt", "decrypt"]);
}

async function encryptMessage(text) {
    if (!currentRoomKey) throw new Error("Room Key not available");

    // 1. Encrypt Content with Room Key (AES-GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, currentRoomKey, encoded);

    // 2. Return payload (No per-user keys needed anymore!)
    return {
        iv: arrayBufferToHex(iv),
        content: arrayBufferToHex(ciphertext),
        type: 'room-v1' // Version tag for future proofing
    };
}

async function decryptMessage(payload) {
    // Support Legacy (Per-User Keys) Messages
    if (payload.keys && !payload.type) {
        const { iv, content, keys } = payload;
        const myEncryptedKey = keys[currentUser.email];
        if (!myEncryptedKey) throw new Error("No private key for me (Legacy message)");

        const encryptedKeyBuffer = hexToArrayBuffer(myEncryptedKey);
        const aesKeyRaw = await window.crypto.subtle.decrypt(KEY_ALGO, myPrivateKey, encryptedKeyBuffer);
        const aesKey = await window.crypto.subtle.importKey("raw", aesKeyRaw, ENC_ALGO, false, ["decrypt"]);

        const ivBuffer = hexToArrayBuffer(iv);
        const contentBuffer = hexToArrayBuffer(content);
        const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuffer }, aesKey, contentBuffer);

        return new TextDecoder().decode(decryptedBuffer);
    }

    // Room Key Messages
    if (payload.type === 'room-v1') {
        if (!currentRoomKey) throw new Error("Room Key missing");
        const { iv, content } = payload;
        const ivBuffer = hexToArrayBuffer(iv);
        const contentBuffer = hexToArrayBuffer(content);
        const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuffer }, currentRoomKey, contentBuffer);
        return new TextDecoder().decode(decryptedBuffer);
    }

    throw new Error("Unknown message type");
}

function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToArrayBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
}

// --- Messaging ---

chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value;
    if (!text) return;

    try {
        const encrypted = await encryptMessage(text);
        socket.emit('chat message', {
            sender: currentUser.email,
            senderUsername: currentUser.username,
            receiver: null, // Broadcast
            encrypted: encrypted
        });
        messageInput.value = '';
    } catch (e) {
        console.error("Encryption failed", e);
        alert("Encryption failed");
    }
});

socket.on('chat message', async (msg) => {
    await displayMessage(msg);
});

socket.on('history', async (msgs) => {
    console.log(`[History] Received ${msgs.length} messages.`);
    messagesDiv.innerHTML = '';

    if (!msgs || msgs.length === 0) {
        messagesDiv.innerHTML = '<div style="color: #888; text-align: center; padding: 20px;">No messages yet.</div>';
        return;
    }

    for (const msg of msgs) {
        try {
            let encryptedObj;
            try {
                encryptedObj = typeof msg.encrypted_content === 'string'
                    ? JSON.parse(msg.encrypted_content)
                    : msg.encrypted_content;
            } catch (e) {
                console.error("[History] JSON Parse Error for msg:", msg, e);
                continue; // Skip bad message
            }

            const parsed = {
                sender: msg.sender_email,
                senderUsername: msg.sender_username,
                encrypted: encryptedObj,
                isApproved: msg.sender_approved
            };
            await displayMessage(parsed);
        } catch (err) {
            console.error("[History] Error displaying message:", err);
        }
    }
});

async function displayMessage(msg) {
    const div = document.createElement('div');
    div.classList.add('message');
    div.classList.add(msg.sender === currentUser.email ? 'sent' : 'received');

    const senderDisplay = document.createElement('strong');
    // Display Username if available, else email
    const displayName = msg.senderUsername || msg.sender;
    senderDisplay.textContent = msg.sender === currentUser.email ? 'You' : displayName;
    div.appendChild(senderDisplay);
    div.appendChild(document.createElement('br'));

    const contentSpan = document.createElement('span');

    // Visibility Rule (Deny by Default):
    // 1. Admin sees everything.
    // 2. Sender sees their own message.
    // 3. Others only see if Approved (strictly equals 1 or true).

    let canView = false;
    if (currentUser.isAdmin || msg.sender === currentUser.email) {
        canView = true;
    } else if (msg.isApproved === 1 || msg.isApproved === true) {
        canView = true;
    }

    // DEBUG
    // console.log(`Msg from ${msg.sender}: isApproved=${msg.isApproved} (${typeof msg.isApproved}), Admin=${currentUser.isAdmin}, CanView=${canView}`);

    if (canView) {
        try {
            const text = await decryptMessage(msg.encrypted);
            contentSpan.textContent = text;
        } catch (e) {
            console.error("Decryption Error:", e);
            // Show specific error to user for debugging
            contentSpan.textContent = `[Encrypted: ${e.message}]`;
            contentSpan.classList.add('error-text');

            const meta = document.createElement('small');
            meta.className = 'encrypted-indicator';
            meta.textContent = " 🔒";
            div.appendChild(meta);
        }
    } else {
        contentSpan.textContent = "🔒 [Encrypted Message - Pending Approval]";
        contentSpan.style.color = '#ffa502';
        contentSpan.style.fontStyle = 'italic';
        contentSpan.title = "Only Admin can approve this user.";
    }

    div.appendChild(contentSpan);
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// --- Admin ---

function renderPendingUsers() {
    pendingList.innerHTML = '';
    Object.values(usersMap).forEach(u => {
        if (!u.is_approved && !u.is_admin && !u.isAdmin) { // Check both casing for admin just in case
            const li = document.createElement('li');
            li.classList.add('user-item');
            li.innerHTML = `
                <span>${u.username} (${u.email})</span>
                <button class="approve-btn" onclick="approveUser('${u.email}')">Accept</button>
            `;
            pendingList.appendChild(li);
        }
    });
}

window.approveUser = async (targetEmail) => {
    try {
        const res = await fetch('/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: sessionToken, targetEmail })
        });
        if (res.ok) {
            usersMap[targetEmail].is_approved = 1;
            renderPendingUsers();
        }
    } catch (e) {
        alert("Error approving");
    }
};

socket.on('new-user-pending', (user) => {
    fetchUsers();
});

socket.on('user-approved', ({ email }) => {
    // Update local state and REFRESH CHAT for everyone to reveal messages
    if (usersMap[email]) {
        usersMap[email].is_approved = 1;
    }
    // Refresh history to decrypt messages
    socket.emit('join', currentUser.email);
});

// Socket Status
socket.on('connect', () => {
    connectionStatus.textContent = 'Connected';
    connectionStatus.classList.add('connected');
    // Refetch users on reconnect to ensure we have latest keys
    if (currentUser) fetchUsers();
});

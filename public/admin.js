// Admin Panel JavaScript
const socket = io();

let sessionToken = localStorage.getItem('sessionToken');
let currentUser = JSON.parse(localStorage.getItem('currentUser') || 'null');

// DOM Elements
const adminEmailDisplay = document.getElementById('adminEmail');
const logoutBtn = document.getElementById('logoutBtn');
const userList = document.getElementById('userList');
const messageList = document.getElementById('messageList');
const refreshMessagesBtn = document.getElementById('refreshMessages');
const deleteAllMessagesBtn = document.getElementById('deleteAllMessages');

// Check if user is logged in
if (!currentUser || !sessionToken) {
    alert('Please log in first.');
    window.location.href = '/';
} else {
    console.log('[Admin Panel] Access granted');
    adminEmailDisplay.textContent = currentUser.email;

    // Load data on page load
    fetchUsers();
    fetchMessages();
}


// Back to Chat
const backToChatBtn = document.getElementById('backToChatBtn');
if (backToChatBtn) {
    backToChatBtn.addEventListener('click', () => {
        window.location.href = '/';
    });
}

// Logout
logoutBtn.addEventListener('click', () => {
    localStorage.clear();
    window.location.href = '/';
});

// Fetch and display users
async function fetchUsers() {
    userList.innerHTML = '<p>Loading...</p>';
    try {
        const res = await fetch('/users', {
            headers: { 'token': sessionToken }
        });
        const users = await res.json();

        if (res.status !== 200) throw new Error(users.error);

        // Filter out admin's email
        const filteredUsers = users.filter(u => u.email !== currentUser.email);

        if (filteredUsers.length === 0) {
            userList.innerHTML = '<p>No users found.</p>';
            return;
        }

        userList.innerHTML = '';
        filteredUsers.forEach(u => {
            const card = document.createElement('div');
            card.className = 'user-card';

            const verifiedBadge = u.is_verified ?
                '<span class="status-badge status-verified">✅ Verified</span>' :
                '<span class="status-badge status-pending">⏳ Pending</span>';

            const acceptedBadge = u.acceptme ?
                '<span class="status-badge status-accepted">✅ Accepted</span>' :
                '<span class="status-badge status-pending">⏳ Awaiting Approval</span>';

            card.innerHTML = `
                <div class="user-header">
                    <div class="user-email">${u.email}</div>
                    <div class="user-status">
                        ${verifiedBadge}
                        ${acceptedBadge}
                    </div>
                </div>
                <div class="user-keys">
                    <div class="key-item">
                        <span class="key-label">Public Key:</span><br>
                        <code>${u.public_key ? u.public_key.substring(0, 100) + '...' : 'N/A'}</code>
                    </div>
                    <div class="key-item">
                        <span class="key-label">Encrypted Private Key:</span><br>
                        <code>${u.private_key_encrypted ? JSON.stringify(JSON.parse(u.private_key_encrypted)).substring(0, 100) + '...' : 'N/A'}</code>
                    </div>
                </div>
                <div class="user-actions">
                    ${!u.acceptme ? `<button class="btn-accept" data-email="${u.email}">Accept</button>` : ''}
                    <button class="btn-delete-user" data-id="${u._id}">Delete User</button>
                </div>
            `;

            userList.appendChild(card);
        });

        // Attach event listeners
        document.querySelectorAll('.btn-accept').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const email = e.target.getAttribute('data-email');
                if (confirm(`Accept ${email} for chat access?`)) {
                    await acceptUser(email);
                }
            });
        });

        document.querySelectorAll('.btn-delete-user').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const userId = e.target.getAttribute('data-id');
                if (confirm('Are you SURE you want to delete this user? This cannot be undone.')) {
                    await deleteUser(userId);
                }
            });
        });

    } catch (e) {
        userList.innerHTML = `<p style="color:#d63031">Error: ${e.message}</p>`;
    }
}

// Accept user
async function acceptUser(targetEmail) {
    try {
        const res = await fetch('/accept-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: sessionToken, targetEmail })
        });
        const data = await res.json();
        if (res.status === 200) {
            alert('User accepted for chat access.');
            fetchUsers();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

// Delete user
async function deleteUser(userId) {
    try {
        const res = await fetch(`/users/${userId}`, {
            method: 'DELETE',
            headers: { 'token': sessionToken }
        });
        const data = await res.json();
        if (res.status === 200) {
            alert('User deleted.');
            fetchUsers();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

// CRYPTO UTILS
const KEY_ALGO = { name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" };
const ENC_ALGO = { name: "AES-GCM", length: 256 };

function hexToArrayBuffer(hex) {
    if (!hex) return new ArrayBuffer(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
}

async function getAdminRoomKey() {
    const jsonKey = sessionStorage.getItem('roomKey');
    if (!jsonKey) return null;
    try {
        const jwk = JSON.parse(jsonKey);
        return await window.crypto.subtle.importKey("jwk", jwk, ENC_ALGO, false, ["encrypt", "decrypt"]);
    } catch (e) {
        console.error("Failed to import room key from session:", e);
        return null;
    }
}

async function decryptMessage(encryptedHex, roomKey) {
    if (!encryptedHex || !roomKey) return null;
    try {
        const data = hexToArrayBuffer(encryptedHex);
        const iv = data.slice(0, 12);
        const ciphertext = data.slice(12);
        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, roomKey, ciphertext);
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Decryption failed:", e);
        return "[Decryption Error]";
    }
}

// Fetch and display messages
async function fetchMessages() {
    messageList.innerHTML = '<p>Loading...</p>';
    try {
        const res = await fetch('/get-all-messages', {
            headers: { 'token': sessionToken }
        });
        const data = await res.json();

        if (res.status !== 200) throw new Error(data.error);

        const messages = data.messages || [];
        if (messages.length === 0) {
            messageList.innerHTML = '<p>No messages found.</p>';
            return;
        }

        // Get Key
        const roomKey = await getAdminRoomKey();

        messageList.innerHTML = '';
        for (const msg of messages) {
            const item = document.createElement('div');
            item.className = 'message-item';
            item.dataset.messageId = msg._id;

            const encryptedMsg = msg.encrypted_content || 'N/A';
            const truncatedEncrypted = encryptedMsg.length > 50 ?
                encryptedMsg.substring(0, 50) + '...' : encryptedMsg;

            let decryptedContent = "[Room Key Not Found - Login to Chat First]";
            if (roomKey && msg.encrypted_content) {
                const decrypted = await decryptMessage(msg.encrypted_content, roomKey);
                if (decrypted) decryptedContent = decrypted;
            } else if (!msg.encrypted_content) {
                decryptedContent = "[No Content]";
            }

            item.innerHTML = `
                <div class="message-content">
                    <div class="message-sender"><strong>From:</strong> ${msg.sender_email}</div>
                    <div class="message-decrypted" style="color: #00b894; margin-top:4px;"><strong>Decrypted:</strong> ${decryptedContent}</div>
                    <div class="message-encrypted" style="opacity:0.6; font-size:0.8em;"><strong>Encrypted:</strong> <code>${truncatedEncrypted}</code></div>
                </div>
                <button class="btn-delete-message" data-id="${msg._id}">Delete</button>
            `;
            messageList.appendChild(item);
        }



        // Attach delete listeners
        document.querySelectorAll('.btn-delete-message').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const msgId = e.target.getAttribute('data-id');
                if (confirm('Delete this message?')) {
                    await deleteMessage(msgId);
                }
            });
        });

    } catch (e) {
        messageList.innerHTML = `<p style="color:#d63031">Error: ${e.message}</p>`;
    }
}

// Delete message
async function deleteMessage(messageId) {
    try {
        const res = await fetch('/delete-message', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: sessionToken, messageId })
        });
        const data = await res.json();
        if (res.status === 200) {
            // Remove from UI
            const msgElement = document.querySelector(`[data-message-id="${messageId}"]`);
            if (msgElement) msgElement.remove();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

// Delete all messages
deleteAllMessagesBtn.addEventListener('click', async () => {
    if (!confirm('Are you ABSOLUTELY SURE you want to delete ALL messages? This cannot be undone!')) return;
    if (!confirm('Last warning: This will permanently delete all chat history!')) return;

    try {
        const res = await fetch('/delete-all-messages', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: sessionToken })
        });
        const data = await res.json();
        if (res.status === 200) {
            alert('All messages deleted.');
            fetchMessages();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
});

// Refresh messages
refreshMessagesBtn.addEventListener('click', fetchMessages);

// Socket listeners
socket.on('users-updated', () => {
    fetchUsers();
});

socket.on('message-deleted', ({ messageId }) => {
    const msgElement = document.querySelector(`[data-message-id="${messageId}"]`);
    if (msgElement) msgElement.remove();
});

socket.on('all-messages-deleted', () => {
    fetchMessages();
});

// Initial load
fetchUsers();
fetchMessages();

const textInput = document.getElementById("textInput");
const passwordInput = document.getElementById("password");
const outputBox = document.getElementById("output");
const decryptedBox = document.getElementById("decryptedText");
const shaBox = document.getElementById("shaOutput");

// --- Modern clipboard helper with fallback ---
async function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    const text = el.value ?? '';
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
    } catch {
        console.warn("Clipboard write failed");
    }
}

// Attach counters to any button that is immediately followed by a .count-badge
document.querySelectorAll('button .count-badge').forEach(span => {
  const btn = span.closest('button');
  if (!btn || btn.id === 'togglePwd') return;
  btn.addEventListener('click', () => {
    span.textContent = String((parseInt(span.textContent, 10) || 0) + 1);
  });
});

// --- SHA-256 calculation ---
async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Peek password toggle ---
function togglePassword() {
    const pwd = document.getElementById("password");
    const btn = document.getElementById("togglePwd");
    const showing = pwd.type === "text";
    pwd.type = showing ? "password" : "text";
    btn.textContent = showing ? "Show Password" : "Hide Password";  // <-- added
    btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
}
document.getElementById('togglePwd').addEventListener('click', togglePassword);

// --- Safer Base64 helpers ---
function u8ToBase64(u8) {
    let bin = '';
    for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    return btoa(bin);
}
function base64ToU8(b64) {
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
}

// AES-256-GCM Encryption
async function encryptText(text, password) {
    if (!text || !password) return "";
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
    const combined = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.byteLength);
    combined.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);

    return u8ToBase64(combined);
}

// AES-256-GCM Decryption
async function decryptText(base64, password) {
    if (!base64 || !password) return "";
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    try {
        const combined = base64ToU8(base64);
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const ciphertext = combined.slice(28);

        const keyMaterial = await crypto.subtle.importKey(
            "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        return dec.decode(decrypted);
    } catch (e) {
        return "Decryption failed (wrong password or corrupted data)";
    }
}

// Reactive updates
let updateTimeout;

// Update SHA, encrypt, and decrypt from input text
async function updateFromInput() {
    clearTimeout(updateTimeout);
    updateTimeout = setTimeout(async () => {
        shaBox.value = await sha256(textInput.value);

        const encrypted = await encryptText(textInput.value, passwordInput.value);
        outputBox.value = encrypted;

        decryptedBox.value = await decryptText(encrypted, passwordInput.value);
    }, 150);
}

// Update decrypted from encrypted text
async function updateFromEncrypted() {
    clearTimeout(updateTimeout);
    updateTimeout = setTimeout(async () => {
        decryptedBox.value = await decryptText(outputBox.value, passwordInput.value);
    }, 150);
}

// Event listeners
textInput.addEventListener("input", updateFromInput);
passwordInput.addEventListener("input", async () => {
    await updateFromInput();
});
outputBox.addEventListener("input", updateFromEncrypted);

// Clear all boxes on reload
window.addEventListener("load", () => {
    document.querySelectorAll("input[type='text'], input[type='password'], textarea")
        .forEach(el => el.value = "");
});

const themeToggle = document.getElementById('theme-toggle');
themeToggle.addEventListener('click', () => {
  if (document.body.hasAttribute('data-theme')) {
    document.body.removeAttribute('data-theme');
  } else {
    document.body.setAttribute('data-theme', 'light');
  }
}
);


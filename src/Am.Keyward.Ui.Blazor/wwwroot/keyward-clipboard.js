// Clipboard for secrets (a static web asset of this RCL, imported by ClipboardInterop.TryCopySecretToClipboardAsync).
// A copied password, value or token is taken off the clipboard again after a short time — but only when the clipboard
// still holds it, so whatever the user copied in the meantime survives. Reading the clipboard needs permission: where
// it is not already granted (or the browser cannot tell), the clear is skipped silently instead of prompting.

let pending = null;

async function mayReadClipboard() {
    if (!navigator.clipboard?.readText || !navigator.permissions?.query) {
        return false;
    }

    try {
        const status = await navigator.permissions.query({ name: "clipboard-read" });
        return status.state === "granted";
    } catch {
        return false; // "clipboard-read" is unknown to this browser
    }
}

async function clearIfUnchanged(entry) {
    if (pending !== entry) {
        return; // a newer copy took over
    }

    if (!document.hasFocus()) {
        // Clipboard access needs a focused document; try again when the user comes back.
        window.addEventListener("focus", () => clearIfUnchanged(entry), { once: true });
        return;
    }

    pending = null;
    try {
        if (await mayReadClipboard() && await navigator.clipboard.readText() === entry.text) {
            await navigator.clipboard.writeText("");
        }
    } catch {
        // Refused or not focused after all: best effort only.
    }
}

export async function copySecret(text, keepMilliseconds) {
    try {
        await navigator.clipboard.writeText(text);
    } catch {
        return false;
    }

    if (pending) {
        clearTimeout(pending.timer);
    }

    const entry = { text, timer: 0 };
    entry.timer = setTimeout(() => clearIfUnchanged(entry), keepMilliseconds);
    pending = entry;
    return true;
}

// Collocated JS module for KeywardUi (served as a static web asset of this RCL, no host wiring needed).
// Reports the browser's time zone so UTC timestamps from the database render in the viewer's local time.
export function getTimeZoneName() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone ?? null;
}

export function getTimeZoneOffsetMinutes() {
    return new Date().getTimezoneOffset();
}

// Small on/off UI preferences that must survive a page reload (the collapsed state of the tree pane).
// localStorage can throw (private mode, blocked storage), so both sides swallow — a lost preference is
// never worth breaking a page over.
export function readFlag(key) {
    try {
        return window.localStorage.getItem(key) === "1";
    } catch {
        return false;
    }
}

export function writeFlag(key, value) {
    try {
        window.localStorage.setItem(key, value ? "1" : "0");
    } catch {
        // Storage unavailable — the preference simply stays per-session.
    }
}

// Collocated JS module for KeywardUi (served as a static web asset of this RCL, no host wiring needed).
// Reports the browser's time zone so UTC timestamps from the database render in the viewer's local time.
export function getTimeZoneName() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone ?? null;
}

export function getTimeZoneOffsetMinutes() {
    return new Date().getTimezoneOffset();
}

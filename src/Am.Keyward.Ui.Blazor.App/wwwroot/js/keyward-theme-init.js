// Applies the per-browser theme BEFORE first paint (no flash of the wrong scheme). Loaded as a blocking script in
// <head> (a file, not inline, so the Content-Security-Policy needs no 'unsafe-inline'); js/keyward-theme.js
// re-applies it after Blazor enhanced navigations.
(function () {
    try {
        if (localStorage.getItem('amkeyward-dark') === '1') { document.documentElement.classList.add('dark'); }
        var kwTheme = localStorage.getItem('amkeyward-theme');
        if (kwTheme) { document.documentElement.setAttribute('data-theme', kwTheme); }
    } catch (e) { /* localStorage unavailable */ }
})();

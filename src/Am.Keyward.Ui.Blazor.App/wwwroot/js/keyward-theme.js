// Per-browser theme (dark mode + colour theme): purely client-side, stored in localStorage and applied as
// a class / data attribute on <html>. The topbar controls call these functions directly (plain onclick, no
// Blazor circuit needed); the CSS reacts to html.dark / html[data-theme="..."].
window.keywardTheme = {
    themeKey: 'amkeyward-theme',
    darkKey: 'amkeyward-dark',
    setTheme: function (theme) {
        if (theme) {
            document.documentElement.setAttribute('data-theme', theme);
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        try { localStorage.setItem(this.themeKey, theme || ''); } catch (e) { /* localStorage unavailable */ }
        var menu = document.querySelector('.theme-menu');
        if (menu) { menu.removeAttribute('open'); }
    },
    toggleDark: function () {
        var dark = !document.documentElement.classList.contains('dark');
        document.documentElement.classList.toggle('dark', dark);
        try { localStorage.setItem(this.darkKey, dark ? '1' : '0'); } catch (e) { /* localStorage unavailable */ }
    },
    apply: function () {
        try {
            document.documentElement.classList.toggle('dark', localStorage.getItem(this.darkKey) === '1');
            var theme = localStorage.getItem(this.themeKey);
            if (theme) {
                document.documentElement.setAttribute('data-theme', theme);
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
        } catch (e) { /* localStorage unavailable */ }
    }
};

// Blazor enhanced navigation patches the DOM to match the server response, which carries no theme
// attributes (they are client-side only) — re-apply after every enhanced load so the theme survives.
(function registerEnhancedLoad(attempt) {
    if (window.Blazor && typeof window.Blazor.addEventListener === 'function') {
        window.Blazor.addEventListener('enhancedload', function () { window.keywardTheme.apply(); });
    } else if (attempt < 200) { // ~10 s — give up if blazor.web.js never loads
        setTimeout(function () { registerEnhancedLoad(attempt + 1); }, 50);
    }
})(0);

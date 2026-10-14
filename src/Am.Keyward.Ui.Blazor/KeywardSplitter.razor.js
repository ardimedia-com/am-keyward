// Collocated JS module for KeywardSplitter: drags the handle, writes the first pane's size into a CSS custom property
// on the container (the handle's parent), remembers it in localStorage and clamps it whenever the container resizes,
// so the second pane always stays visible. Columns are stored in pixels, rows as a share of the container height.

const KEY_STEP = 24;

function read(key) {
    try {
        const value = parseFloat(localStorage.getItem(key));
        return Number.isFinite(value) ? value : null;
    } catch {
        return null; // storage blocked (private mode, policy): the default applies
    }
}

function write(key, value) {
    try {
        localStorage.setItem(key, String(value));
    } catch {
        // not remembered — the split still works for this page
    }
}

export function attach(handle, options) {
    const container = handle.parentElement;
    const rows = options.rows;
    let stored = read(options.storageKey); // px (columns) or share 0–1 (rows); null = default

    const total = () => {
        const box = container.getBoundingClientRect();
        return (rows ? box.height : box.width) - (rows ? handle.offsetHeight : handle.offsetWidth);
    };

    // A stacked layout (narrow screen) hides the handle; then nothing is clamped or set.
    const active = () => handle.offsetParent !== null && getComputedStyle(handle).display !== "none";

    const clamp = (px) => {
        const max = total() - options.minSecond;
        return Math.max(options.minFirst, Math.min(px, Math.max(options.minFirst, max)));
    };

    const toPx = (size) => (rows ? size * total() : size);
    const fromPx = (px) => (rows ? px / Math.max(total(), 1) : px);

    const apply = () => {
        if (!active()) {
            container.style.removeProperty(options.variable);
            return;
        }

        const px = clamp(toPx(stored ?? options.defaultSize));
        container.style.setProperty(options.variable, `${Math.round(px)}px`);
        handle.setAttribute("aria-valuenow", String(Math.round(px)));
    };

    const set = (px, remember) => {
        const clamped = clamp(px);
        stored = fromPx(clamped);
        container.style.setProperty(options.variable, `${Math.round(clamped)}px`);
        handle.setAttribute("aria-valuenow", String(Math.round(clamped)));
        if (remember) {
            write(options.storageKey, rows ? stored.toFixed(4) : Math.round(clamped));
        }
    };

    const current = () => {
        const value = parseFloat(container.style.getPropertyValue(options.variable));
        return Number.isFinite(value) ? value : toPx(stored ?? options.defaultSize);
    };

    const disabled = () => handle.classList.contains("disabled");

    let dragging = null;
    const onDown = (event) => {
        if (disabled() || event.button !== 0) {
            return;
        }

        event.preventDefault();
        const box = container.getBoundingClientRect();
        dragging = { origin: rows ? box.top : box.left, pointer: event.pointerId };
        handle.setPointerCapture(event.pointerId);
        handle.classList.add("dragging");
    };

    const onMove = (event) => {
        if (!dragging) {
            return;
        }

        set((rows ? event.clientY : event.clientX) - dragging.origin, false);
    };

    const onUp = () => {
        if (!dragging) {
            return;
        }

        handle.releasePointerCapture?.(dragging.pointer);
        dragging = null;
        handle.classList.remove("dragging");
        set(current(), true);
    };

    const onKey = (event) => {
        if (disabled()) {
            return;
        }

        const back = rows ? "ArrowUp" : "ArrowLeft";
        const forward = rows ? "ArrowDown" : "ArrowRight";
        if (event.key === back || event.key === forward) {
            event.preventDefault();
            set(current() + (event.key === forward ? KEY_STEP : -KEY_STEP), true);
        } else if (event.key === "Home" || event.key === "End") {
            event.preventDefault();
            set(event.key === "Home" ? options.minFirst : total() - options.minSecond, true);
        }
    };

    const onDouble = () => {
        if (disabled()) {
            return;
        }

        try {
            localStorage.removeItem(options.storageKey);
        } catch {
            // nothing stored anyway
        }

        stored = null;
        apply();
    };

    handle.addEventListener("pointerdown", onDown);
    handle.addEventListener("pointermove", onMove);
    handle.addEventListener("pointerup", onUp);
    handle.addEventListener("pointercancel", onUp);
    handle.addEventListener("keydown", onKey);
    handle.addEventListener("dblclick", onDouble);

    // Window resize, a collapsing nav, the tree turning into a rail: re-clamp so the second pane stays in view.
    const observer = new ResizeObserver(() => {
        if (!dragging) {
            apply();
        }
    });
    observer.observe(container);
    apply();

    return {
        dispose() {
            observer.disconnect();
            handle.removeEventListener("pointerdown", onDown);
            handle.removeEventListener("pointermove", onMove);
            handle.removeEventListener("pointerup", onUp);
            handle.removeEventListener("pointercancel", onUp);
            handle.removeEventListener("keydown", onKey);
            handle.removeEventListener("dblclick", onDouble);
        },
    };
}

// Collocated JS module for VaultWorkspace (a static web asset of this RCL, no host wiring needed).
// Reads the QR code a website shows when 2FA is switched on — from a pasted screenshot or a chosen image — in the
// browser, so the picture never leaves it; only the decoded otpauth link goes to the server, into the form field.

let jsQrLoading;

// jsQR (Apache-2.0, vendored under lib/jsqr) is a classic script that sets window.jsQR; load it on first use only.
function loadJsQr() {
    if (window.jsQR) {
        return Promise.resolve(window.jsQR);
    }

    jsQrLoading ??= new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = new URL("../lib/jsqr/jsQR.js", import.meta.url).href;
        script.onload = () => resolve(window.jsQR);
        script.onerror = () => {
            jsQrLoading = undefined;
            reject(new Error("jsQR could not be loaded"));
        };
        document.head.appendChild(script);
    });
    return jsQrLoading;
}

async function decodeImage(blob) {
    const jsQR = await loadJsQr();
    const bitmap = await createImageBitmap(blob);
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(bitmap, 0, 0);
    bitmap.close?.();
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    const found = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
    return found ? found.data : null;
}

async function report(dotnet, blob) {
    let text = null;
    try {
        text = await decodeImage(blob);
    } catch {
        text = null;
    }
    await dotnet.invokeMethodAsync("OnQrDecodedAsync", text);
}

// One pair of document listeners for the component's lifetime; the form field opts in with data-kw-qr (paste) and
// its file input with data-kw-qr-file. A paste without an image (the key as text) is left alone.
export function listen(dotnet) {
    const onPaste = (event) => {
        if (!event.target.closest?.("[data-kw-qr]")) {
            return;
        }

        const image = [...(event.clipboardData?.items ?? [])].find((item) => item.type.startsWith("image/"));
        if (!image) {
            return;
        }

        event.preventDefault();
        report(dotnet, image.getAsFile());
    };

    const onChange = (event) => {
        const input = event.target;
        if (!input.matches?.("input[type=file][data-kw-qr-file]") || !input.files?.length) {
            return;
        }

        const file = input.files[0];
        input.value = "";
        report(dotnet, file);
    };

    document.addEventListener("paste", onPaste, true);
    document.addEventListener("change", onChange, true);
    return {
        dispose() {
            document.removeEventListener("paste", onPaste, true);
            document.removeEventListener("change", onChange, true);
        },
    };
}

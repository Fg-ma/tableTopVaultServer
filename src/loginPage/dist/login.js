"use strict";
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const vaultPasswordInput = document.getElementById("vaultPassword");
    if (!vaultPasswordInput)
        return;
    const res = await fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            cmd: "login",
            password: vaultPasswordInput.value,
        }),
        credentials: "include",
    });
    vaultPasswordInput.value = "";
    if (res.ok) {
        window.location.href = "/dashboard/";
    }
    else {
        const loginError = document.getElementById("loginError");
        if (loginError)
            loginError.textContent = "Invalid password";
    }
});
document
    .getElementById("toggle-password-visibility")
    ?.addEventListener("click", () => {
    const input = document.getElementById("vaultPassword");
    const btn = document.getElementById("toggle-password-visibility");
    const img = btn?.querySelector("img");
    if (!input || !btn || !img)
        return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    img.src = isHidden
        ? "/public/svgs/visibilityOffIcon.svg"
        : "/public/svgs/visibilityIcon.svg";
    img.alt = isHidden ? "Hide password" : "Show password";
});

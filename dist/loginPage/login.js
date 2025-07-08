"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var _a, _b;
(_a = document.getElementById("loginForm")) === null || _a === void 0 ? void 0 : _a.addEventListener("submit", (e) => __awaiter(void 0, void 0, void 0, function* () {
    e.preventDefault();
    const vaultTokenInput = document.getElementById("vaultToken");
    if (!vaultTokenInput)
        return;
    const token = vaultTokenInput.value;
    const res = yield fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ cmd: "login", token }),
    });
    if (res.ok) {
        const data = yield res.json();
        localStorage.setItem("session_token", data.session_token);
        window.location.href = "/dashboard/";
    }
    else {
        const loginError = document.getElementById("loginError");
        if (loginError)
            loginError.textContent = "Invalid token";
    }
}));
(_b = document
    .getElementById("toggle-token-visibility")) === null || _b === void 0 ? void 0 : _b.addEventListener("click", () => {
    const input = document.getElementById("vaultToken");
    const btn = document.getElementById("toggle-token-visibility");
    const img = btn === null || btn === void 0 ? void 0 : btn.querySelector("img");
    if (!input || !btn || !img)
        return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    img.src = isHidden
        ? "/public/svgs/visibilityOffIcon.svg"
        : "/public/svgs/visibilityIcon.svg";
    img.alt = isHidden ? "Hide token" : "Show token";
});

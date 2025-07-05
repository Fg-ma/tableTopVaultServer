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
var _a;
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
        body: JSON.stringify({ token }),
    });
    if (res.ok) {
        const data = yield res.json();
        localStorage.setItem("session_token", data.session_token);
        const loginOverlay = document.getElementById("loginOverlay");
        if (loginOverlay)
            loginOverlay.style.display = "none";
        serverRequests.loadRequests();
    }
    else {
        const loginError = document.getElementById("loginError");
        if (loginError)
            loginError.textContent = "Invalid token";
    }
}));

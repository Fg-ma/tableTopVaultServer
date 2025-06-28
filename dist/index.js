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
class ServerRequests {
    constructor() {
        this.loadRequests = () => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield fetch("/requests");
                if (!res.ok)
                    throw new Error("Failed to fetch");
                const data = yield res.json();
                const list = document.getElementById("requestsList");
                if (!list)
                    return;
                list.innerHTML = "";
                for (const requestId in data) {
                    const req = data[requestId];
                    const li = document.createElement("li");
                    li.className = "request-card";
                    const idEl = document.createElement("div");
                    idEl.className = "request-id";
                    idEl.textContent = requestId;
                    const bodyEl = document.createElement("pre");
                    bodyEl.className = "request-body";
                    bodyEl.textContent = JSON.stringify(req, null, 2);
                    const btnRow = document.createElement("div");
                    btnRow.style.display = "flex";
                    btnRow.style.justifyContent = "flex-end";
                    btnRow.style.gap = "0.5rem";
                    const acceptBtn = document.createElement("button");
                    acceptBtn.className = "accept-btn";
                    acceptBtn.textContent = "Accept";
                    acceptBtn.addEventListener("click", () => this.sendAccept(requestId));
                    const declineBtn = document.createElement("button");
                    declineBtn.className = "accept-btn";
                    declineBtn.style.backgroundColor = "var(--tone-black-6)";
                    declineBtn.textContent = "Decline";
                    declineBtn.addEventListener("click", () => this.sendDecline(requestId));
                    btnRow.append(acceptBtn, declineBtn);
                    li.append(idEl, bodyEl, btnRow);
                    list.appendChild(li);
                }
            }
            catch (e) {
                console.error(e);
            }
        });
        this.sendAccept = (requestId) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield fetch("/accept", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ request_id: requestId }),
                });
                if (res.ok)
                    this.loadRequests();
                else
                    console.error("Approve failed");
            }
            catch (e) {
                console.error(e);
            }
        });
        this.sendDecline = (requestId) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield fetch("/decline", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ request_id: requestId }),
                });
                if (res.ok)
                    this.loadRequests();
                else
                    console.error("Decline failed");
            }
            catch (e) {
                console.error(e);
            }
        });
    }
}
const serverRequests = new ServerRequests();
(_a = document.getElementById("loginForm")) === null || _a === void 0 ? void 0 : _a.addEventListener("submit", (e) => __awaiter(void 0, void 0, void 0, function* () {
    e.preventDefault();
    const vaultTokenInput = document.getElementById("vaultToken");
    if (!vaultTokenInput)
        return;
    const token = vaultTokenInput.value;
    const res = yield fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
    });
    if (res.ok) {
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
window.addEventListener("load", serverRequests.loadRequests);
setInterval(serverRequests.loadRequests, 5000);

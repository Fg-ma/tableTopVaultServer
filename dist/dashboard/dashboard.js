"use strict";
class ServerRequests {
    constructor() { }
    loadRequests = async () => {
        try {
            const res = await fetch("/list", {
                headers: {
                    Authorization: `Bearer ${localStorage.getItem("session_token")}`,
                },
            });
            if (res.status === 401) {
                window.location.href = "/loginPage/";
                return;
            }
            if (!res.ok)
                throw new Error("Failed to fetch");
            const data = await res.json();
            const list = document.getElementById("requestsList");
            if (!list)
                return;
            list.innerHTML = "";
            for (const req of data) {
                const requestId = req.request_id;
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
    };
    sendAccept = async (requestId) => {
        try {
            const res = await fetch("/approve", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${localStorage.getItem("session_token")}`,
                },
                body: JSON.stringify({ cmd: "approve", request_id: requestId }),
            });
            if (res.ok) {
                setTimeout(() => this.loadRequests(), 500);
            }
            else
                console.error("Approve failed");
        }
        catch (e) {
            console.error(e);
        }
    };
    sendDecline = async (requestId) => {
        try {
            const res = await fetch("/decline", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${localStorage.getItem("session_token")}`,
                },
                body: JSON.stringify({ cmd: "decline", request_id: requestId }),
            });
            if (res.ok) {
                setTimeout(() => this.loadRequests(), 500);
            }
            else
                console.error("Decline failed");
        }
        catch (e) {
            console.error(e);
        }
    };
}
const serverRequests = new ServerRequests();
window.addEventListener("load", serverRequests.loadRequests);
setInterval(serverRequests.loadRequests, 5000);

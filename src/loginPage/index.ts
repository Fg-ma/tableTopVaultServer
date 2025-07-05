document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const vaultTokenInput = document.getElementById(
    "vaultToken"
  ) as HTMLInputElement;

  if (!vaultTokenInput) return;

  const token = vaultTokenInput.value;
  const res = await fetch("/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  });
  if (res.ok) {
    const data = await res.json();
    localStorage.setItem("session_token", data.session_token);
    const loginOverlay = document.getElementById("loginOverlay");
    if (loginOverlay) loginOverlay.style.display = "none";
    serverRequests.loadRequests();
  } else {
    const loginError = document.getElementById("loginError");
    if (loginError) loginError.textContent = "Invalid token";
  }
});

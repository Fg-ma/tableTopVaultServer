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
    body: JSON.stringify({ cmd: "login", token }),
  });

  if (res.ok) {
    const data = await res.json();
    localStorage.setItem("session_token", data.session_token);

    window.location.href = "/dashboard/";
  } else {
    const loginError = document.getElementById("loginError");
    if (loginError) loginError.textContent = "Invalid token";
  }
});

document
  .getElementById("toggle-token-visibility")
  ?.addEventListener("click", () => {
    const input = document.getElementById("vaultToken") as HTMLInputElement;
    const btn = document.getElementById("toggle-token-visibility");
    const img = btn?.querySelector("img");

    if (!input || !btn || !img) return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    img.src = isHidden
      ? "/public/svgs/visibilityOffIcon.svg"
      : "/public/svgs/visibilityIcon.svg";
    img.alt = isHidden ? "Hide token" : "Show token";
  });

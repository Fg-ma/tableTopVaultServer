const hashPassword = async (password: string) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
};

document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const vaultPasswordInput = document.getElementById(
    "vaultPassword"
  ) as HTMLInputElement;

  if (!vaultPasswordInput) return;

  const res = await fetch("/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      cmd: "login",
      password: hashPassword(vaultPasswordInput.value),
    }),
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
  .getElementById("toggle-password-visibility")
  ?.addEventListener("click", () => {
    const input = document.getElementById("vaultPassword") as HTMLInputElement;
    const btn = document.getElementById("toggle-password-visibility");
    const img = btn?.querySelector("img");

    if (!input || !btn || !img) return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    img.src = isHidden
      ? "/public/svgs/visibilityOffIcon.svg"
      : "/public/svgs/visibilityIcon.svg";
    img.alt = isHidden ? "Hide password" : "Show password";
  });

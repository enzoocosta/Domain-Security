(function () {
  var storageKey = "dsc-theme";
  var root = document.documentElement;
  var button = document.getElementById("theme-toggle");

  function getTheme() {
    return root.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }

  function syncButton(theme) {
    if (!button) {
      return;
    }
    button.setAttribute("aria-pressed", String(theme === "dark"));
    button.setAttribute(
      "aria-label",
      theme === "dark" ? "Ativar modo claro" : "Ativar modo escuro"
    );
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    syncButton(theme);
  }

  if (!button) {
    return;
  }

  syncButton(getTheme());
  button.addEventListener("click", function () {
    var nextTheme = getTheme() === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
    try {
      localStorage.setItem(storageKey, nextTheme);
    } catch (error) {
      // Storage failure should not block theme switching.
    }
  });
})();

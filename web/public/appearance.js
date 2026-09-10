/* Cache only. Authenticated account preferences supersede this before first interaction. */
try {
  var appearance = JSON.parse(
    localStorage.getItem("nebulalog.appearance") || "{}",
  );
  var chosenTheme = ["light", "dark", "system"].includes(appearance.theme)
    ? appearance.theme
    : "system";
  document.documentElement.dataset.theme =
    chosenTheme === "system"
      ? matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : chosenTheme;
  document.documentElement.dataset.density =
    appearance.density === "comfortable" ? "comfortable" : "compact";
} catch (_) {
  document.documentElement.dataset.theme = "dark";
  document.documentElement.dataset.density = "compact";
}

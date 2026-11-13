/* set the theme before first paint so there is no flash */
try { var t = localStorage.getItem("mcpgate-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) {}

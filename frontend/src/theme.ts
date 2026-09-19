export type Theme = "dark" | "light";

const STORAGE_KEY = "mirraura-theme";

export function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function setStoredTheme(theme: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // localStorage unavailable (private mode, blocked) — theme just
    // won't persist across reloads, which is a harmless degradation.
  }
}

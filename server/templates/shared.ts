import { Matcher } from "../templateEngine.js";

// Negative matcher shared by file-exposure templates: excludes SPA HTML
// fallbacks so a single-page app that returns index.html for every path is
// never flagged. Exported for reuse across the grouped template modules.
export const NOT_HTML: Matcher = {
  type: "word" as const,
  words: ["<!doctype", "<html", "<head", "<body"],
  negative: true,
};

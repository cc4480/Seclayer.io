import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const ADMIN_BACKUPS_AND_ARTIFACTS: Template[] = [
  // --- Exposed admin tooling / CMS config backups / artifacts ---
  {
    id: "tomcat-manager-exposed",
    name: "Apache Tomcat Manager Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Tomcat Web Application Manager is reachable, a high-value target for deploying a malicious WAR (RCE) if credentials are weak.",
    fix: "Restrict the manager app to trusted networks and use strong, unique credentials.",
    requests: [
      {
        path: "/manager/html",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Tomcat Web Application Manager"] },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-config-save-exposed",
    name: "WordPress wp-config Editor Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "An editor/temp backup of wp-config.php is publicly readable, exposing database credentials and WordPress salts.",
    fix: "Delete the backup, block dotted/tilde temp files, and rotate the exposed credentials.",
    requests: [
      {
        path: "/wp-config.php.save",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["DB_PASSWORD", "DB_NAME"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/wp-config.php~",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["DB_PASSWORD", "DB_NAME"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "laravel-log-exposed",
    name: "Laravel Log File Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Laravel application log is publicly readable, leaking stack traces, queries, and frequently secrets in error context.",
    fix: "Store logs outside the web root and deny direct access to the storage directory.",
    requests: [
      {
        path: "/storage/logs/laravel.log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["production.ERROR", "local.ERROR", "Stack trace", "stacktrace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "dsstore-exposed",
    name: ".DS_Store File Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "A macOS .DS_Store file is publicly readable, enabling reconstruction of the directory's file names.",
    fix: "Remove .DS_Store files from the web root and add them to your ignore rules.",
    requests: [
      {
        path: "/.DS_Store",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Bud1"] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
];

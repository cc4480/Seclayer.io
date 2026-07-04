import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const KEYS_AND_CMS_EXPOSURE: Template[] = [
  // --- Cloud / key material ---
  {
    id: "gcp-service-account-exposed",
    name: "GCP Service Account Key Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A Google Cloud service-account key file is publicly readable, granting programmatic access to cloud resources.",
    fix: "Remove the key from the web root and revoke/rotate the service-account key immediately.",
    requests: [
      {
        path: "/service-account.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"private_key"', '"client_email"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/credentials.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"private_key"', '"client_email"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "ssh-private-key-exposed",
    name: "SSH Private Key Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "An SSH private key is publicly downloadable from the web root, enabling direct server access.",
    fix: "Remove the key from the web root and rotate it (and any authorized_keys it maps to) immediately.",
    requests: [
      {
        path: "/.ssh/id_rsa",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PRIVATE KEY-----"] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/id_rsa",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PRIVATE KEY-----"] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "npmrc-token-exposed",
    name: "npm Auth Token (.npmrc) Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An .npmrc containing an npm auth token is publicly readable, allowing package publish/install under that account.",
    fix: "Remove .npmrc from the web root and revoke the npm token.",
    requests: [
      {
        path: "/.npmrc",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["_authToken", "_auth="], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- CMS-specific exposures ---
  {
    id: "wp-debug-log-exposed",
    name: "WordPress debug.log Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "WordPress debug logging is enabled and the log is publicly readable, leaking stack traces, paths, and sometimes secrets.",
    fix: "Disable WP_DEBUG_LOG in production and remove the exposed log file.",
    requests: [
      {
        path: "/wp-content/debug.log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PHP Notice", "PHP Warning", "PHP Fatal error", "WordPress database error", "Stack trace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-xmlrpc-enabled",
    name: "WordPress XML-RPC Enabled",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "xmlrpc.php is enabled, providing an amplification surface for credential brute-force and pingback-based DDoS.",
    fix: "Disable XML-RPC if unused, or restrict and rate-limit it.",
    requests: [
      {
        path: "/xmlrpc.php",
        matchers: [
          { type: "status", status: [200, 405] },
          { type: "word", words: ["XML-RPC server accepts POST requests only"] },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "drupal-changelog-exposed",
    name: "Drupal Version Disclosed (CHANGELOG.txt)",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "Drupal's CHANGELOG.txt is publicly readable, disclosing the exact core version for targeted exploitation.",
    fix: "Remove or block access to CHANGELOG.txt and keep core patched.",
    requests: [
      {
        path: "/CHANGELOG.txt",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Drupal "] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/core/CHANGELOG.txt",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Drupal "] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "joomla-config-backup-exposed",
    name: "Joomla configuration.php Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A backup of Joomla's configuration.php is publicly readable, exposing database credentials and secrets.",
    fix: "Remove the backup from the web root and rotate the exposed credentials.",
    requests: [
      {
        path: "/configuration.php~",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["JConfig", "public $password", "public $db"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
];

import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const ENV_DUMPS_AND_MANIFESTS: Template[] = [
  // --- Environment variants & database dumps ---
  {
    id: "env-production-exposed",
    name: "Production Environment File Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A production environment file (.env.production / .env.local) is publicly readable and typically contains live secrets.",
    fix: "Remove the file from the web root and rotate every exposed secret.",
    requests: [
      {
        path: "/.env.production",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.env.local",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "sql-dump-exposed",
    name: "Database Dump Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A SQL database dump is publicly downloadable, exposing complete schema and data including potentially credentials and PII.",
    fix: "Remove database dumps from the web root immediately and assess for data exposure.",
    requests: [
      {
        path: "/backup.sql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump", "PostgreSQL database dump"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/database.sql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/dump.sql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "backup-archive-exposed",
    name: "Backup Archive Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A site/source backup archive is publicly downloadable from the web root, frequently containing source code and secrets.",
    fix: "Remove archive files from the web root and store backups outside the document root.",
    requests: [
      {
        path: "/backup.zip",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", part: "header", words: ["application/zip", "application/x-zip", "application/octet-stream"], condition: "or" },
        ],
        matchersCondition: "and",
      },
      {
        path: "/backup.tar.gz",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", part: "header", words: ["application/gzip", "application/x-gzip", "application/x-tar", "application/octet-stream"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Deployment / CI / package manifests ---
  {
    id: "vscode-sftp-exposed",
    name: "VS Code SFTP Config Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A .vscode/sftp.json deployment config is publicly readable and commonly contains SFTP/SSH host credentials.",
    fix: "Remove the file from the web root and rotate the exposed deployment credentials.",
    requests: [
      {
        path: "/.vscode/sftp.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"password"', '"privateKeyPath"', '"host"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "gitlab-ci-exposed",
    name: "GitLab CI Config Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "A .gitlab-ci.yml is publicly readable, disclosing pipeline structure and occasionally embedded variables.",
    fix: "Avoid serving CI configuration from the web root.",
    requests: [
      {
        path: "/.gitlab-ci.yml",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["stages:", "script:", "image:"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "composer-json-exposed",
    name: "composer.json Exposed",
    severity: "low",
    category: "SCA",
    confidence: "high",
    description:
      "composer.json is served from the web root, disclosing the PHP dependency list and versions for CVE correlation.",
    fix: "Do not serve dependency manifests from the public web root.",
    requests: [
      {
        path: "/composer.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"require"', '"require-dev"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "composer-lock-exposed",
    name: "composer.lock Exposed",
    severity: "low",
    category: "SCA",
    confidence: "high",
    description:
      "composer.lock is served from the web root, disclosing exact PHP dependency versions for CVE correlation.",
    fix: "Do not serve lockfiles from the public web root.",
    requests: [
      {
        path: "/composer.lock",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"packages"', '"content-hash"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
];

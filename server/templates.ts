import { Template } from "./templateEngine.js";

// Starter detection pack. Each template confirms the finding by matching the
// response BODY signature and excluding SPA HTML fallbacks (negative matcher),
// so a single-page app that returns index.html for every path is never flagged.
// Grow coverage by adding entries here — no engine changes required.
//
// Paths already covered by the scanner's signature probes (/.env, /.git/config,
// /.git/HEAD, /phpinfo.php, /.aws/credentials, /config.json) are intentionally
// omitted to avoid duplicate findings.

const NOT_HTML = { type: "word" as const, words: ["<!doctype", "<html", "<head", "<body"], negative: true };

export const TEMPLATES: Template[] = [
  {
    id: "spring-actuator-env",
    name: "Spring Boot Actuator /env Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "The Spring Boot Actuator env endpoint is publicly reachable and leaks application configuration, environment variables, and frequently database credentials.",
    fix: "Restrict actuator endpoints to an internal management port and require authentication (management.endpoints.web.exposure.include / Spring Security).",
    requests: [
      {
        path: "/actuator/env",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["propertySources", "systemEnvironment", "systemProperties"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "spring-actuator-health",
    name: "Spring Boot Actuator /health Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "The Spring Boot Actuator health endpoint is publicly reachable, disclosing internal component status and aiding fingerprinting.",
    fix: "Limit actuator exposure and authenticate management endpoints.",
    requests: [
      {
        path: "/actuator/health",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"status":"UP"', '"status": "UP"'], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "dockerfile-exposed",
    name: "Dockerfile Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Dockerfile is served from the web root, revealing base images, build steps, and sometimes embedded secrets or internal paths.",
    fix: "Remove build artifacts from the public web root; serve only the built application.",
    requests: [
      {
        path: "/Dockerfile",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^\\s*FROM\\s+\\S+" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "docker-compose-exposed",
    name: "docker-compose.yml Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A docker-compose file is publicly accessible, exposing service topology, environment variables, ports, and often credentials.",
    fix: "Remove infrastructure manifests from the public web root.",
    requests: [
      {
        path: "/docker-compose.yml",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["services:", "image:", "version:"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "package-json-exposed",
    name: "package.json Exposed",
    severity: "low",
    category: "SCA",
    confidence: "high",
    description:
      "package.json is served from the web root, disclosing the full dependency list and versions that attackers can correlate against known CVEs.",
    fix: "Do not serve package manifests from the public web root.",
    requests: [
      {
        path: "/package.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"dependencies"', '"devDependencies"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "env-backup-exposed",
    name: "Environment File Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A backup copy of an environment file (.env.bak / .env.save / .env.old) is publicly readable and typically contains live credentials.",
    fix: "Remove backup files from the web root and rotate any exposed secrets immediately.",
    requests: [
      {
        path: "/.env.bak",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.env.save",
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
    id: "wp-config-backup",
    name: "WordPress wp-config Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A backup of wp-config.php is publicly readable, exposing database credentials and WordPress authentication keys.",
    fix: "Delete configuration backups from the web root and rotate the exposed database credentials and salts.",
    requests: [
      {
        path: "/wp-config.php.bak",
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
    id: "phpmyadmin-exposed",
    name: "phpMyAdmin Panel Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A phpMyAdmin login panel is publicly reachable, providing a brute-force surface directly onto the database.",
    fix: "Restrict phpMyAdmin to a VPN/allow-list and enforce strong authentication.",
    requests: [
      {
        path: "/phpmyadmin/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["phpMyAdmin", "pma_username"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "adminer-exposed",
    name: "Adminer Database Tool Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "Adminer is publicly reachable, exposing a database administration login to the internet.",
    fix: "Remove Adminer from production or restrict it behind authentication and network controls.",
    requests: [
      {
        path: "/adminer.php",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Adminer", "Login - Adminer"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "apache-server-status",
    name: "Apache mod_status Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The Apache server-status page is publicly reachable, leaking active request URLs, client IPs, and server internals.",
    fix: 'Restrict <Location /server-status> to localhost or trusted IPs.',
    requests: [
      {
        path: "/server-status",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Apache Server Status", "Server uptime"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "laravel-telescope",
    name: "Laravel Telescope Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "Laravel Telescope is reachable in production, exposing requests, queries, mail, and sensitive runtime data.",
    fix: "Disable Telescope in production or gate it behind the Telescope authorization gate.",
    requests: [
      {
        path: "/telescope/requests",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Telescope", "Laravel"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "swagger-ui-exposed",
    name: "Swagger UI Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "Interactive Swagger/OpenAPI UI is publicly reachable, documenting the full API surface for attackers.",
    fix: "Restrict API documentation to authenticated/internal users in production.",
    requests: [
      {
        path: "/swagger-ui/index.html",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Swagger UI", "swagger-ui"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
];

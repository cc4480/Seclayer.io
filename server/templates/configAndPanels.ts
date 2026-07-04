import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const CONFIG_AND_PANELS: Template[] = [
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
];

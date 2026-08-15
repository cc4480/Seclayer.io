import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const ADMIN_TOOLS_AND_SOURCE: Template[] = [
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

  // --- Source / VCS / config file exposure ---
  {
    id: "git-credentials-exposed",
    name: "Git Credentials File Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A .git-credentials file is publicly readable and embeds credentials directly inside repository URLs.",
    fix: "Remove the file from the web root and rotate the exposed credentials.",
    requests: [
      {
        path: "/.git-credentials",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "https?://[^:/]+:[^@]+@" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "web-config-exposed",
    name: "IIS web.config Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An ASP.NET/IIS web.config is publicly readable, often exposing connection strings, machine keys, and app settings.",
    fix: "Block direct access to web.config and rotate any exposed connection strings or machine keys.",
    requests: [
      {
        path: "/web.config",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<configuration", "<system.webServer", "<connectionStrings"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "webinf-web-xml-exposed",
    name: "Java WEB-INF/web.xml Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Java deployment descriptor WEB-INF/web.xml is publicly readable, disclosing servlet mappings, parameters, and internal structure.",
    fix: "Ensure the servlet container denies direct access to /WEB-INF/.",
    requests: [
      {
        path: "/WEB-INF/web.xml",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<web-app", "<servlet"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "htaccess-exposed",
    name: "Apache .htaccess Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "An .htaccess file is publicly readable, revealing rewrite rules, access controls, and internal path structure.",
    fix: "Configure the server to deny access to files beginning with a dot.",
    requests: [
      {
        path: "/.htaccess",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["RewriteEngine", "RewriteRule", "<IfModule", "Order allow"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "htpasswd-exposed",
    name: "Apache .htpasswd Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An .htpasswd file is publicly readable, exposing usernames and password hashes for offline cracking.",
    fix: "Deny web access to .htpasswd and rotate the affected credentials.",
    requests: [
      {
        path: "/.htpasswd",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: ":\\$(apr1|2[aby]|1|5|6)\\$" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
];

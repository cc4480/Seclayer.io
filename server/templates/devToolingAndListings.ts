import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const DEV_TOOLING_AND_LISTINGS: Template[] = [
  // --- Dev / CI tooling exposed ---
  {
    id: "laravel-debugbar-exposed",
    name: "Laravel Debugbar Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "Laravel Debugbar assets are reachable, indicating debug mode in production and leaking queries/requests.",
    fix: "Disable Debugbar and set APP_DEBUG=false in production.",
    requests: [
      {
        path: "/_debugbar/open",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["phpdebugbar", "PhpDebugBar"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "jenkins-exposed",
    name: "Jenkins Login Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Jenkins CI login is publicly reachable, presenting a high-value RCE target if misconfigured or unpatched.",
    fix: "Place Jenkins behind a VPN/SSO and keep it updated; never expose it directly.",
    requests: [
      {
        path: "/login",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Jenkins", "j_username"], condition: "and" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "server-log-exposed",
    name: "Server Log File Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A server/application log file is publicly readable, leaking stack traces, internal paths, and request details.",
    fix: "Store logs outside the web root and deny direct access to log files.",
    requests: [
      {
        path: "/error_log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PHP Fatal error", "PHP Warning", "[error]", "Stack trace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/logs/error.log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PHP Fatal error", "PHP Warning", "[error]", "Stack trace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Dangling-resource / subdomain takeover (service "not found" fingerprints) ---
  {
    id: "subdomain-takeover",
    name: "Potential Subdomain Takeover",
    severity: "high",
    category: "EASM",
    confidence: "high",
    description:
      "The host responds with a third-party service's 'unclaimed resource' page, indicating a dangling DNS record an attacker could claim to take over the (sub)domain.",
    fix: "Remove the dangling DNS record or re-claim the resource on the referenced provider.",
    requests: [
      {
        path: "/",
        matchers: [
          {
            type: "word",
            words: [
              "There isn't a GitHub Pages site here.",
              "herokucdn.com",
              "NoSuchBucket",
              "Sorry, this shop is currently unavailable",
              "Fastly error: unknown domain",
              "The gods are wise, but do not know of the site which you seek.",
              "is not configured for an account",
              "Whatever you were looking for doesn't currently exist at this address",
            ],
            condition: "or",
          },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Cloud storage / directory listing ---
  {
    id: "s3-bucket-listing",
    name: "S3 Bucket Listing Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The endpoint returns an S3 XML bucket listing, exposing object keys (and potentially their contents) to anonymous users.",
    fix: "Disable public list permissions on the bucket and apply a restrictive bucket policy.",
    requests: [
      {
        path: "/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<ListBucketResult"] },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "open-directory-listing",
    name: "Open Directory Listing Enabled",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The server returns an auto-generated directory index, exposing the file listing of the document root or a subdirectory.",
    fix: "Disable automatic directory indexing (Apache Options -Indexes / nginx autoindex off).",
    requests: [
      {
        path: "/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<title>Index of /", "[To Parent Directory]", "Directory listing for /"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
];

import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const FRAMEWORK_TOOLING_AND_API: Template[] = [
  // --- Framework actuators / dev tooling exposed in production ---
  {
    id: "jolokia-exposed",
    name: "Jolokia JMX Endpoint Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Jolokia endpoint exposes JMX over HTTP, allowing enumeration (and sometimes invocation) of MBeans — a known RCE vector.",
    fix: "Disable Jolokia in production or restrict it to authenticated internal access.",
    requests: [
      {
        path: "/jolokia/list",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["jolokia", '"agent"', '"request"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "actuator-configprops-exposed",
    name: "Spring Actuator /configprops Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The Spring Actuator configprops endpoint is reachable, disclosing bound configuration properties and infrastructure details.",
    fix: "Restrict actuator exposure and require authentication on management endpoints.",
    requests: [
      {
        path: "/actuator/configprops",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["contexts", "beans", "configProps", "prefix"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "symfony-profiler-exposed",
    name: "Symfony Profiler Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Symfony web profiler is reachable in production, exposing requests, queries, sessions, and configuration.",
    fix: "Disable the profiler/web toolbar in the production environment.",
    requests: [
      {
        path: "/_profiler",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Symfony Profiler", "sf-toolbar", "WebProfilerBundle"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "rails-info-exposed",
    name: "Rails Application Info Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The Rails /rails/info endpoints are reachable, indicating development mode in production and disclosing routes and versions.",
    fix: "Run Rails in the production environment and ensure detailed error/info pages are disabled.",
    requests: [
      {
        path: "/rails/info/properties",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Ruby version", "Rails version", "Middleware"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-user-enumeration",
    name: "WordPress REST User Enumeration",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The WordPress REST users endpoint returns the list of accounts, enabling username enumeration for targeted brute-force.",
    fix: "Restrict or disable the wp/v2/users REST endpoint for unauthenticated requests.",
    requests: [
      {
        path: "/wp-json/wp/v2/users",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"slug"', '"name"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "solr-admin-exposed",
    name: "Apache Solr Admin Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Apache Solr admin interface is publicly reachable, exposing core management and a known RCE surface.",
    fix: "Restrict the Solr admin UI/API to trusted internal networks.",
    requests: [
      {
        path: "/solr/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Solr Admin", "Apache SOLR", "solr-admin"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- API specs / GraphQL tooling ---
  {
    id: "openapi-spec-exposed",
    name: "OpenAPI/Swagger Spec Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "A machine-readable OpenAPI/Swagger specification is publicly reachable, fully documenting the API surface for attackers.",
    fix: "Restrict API specifications to authenticated/internal consumers in production.",
    requests: [
      {
        path: "/openapi.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"openapi"', '"swagger"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/v2/api-docs",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"swagger"', '"openapi"', '"paths"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "graphiql-exposed",
    name: "GraphiQL / GraphQL Playground Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "An interactive GraphQL IDE is publicly reachable, easing schema exploration and query crafting against the API.",
    fix: "Disable GraphiQL/Playground in production.",
    requests: [
      {
        path: "/graphiql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["graphiql", "GraphQL Playground", "GraphiQL"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
];

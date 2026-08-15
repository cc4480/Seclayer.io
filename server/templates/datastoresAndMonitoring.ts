import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const DATASTORES_AND_MONITORING: Template[] = [
  // --- Exposed datastores / services over HTTP ---
  {
    id: "elasticsearch-exposed",
    name: "Elasticsearch Cluster Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An Elasticsearch HTTP API is publicly reachable, allowing index enumeration and unauthenticated data access.",
    fix: "Bind Elasticsearch to an internal interface and require authentication (e.g. X-Pack/security).",
    requests: [
      {
        path: "/_cluster/health",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"cluster_name"', '"number_of_nodes"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "couchdb-exposed",
    name: "Apache CouchDB Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A CouchDB instance/admin UI is publicly reachable, exposing databases to unauthenticated access.",
    fix: "Restrict CouchDB to internal networks and configure an admin account.",
    requests: [
      {
        path: "/_utils/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Fauxton", "couchdb"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "kubernetes-api-exposed",
    name: "Kubernetes API Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Kubernetes API server version endpoint is publicly reachable, indicating an exposed control plane.",
    fix: "Restrict the Kubernetes API to trusted networks and disable anonymous auth.",
    requests: [
      {
        path: "/version",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"gitVersion"', '"goVersion"', '"compiler"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "rabbitmq-management-exposed",
    name: "RabbitMQ Management API Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The RabbitMQ management API is publicly reachable, disclosing broker version and topology.",
    fix: "Restrict the RabbitMQ management plugin to internal access.",
    requests: [
      {
        path: "/api/overview",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["rabbitmq_version", "management_version"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Monitoring / observability dashboards ---
  {
    id: "prometheus-metrics-exposed",
    name: "Prometheus Metrics Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Prometheus metrics endpoint is publicly reachable, leaking internal performance, hostnames, and operational detail.",
    fix: "Restrict /metrics to internal scrapers or require authentication.",
    requests: [
      {
        path: "/metrics",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["# HELP", "# TYPE"], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "grafana-exposed",
    name: "Grafana Instance Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Grafana dashboard login is publicly reachable, providing a brute-force surface and (on old versions) known exploits.",
    fix: "Place Grafana behind SSO/VPN and keep it patched.",
    requests: [
      {
        path: "/login",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Grafana", "grafana-app"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "kibana-exposed",
    name: "Kibana Instance Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Kibana interface is publicly reachable, exposing dashboards over the underlying Elasticsearch data.",
    fix: "Restrict Kibana to internal/authenticated access.",
    requests: [
      {
        path: "/app/kibana",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["kbn-injected-metadata", "kibana"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
];

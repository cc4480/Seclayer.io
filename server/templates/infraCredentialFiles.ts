import { Template } from "../templateEngine.js";
import { NOT_HTML } from "./shared.js";

export const INFRA_CREDENTIAL_FILES: Template[] = [
  // --- Infrastructure / cloud credential files ---
  {
    id: "kubeconfig-exposed",
    name: "Kubeconfig Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A kubeconfig file is publicly readable, embedding cluster endpoints and client certificate/token credentials.",
    fix: "Remove the file from the web root and rotate the embedded cluster credentials.",
    requests: [
      {
        path: "/.kube/config",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["client-certificate-data", "client-key-data", "current-context:"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "terraform-state-exposed",
    name: "Terraform State Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A Terraform state file is publicly readable; state frequently contains plaintext secrets, keys, and full infrastructure detail.",
    fix: "Remove state from the web root, use a secured remote backend, and rotate any exposed secrets.",
    requests: [
      {
        path: "/terraform.tfstate",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"terraform_version"', '"lineage"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.terraform/terraform.tfstate",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"terraform_version"', '"lineage"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "docker-config-exposed",
    name: "Docker Registry Config Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Docker client config is publicly readable, exposing base64-encoded registry credentials.",
    fix: "Remove the file from the web root and rotate the registry credentials.",
    requests: [
      {
        path: "/.docker/config.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"auths"', '"auth"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.dockercfg",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"auth"', "https://index.docker.io"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "netrc-exposed",
    name: ".netrc Credentials Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A .netrc file is publicly readable, exposing machine login/password pairs used for automated authentication.",
    fix: "Remove .netrc from the web root and rotate the exposed credentials.",
    requests: [
      {
        path: "/.netrc",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "machine\\s+\\S+\\s+(login|password)\\s+\\S+" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "aws-config-exposed",
    name: "AWS CLI Config Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "An AWS CLI config file is publicly readable, disclosing profiles, regions, and role/account references.",
    fix: "Remove the file from the web root.",
    requests: [
      {
        path: "/.aws/config",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "\\[(default|profile )" },
          { type: "word", words: ["region", "role_arn", "output"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
];

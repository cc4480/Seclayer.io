import { Template } from "./templateEngine.js";
import { CONFIG_AND_PANELS } from "./templates/configAndPanels.js";
import { ADMIN_TOOLS_AND_SOURCE } from "./templates/adminToolsAndSource.js";
import { ENV_DUMPS_AND_MANIFESTS } from "./templates/envDumpsAndManifests.js";
import { FRAMEWORK_TOOLING_AND_API } from "./templates/frameworkToolingAndApi.js";
import { DATASTORES_AND_MONITORING } from "./templates/datastoresAndMonitoring.js";
import { KEYS_AND_CMS_EXPOSURE } from "./templates/keysAndCmsExposure.js";
import { DEV_TOOLING_AND_LISTINGS } from "./templates/devToolingAndListings.js";
import { INFRA_CREDENTIAL_FILES } from "./templates/infraCredentialFiles.js";
import { ADMIN_BACKUPS_AND_ARTIFACTS } from "./templates/adminBackupsAndArtifacts.js";
import { TEMPLATE_TAGS } from "./templates/tags.js";

// Starter detection pack. Each template confirms the finding by matching the
// response BODY signature and excluding SPA HTML fallbacks (negative matcher),
// so a single-page app that returns index.html for every path is never flagged.
// Grow coverage by adding entries to the grouped modules under ./templates/ —
// no engine changes required.
//
// Paths already covered by the scanner's signature probes (/.env, /.git/config,
// /.git/HEAD, /phpinfo.php, /.aws/credentials, /config.json) are intentionally
// omitted to avoid duplicate findings.

const RAW_TEMPLATES: Template[] = [
  ...CONFIG_AND_PANELS,
  ...ADMIN_TOOLS_AND_SOURCE,
  ...ENV_DUMPS_AND_MANIFESTS,
  ...FRAMEWORK_TOOLING_AND_API,
  ...DATASTORES_AND_MONITORING,
  ...KEYS_AND_CMS_EXPOSURE,
  ...DEV_TOOLING_AND_LISTINGS,
  ...INFRA_CREDENTIAL_FILES,
  ...ADMIN_BACKUPS_AND_ARTIFACTS,
];

export const TEMPLATES: Template[] = RAW_TEMPLATES.map((t) => ({
  ...t,
  tags: TEMPLATE_TAGS[t.id],
}));

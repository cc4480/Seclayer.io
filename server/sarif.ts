/** Convert a completed scan's findings to SARIF 2.1.0 for GitHub Security tab upload */
export function generateSarif(scan: import('../src/types.js').Scan) {
  const lvl = (s: string) => s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note';
  const score = (s: string) => s === 'critical' ? '9.5' : s === 'high' ? '7.5' : s === 'medium' ? '5.0' : '2.0';
  const slug = (t: string) => t.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

  const findings = scan.findings ?? [];
  const ruleMap = new Map<string, typeof findings[0]>();
  for (const f of findings) if (!ruleMap.has(slug(f.title))) ruleMap.set(slug(f.title), f);

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Seclayer',
          version: '2.2.0',
          informationUri: 'https://seclayer.io',
          rules: [...ruleMap.entries()].map(([id, f]) => ({
            id,
            name: f.title,
            shortDescription: { text: f.title },
            fullDescription: { text: f.description },
            help: { text: `Fix: ${f.fix}`, markdown: `**Fix:** ${f.fix}` },
            helpUri: 'https://seclayer.io',
            properties: { 'security-severity': score(f.severity), tags: ['security', f.severity] },
          })),
        },
      },
      results: findings.map(f => ({
        ruleId: slug(f.title),
        level: lvl(f.severity),
        message: { text: `${f.description}\n\nFix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.endpoint || scan.url } } }],
        properties: { severity: f.severity, category: f.category },
      })),
      artifacts: [{ location: { uri: scan.url }, description: { text: 'Seclayer scan target' } }],
      properties: { seclayerScore: scan.score, seclayerSeverity: scan.severity },
    }],
  };
}

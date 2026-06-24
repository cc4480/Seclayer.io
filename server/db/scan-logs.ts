// In-memory scan log store — transient, only relevant during an active scan.
export class ScanLogsStore {
  private readonly scanLogs = new Map<string, string[]>();

  appendScanLog(scanId: string, message: string): void {
    if (!this.scanLogs.has(scanId)) this.scanLogs.set(scanId, []);
    const ts = new Date().toISOString();
    this.scanLogs.get(scanId)!.push(`[${ts}] ${message}`);
  }

  getScanLogs(scanId: string): string[] {
    return this.scanLogs.get(scanId) ?? [];
  }
}

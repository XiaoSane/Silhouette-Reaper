import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class StringsExtractorEngine implements ForensicEngine {
  engineId = 'engine-strings';
  name = 'Printable Strings & Indicator Extractor';
  version = '2.0.0';

  supports(_context: ForensicExecutionContext): boolean {
    return true; // Runs on all evidence
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;
    const warnings: string[] = [];
    const limitations: string[] = [];

    // Efficient extraction of ASCII printable strings (min length 4) without per-character allocations
    const asciiStrings: string[] = [];
    const maxScanBytes = Math.min(buf.length, 10 * 1024 * 1024); // 10MB limit

    let strStart = -1;
    for (let i = 0; i < maxScanBytes; i++) {
      const byte = buf[i];
      if (byte >= 32 && byte <= 126) {
        if (strStart === -1) strStart = i;
      } else {
        if (strStart !== -1) {
          if (i - strStart >= 4) {
            asciiStrings.push(buf.toString('latin1', strStart, i));
          }
          strStart = -1;
        }
      }
    }
    if (strStart !== -1 && maxScanBytes - strStart >= 4) {
      asciiStrings.push(buf.toString('latin1', strStart, maxScanBytes));
    }

    // Extract UTF-16LE wide strings (Windows executables, registry keys, PowerShell commands)
    let wideStart = -1;
    for (let i = 0; i + 1 < maxScanBytes; i += 2) {
      const b0 = buf[i];
      const b1 = buf[i + 1];
      if (b0 >= 32 && b0 <= 126 && b1 === 0x00) {
        if (wideStart === -1) wideStart = i;
      } else {
        if (wideStart !== -1) {
          if ((i - wideStart) / 2 >= 4) {
            asciiStrings.push(buf.toString('utf16le', wideStart, i));
          }
          wideStart = -1;
        }
      }
    }

    const allText = asciiStrings.join('\n');

    // Pattern Matching
    // 1. IPv4 addresses
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const ips = Array.from(new Set(allText.match(ipv4Regex) || [])).filter(
      (ip) => !ip.startsWith('0.') && !ip.startsWith('127.0.0.') && ip !== '255.255.255.255'
    );

    // 2. URLs
    const urlRegex = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/gi;
    const urls = Array.from(new Set(allText.match(urlRegex) || [])).slice(0, 30);

    // 3. Email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = Array.from(new Set(allText.match(emailRegex) || [])).slice(0, 30);

    // 4. File paths
    const winPathRegex = /[a-zA-Z]:\\[a-zA-Z0-9._\- \t\\]+/g;
    const unixPathRegex = /\/(?:etc|var|usr|bin|tmp|home|opt|dev|root)\/[a-zA-Z0-9._\-\/]+/g;
    const winPaths = Array.from(new Set(allText.match(winPathRegex) || [])).slice(0, 20);
    const unixPaths = Array.from(new Set(allText.match(unixPathRegex) || [])).slice(0, 20);

    // 5. Registry keys
    const regRegex = /(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[a-zA-Z0-9._\-\\]+/gi;
    const registryKeys = Array.from(new Set(allText.match(regRegex) || [])).slice(0, 20);

    // 6. Security & Execution Indicators
    const indicatorPatterns = [
      { pattern: /powershell(\.exe)?\s+(-(enc|encodedcommand|nop|w\s+hidden))/i, label: 'Encoded/Obfuscated PowerShell' },
      { pattern: /cmd(\.exe)?\s+\/c/i, label: 'CMD Command Execution' },
      { pattern: /certutil(\.exe)?\s+(-urlcache|-decode)/i, label: 'Certutil Ingress / Decoding' },
      { pattern: /vssadmin(\.exe)?\s+delete\s+shadows/i, label: 'Shadow Copy Deletion' },
      { pattern: /Invoke-(Expression|WebRequest|RestMethod|Mimikatz)/i, label: 'PowerShell Offensive Invocation' },
      { pattern: /rundll32(\.exe)?\s+[a-zA-Z0-9._]+,\w+/i, label: 'Rundll32 DLL Execution' },
      { pattern: /schtasks(\.exe)?\s+\/create/i, label: 'Scheduled Task Creation' },
      { pattern: /bitsadmin(\.exe)?\s+\/transfer/i, label: 'BITSAdmin File Transfer' },
    ];

    const detectedIndicators: { label: string; matched_string: string }[] = [];
    for (const ind of indicatorPatterns) {
      const m = allText.match(ind.pattern);
      if (m) {
        detectedIndicators.push({
          label: ind.label,
          matched_string: m[0],
        });
      }
    }

    const artifacts = [
      {
        artifact_type: 'EXTRACTED_INDICATORS',
        name: 'Extracted Strings, Network & System Indicators',
        category: 'STRING' as const,
        data_payload: {
          total_strings_extracted: asciiStrings.length,
          ipv4_addresses: ips.slice(0, 20),
          urls: urls,
          emails: emails,
          windows_paths: winPaths,
          unix_paths: unixPaths,
          registry_keys: registryKeys,
          detected_execution_indicators: detectedIndicators,
          sample_strings: asciiStrings.slice(0, 40),
        },
      },
    ];

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'STRINGS_INDICATOR_EXTRACTION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          strings_count: asciiStrings.length,
          ips_found: ips.length,
          urls_found: urls.length,
          indicators_found: detectedIndicators.length,
        },
        warnings,
        errors: [],
      },
      artifacts,
      timelineEvents: [],
      findings: [],
      warnings,
      limitations,
    };
  }
}

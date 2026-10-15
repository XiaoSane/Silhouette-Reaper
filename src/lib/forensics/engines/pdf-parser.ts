import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class PdfForensicEngine implements ForensicEngine {
  engineId = 'engine-pdf-parser';
  name = 'PDF Document & Structure Forensic Engine';
  version = '2.3.1';

  supports(context: ForensicExecutionContext): boolean {
    const mime = context.detectedMime || context.declaredMime || '';
    const ext = (context.detectedExtension || context.originalFilename.split('.').pop() || '').toLowerCase();
    return mime === 'application/pdf' || ext === 'pdf';
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;
    const warnings: string[] = [];
    const limitations: string[] = [];
    const artifacts: EngineResult['artifacts'] = [];
    const timelineEvents: EngineResult['timelineEvents'] = [];

    const rawString = buf.toString('latin1');

    // 1. Version Check
    const versionMatch = rawString.match(/%PDF-([0-9.]+)/);
    const pdfVersion = versionMatch ? versionMatch[1] : 'Unknown';

    // 2. Incremental Update Count (number of %%EOF markers)
    const eofMatches = rawString.match(/%%EOF/g) || [];
    const incrementalUpdates = Math.max(0, eofMatches.length - 1);

    // 3. Security & Active Content Checks
    const hasJavaScript = /\/JavaScript|\/JS\b/i.test(rawString);
    const hasOpenAction = /\/OpenAction\b/i.test(rawString);
    const hasLaunch = /\/Launch\b/i.test(rawString);
    const hasEmbeddedFiles = /\/EmbeddedFiles\b|\/EF\b/i.test(rawString);
    const isEncrypted = /\/Encrypt\b/i.test(rawString);
    const isLinearized = /\/Linearized\b/i.test(rawString);

    // 4. Metadata dictionary extraction
    const metadata: Record<string, string> = {};
    const extractField = (field: string) => {
      const regex = new RegExp(`\\/${field}\\s*(?:\\(([^\\)]+)\\)|<([0-9a-fA-F]+)>)`, 'i');
      const match = rawString.match(regex);
      if (match) {
        if (match[1]) return match[1];
        if (match[2]) {
          try {
            return Buffer.from(match[2], 'hex').toString('utf8');
          } catch {
            return match[2];
          }
        }
      }
      return null;
    };

    const title = extractField('Title');
    const author = extractField('Author');
    const creator = extractField('Creator');
    const producer = extractField('Producer');
    const creationDateRaw = extractField('CreationDate');
    const modDateRaw = extractField('ModDate');

    if (title) metadata.title = title;
    if (author) metadata.author = author;
    if (creator) metadata.creator = creator;
    if (producer) metadata.producer = producer;

    // Helper to parse PDF date: D:YYYYMMDDHHmmSSOHH'mm'
    const parsePdfDate = (raw: string | null): { iso: string | null; offset: string } => {
      if (!raw) return { iso: null, offset: 'UTC' };
      const clean = raw.replace(/^D:/, '').replace(/'/g, '');
      const m = clean.match(/^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([+\-Z])?(\d{2})?(\d{2})?/);
      if (!m) return { iso: null, offset: 'UTC' };
      const year = parseInt(m[1], 10);
      const month = m[2] ? parseInt(m[2], 10) - 1 : 0;
      const day = m[3] ? parseInt(m[3], 10) : 1;
      const hour = m[4] ? parseInt(m[4], 10) : 0;
      const min = m[5] ? parseInt(m[5], 10) : 0;
      const sec = m[6] ? parseInt(m[6], 10) : 0;

      let utcMs = Date.UTC(year, month, day, hour, min, sec);
      let offsetStr = 'UTC';

      const sign = m[7];
      const tzHr = m[8];
      const tzMin = m[9];

      if (sign && (sign === '+' || sign === '-') && tzHr) {
        const offsetMins = parseInt(tzHr, 10) * 60 + (tzMin ? parseInt(tzMin, 10) : 0);
        const offsetMs = offsetMins * 60 * 1000;
        utcMs = sign === '+' ? utcMs - offsetMs : utcMs + offsetMs;
        offsetStr = `${sign}${tzHr.padStart(2, '0')}:${(tzMin || '00').padStart(2, '0')}`;
      } else if (sign === 'Z') {
        offsetStr = 'Z';
      }

      const date = new Date(utcMs);
      return {
        iso: !isNaN(date.getTime()) ? date.toISOString() : null,
        offset: offsetStr,
      };
    };

    const creationDateInfo = parsePdfDate(creationDateRaw);
    const modDateInfo = parsePdfDate(modDateRaw);

    // Page count estimate (number of /Type /Page\b)
    const pageMatches = rawString.match(/\/Type\s*\/Page\b/g) || [];
    const estimatedPages = pageMatches.length;

    artifacts.push({
      artifact_type: 'PDF_DOCUMENT_METADATA',
      name: 'PDF Document Catalog & Metadata',
      category: 'METADATA',
      data_payload: {
        pdf_version: pdfVersion,
        page_count: estimatedPages,
        incremental_updates_count: incrementalUpdates,
        linearized_fast_web_view: isLinearized,
        encrypted: isEncrypted,
        active_content: {
          has_javascript: hasJavaScript,
          has_open_action: hasOpenAction,
          has_launch_action: hasLaunch,
          has_embedded_files: hasEmbeddedFiles,
        },
        document_properties: metadata,
        raw_creation_date: creationDateRaw,
        raw_mod_date: modDateRaw,
      },
    });

    // Timeline Events
    if (creationDateInfo.iso) {
      timelineEvents.push({
        timestamp_utc: creationDateInfo.iso,
        timestamp_raw: creationDateRaw || '',
        timestamp_precision: 'SECOND',
        timezone_offset: creationDateInfo.offset,
        event_type: 'DOCUMENT_CREATION_DATE',
        source_parser: this.name,
        source_field: 'CreationDate',
        description: `PDF created by application: ${producer || creator || 'Unknown Producer'}`,
        confidence: 'DEFINITIVE',
      });
    }

    if (modDateInfo.iso) {
      timelineEvents.push({
        timestamp_utc: modDateInfo.iso,
        timestamp_raw: modDateRaw || '',
        timestamp_precision: 'SECOND',
        timezone_offset: modDateInfo.offset,
        event_type: 'DOCUMENT_MODIFIED_DATE',
        source_parser: this.name,
        source_field: 'ModDate',
        description: 'PDF document revision/modification recorded',
        confidence: 'DEFINITIVE',
      });
    }

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'PDF_FORENSIC_EXAMINATION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          pdf_version: pdfVersion,
          page_count: estimatedPages,
          has_javascript: hasJavaScript,
        },
        warnings,
        errors: [],
      },
      artifacts,
      timelineEvents,
      findings: [],
      warnings,
      limitations,
    };
  }
}

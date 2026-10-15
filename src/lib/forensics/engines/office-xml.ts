import AdmZip from 'adm-zip';
import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class OfficeXmlEngine implements ForensicEngine {
  engineId = 'engine-office-xml';
  name = 'Office OpenXML & Document Forensic Engine';
  version = '1.8.2';

  supports(context: ForensicExecutionContext): boolean {
    const mime = context.detectedMime || context.declaredMime || '';
    const ext = (context.detectedExtension || context.originalFilename.split('.').pop() || '').toLowerCase();
    return (
      mime.includes('openxmlformats') ||
      mime.includes('wordprocessingml') ||
      mime.includes('spreadsheetml') ||
      mime.includes('presentationml') ||
      ['docx', 'xlsx', 'pptx', 'docm', 'xlsm'].includes(ext)
    );
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;
    const warnings: string[] = [];
    const limitations: string[] = [];
    const artifacts: EngineResult['artifacts'] = [];
    const timelineEvents: EngineResult['timelineEvents'] = [];

    try {
      const zip = new AdmZip(buf);
      const zipEntries = zip.getEntries();

      let coreXml = '';
      let appXml = '';
      let hasVba = false;
      let hiddenWorksheets: string[] = [];

      for (const entry of zipEntries) {
        const entryLower = entry.entryName.toLowerCase();
        if (entryLower.includes('vbaproject.bin') || entryLower.includes('vba/') || entryLower.includes('/vba')) {
          hasVba = true;
        }
        if (entry.entryName === 'docProps/core.xml') {
          coreXml = entry.getData().toString('utf8');
        } else if (entry.entryName === 'docProps/app.xml') {
          appXml = entry.getData().toString('utf8');
        } else if (entry.entryName === 'xl/workbook.xml') {
          const wb = entry.getData().toString('utf8');
          const sheetMatches = wb.matchAll(/<sheet[^>]+name="([^"]+)"[^>]+state="hidden"[^>]*>/gi);
          for (const m of sheetMatches) {
            hiddenWorksheets.push(m[1]);
          }
        }
      }

      // Parse core.xml properties
      const parseTag = (xml: string, tag: string) => {
        const match = xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
        return match ? match[1].trim() : null;
      };

      const creator = parseTag(coreXml, 'dc:creator');
      const lastModifiedBy = parseTag(coreXml, 'cp:lastModifiedBy');
      const revision = parseTag(coreXml, 'cp:revision');
      const createdRaw = parseTag(coreXml, 'dcterms:created');
      const modifiedRaw = parseTag(coreXml, 'dcterms:modified');
      const title = parseTag(coreXml, 'dc:title');

      // Parse app.xml properties
      const application = parseTag(appXml, 'Application');
      const appVersion = parseTag(appXml, 'AppVersion');
      const totalTime = parseTag(appXml, 'TotalTime');
      const pages = parseTag(appXml, 'Pages');
      const words = parseTag(appXml, 'Words');

      artifacts.push({
        artifact_type: 'OFFICE_DOCUMENT_METADATA',
        name: 'Office OpenXML Core & App Properties',
        category: 'METADATA',
        data_payload: {
          title,
          creator,
          last_modified_by: lastModifiedBy,
          revision_number: revision ? parseInt(revision, 10) : null,
          editing_time_minutes: totalTime ? parseInt(totalTime, 10) : null,
          application,
          app_version: appVersion,
          page_count: pages ? parseInt(pages, 10) : null,
          word_count: words ? parseInt(words, 10) : null,
          has_vba_macros: hasVba,
          hidden_worksheets: hiddenWorksheets,
          total_package_entries: zipEntries.length,
        },
      });

      // Timeline events
      if (createdRaw) {
        const d = new Date(createdRaw);
        if (!isNaN(d.getTime())) {
          timelineEvents.push({
            timestamp_utc: d.toISOString(),
            timestamp_raw: createdRaw,
            timestamp_precision: 'SECOND',
            timezone_offset: 'UTC',
            event_type: 'OFFICE_CREATION_DATE',
            source_parser: this.name,
            source_field: 'dcterms:created',
            description: `Document created by author: ${creator || 'Unknown'} (App: ${application || 'Office'})`,
            confidence: 'DEFINITIVE',
          });
        }
      }

      if (modifiedRaw) {
        const d = new Date(modifiedRaw);
        if (!isNaN(d.getTime())) {
          timelineEvents.push({
            timestamp_utc: d.toISOString(),
            timestamp_raw: modifiedRaw,
            timestamp_precision: 'SECOND',
            timezone_offset: 'UTC',
            event_type: 'OFFICE_MODIFICATION_DATE',
            source_parser: this.name,
            source_field: 'dcterms:modified',
            description: `Document modified by: ${lastModifiedBy || 'Unknown'} (Revision: ${revision || '1'})`,
            confidence: 'DEFINITIVE',
          });
        }
      }
    } catch (err: any) {
      warnings.push(`Office XML parsing warning: ${err.message || 'Error reading OPC package structure'}`);
    }

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'OFFICE_XML_EXAMINATION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          artifacts_extracted: artifacts.length,
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

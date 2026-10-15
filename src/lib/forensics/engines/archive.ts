import AdmZip from 'adm-zip';
import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class ArchiveForensicEngine implements ForensicEngine {
  engineId = 'engine-archive';
  name = 'Archive & Compressed Container Forensic Engine';
  version = '2.2.0';

  supports(context: ForensicExecutionContext): boolean {
    const mime = context.detectedMime || context.declaredMime || '';
    const ext = (context.detectedExtension || context.originalFilename.split('.').pop() || '').toLowerCase();
    return (
      mime === 'application/zip' ||
      mime === 'application/x-zip-compressed' ||
      ['zip', 'jar', 'apk', 'war'].includes(ext)
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
      let suspiciousPathTraversal = false;
      const pathTraversalEntries: string[] = [];
      const nestedArchives: string[] = [];
      const entryList: any[] = [];

      // 1. Raw buffer scan for Zip Slip / Path Traversal in Local / Central Directory headers
      let offset = 0;
      while (offset + 30 <= buf.length) {
        // Look for Local File Header signature: 0x04034B50 (PK\x03\x04)
        if (buf[offset] === 0x50 && buf[offset + 1] === 0x4b && buf[offset + 2] === 0x03 && buf[offset + 3] === 0x04) {
          const fnLen = buf.readUInt16LE(offset + 26);
          const extraLen = buf.readUInt16LE(offset + 28);
          if (offset + 30 + fnLen <= buf.length) {
            const rawName = buf.toString('utf8', offset + 30, offset + 30 + fnLen);
            if (
              rawName.includes('../') ||
              rawName.includes('..\\') ||
              rawName.startsWith('/') ||
              rawName.startsWith('\\') ||
              /^[a-zA-Z]:[\\\/]/.test(rawName)
            ) {
              suspiciousPathTraversal = true;
              if (!pathTraversalEntries.includes(rawName)) {
                pathTraversalEntries.push(rawName);
              }
            }
          }
        }
        offset++;
      }

      // 2. High-level structure analysis with AdmZip
      const zip = new AdmZip(buf);
      const entries = zip.getEntries();

      let totalUncompressedSize = 0;
      let totalCompressedSize = 0;

      for (const entry of entries) {
        const uncompressed = entry.header.size;
        const compressed = entry.header.compressedSize;
        totalUncompressedSize += uncompressed;
        totalCompressedSize += compressed;

        const name = entry.entryName;

        // Check for Zip Slip in parsed entry name
        if (
          name.includes('../') ||
          name.includes('..\\') ||
          name.startsWith('/') ||
          name.startsWith('\\') ||
          /^[a-zA-Z]:[\\\/]/.test(name)
        ) {
          suspiciousPathTraversal = true;
          if (!pathTraversalEntries.includes(name)) {
            pathTraversalEntries.push(name);
          }
        }

        // Check for nested archive
        const lower = name.toLowerCase();
        if (
          lower.endsWith('.zip') ||
          lower.endsWith('.tar') ||
          lower.endsWith('.gz') ||
          lower.endsWith('.7z') ||
          lower.endsWith('.iso')
        ) {
          nestedArchives.push(name);
        }

        // Add to entry list (cap at 100 entries to prevent memory exhaustion)
        if (entryList.length < 100) {
          entryList.push({
            name,
            isDirectory: entry.isDirectory,
            uncompressed_bytes: uncompressed,
            compressed_bytes: compressed,
            crc32: '0x' + entry.header.crc.toString(16).toUpperCase(),
            timestamp: entry.header.time ? new Date(entry.header.time).toISOString() : null,
          });
        }

        // Add timeline events for archive files
        if (entry.header.time) {
          const d = new Date(entry.header.time);
          if (!isNaN(d.getTime())) {
            timelineEvents.push({
              timestamp_utc: d.toISOString(),
              timestamp_raw: entry.header.time.toString(),
              timestamp_precision: 'SECOND',
              timezone_offset: 'MS-DOS_LOCAL',
              event_type: 'ARCHIVE_ENTRY_TIMESTAMP',
              source_parser: this.name,
              source_field: 'DOS_TIME_HEADER',
              description: `Archive file entry: ${name} (${uncompressed} bytes)`,
              confidence: 'DEFINITIVE',
            });
          }
        }
      }

      // Check for Decompression Bomb
      const compressionRatio =
        totalCompressedSize > 0 ? Number((totalUncompressedSize / totalCompressedSize).toFixed(2)) : 1;
      const isDecompressionBomb =
        totalUncompressedSize > 250 * 1024 * 1024 || compressionRatio > 100;

      if (isDecompressionBomb) {
        warnings.push(
          `Decompression anomaly: Uncompressed size (${(totalUncompressedSize / (1024 * 1024)).toFixed(
            2
          )} MB) with ratio ${compressionRatio}:1 exceeds safe sandbox threshold.`
        );
      }

      if (suspiciousPathTraversal) {
        warnings.push(`Path traversal anomaly: Detected Zip Slip patterns in archive directory stream.`);
      }

      artifacts.push({
        artifact_type: 'ARCHIVE_STRUCTURE_MANIFEST',
        name: 'Archive Manifest & Safety Inspection',
        category: 'STRUCTURE',
        data_payload: {
          total_entries: entries.length,
          total_uncompressed_bytes: totalUncompressedSize,
          total_compressed_bytes: totalCompressedSize,
          compression_ratio: compressionRatio,
          is_decompression_bomb_risk: isDecompressionBomb,
          zip_slip_detected: suspiciousPathTraversal,
          traversal_violating_entries: pathTraversalEntries,
          nested_archives_detected: nestedArchives,
          sample_entries: entryList,
        },
      });
    } catch (err: any) {
      warnings.push(`Archive parsing error: ${err.message || 'Corrupted archive container'}`);
    }

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'ARCHIVE_EXAMINATION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          artifacts_extracted: artifacts.length,
          timeline_events: timelineEvents.length,
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

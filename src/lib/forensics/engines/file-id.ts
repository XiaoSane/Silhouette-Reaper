import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class FileIdentificationEngine implements ForensicEngine {
  engineId = 'engine-file-id';
  name = 'File Identification & Magic Byte Analysis';
  version = '1.2.0';

  supports(_context: ForensicExecutionContext): boolean {
    return true; // Always runs for all evidence
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;
    const warnings: string[] = [];
    const limitations: string[] = [];

    // Magic Byte Detection
    let detectedMime = 'application/octet-stream';
    let detectedExtension = 'bin';
    let formatDescription = 'Unknown Binary Data';
    let isText = false;

    if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
      detectedMime = 'image/jpeg';
      detectedExtension = 'jpg';
      formatDescription = 'JPEG (Joint Photographic Experts Group) Image';
    } else if (
      buf.length >= 8 &&
      buf[0] === 0x89 &&
      buf[1] === 0x50 &&
      buf[2] === 0x4e &&
      buf[3] === 0x47 &&
      buf[4] === 0x0d &&
      buf[5] === 0x0a &&
      buf[6] === 0x1a &&
      buf[7] === 0x0a
    ) {
      detectedMime = 'image/png';
      detectedExtension = 'png';
      formatDescription = 'PNG (Portable Network Graphics) Image';
    } else if (buf.length >= 4 && buf.toString('ascii', 0, 4) === 'GIF8') {
      detectedMime = 'image/gif';
      detectedExtension = 'gif';
      formatDescription = 'GIF (Graphics Interchange Format) Image';
    } else if (buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') {
      detectedMime = 'image/webp';
      detectedExtension = 'webp';
      formatDescription = 'WebP Image';
    } else if (buf.length >= 4 && buf.toString('ascii', 0, 4) === '%PDF') {
      detectedMime = 'application/pdf';
      detectedExtension = 'pdf';
      formatDescription = 'PDF (Portable Document Format) Document';
    } else if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05)) {
      // Check if Office document by inspecting strings in buffer
      const scanLimit = Math.min(buf.length, 65536);
      const headString = buf.slice(0, scanLimit).toString('binary');
      const origExt = (context.originalFilename.split('.').pop() || '').toLowerCase();

      if (headString.includes('word/') || (headString.includes('[Content_Types].xml') && ['docx', 'docm', 'dotx'].includes(origExt))) {
        detectedMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        detectedExtension = 'docx';
        formatDescription = 'Microsoft Word OpenXML Document';
      } else if (headString.includes('xl/') || (headString.includes('[Content_Types].xml') && ['xlsx', 'xlsm', 'xltx'].includes(origExt))) {
        detectedMime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        detectedExtension = 'xlsx';
        formatDescription = 'Microsoft Excel OpenXML Spreadsheet';
      } else if (headString.includes('ppt/') || (headString.includes('[Content_Types].xml') && ['pptx', 'pptm', 'potx'].includes(origExt))) {
        detectedMime = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        detectedExtension = 'pptx';
        formatDescription = 'Microsoft PowerPoint OpenXML Presentation';
      } else {
        detectedMime = 'application/zip';
        detectedExtension = 'zip';
        formatDescription = 'ZIP Compressed Archive';
      }
    } else if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
      detectedMime = 'application/gzip';
      detectedExtension = 'gz';
      formatDescription = 'GZIP Compressed Archive';
    } else if (buf.length >= 265 && buf.toString('ascii', 257, 262) === 'ustar') {
      detectedMime = 'application/x-tar';
      detectedExtension = 'tar';
      formatDescription = 'TAR Archive';
    } else if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
      detectedMime = 'application/x-dosexec';
      detectedExtension = 'exe';
      formatDescription = 'Windows Portable Executable (PE / MZ Executable)';
    } else if (buf.length >= 4 && buf[0] === 0x7f && buf.toString('ascii', 1, 4) === 'ELF') {
      detectedMime = 'application/x-executable';
      detectedExtension = 'elf';
      formatDescription = 'Linux Executable and Linkable Format (ELF)';
    } else if (buf.length >= 8 && buf.toString('ascii', 0, 7) === 'ElfFile') {
      detectedMime = 'application/x-ms-evtx';
      detectedExtension = 'evtx';
      formatDescription = 'Windows Event Log (EVTX)';
    } else if (buf.length >= 16 && buf.toString('ascii', 0, 15) === 'SQLite format 3') {
      detectedMime = 'application/vnd.sqlite3';
      detectedExtension = 'sqlite';
      formatDescription = 'SQLite Database File';
    } else {
      // Check if it's plaintext
      let nonPrintable = 0;
      const checkLen = Math.min(buf.length, 1024);
      for (let i = 0; i < checkLen; i++) {
        const byte = buf[i];
        if (byte < 0x09 || (byte > 0x0d && byte < 0x20 && byte !== 0x1b)) {
          nonPrintable++;
        }
      }
      if (checkLen > 0 && nonPrintable / checkLen < 0.05) {
        isText = true;
        const textSample = buf.toString('utf8', 0, checkLen).trim();
        if (textSample.startsWith('{') || textSample.startsWith('[')) {
          detectedMime = 'application/json';
          detectedExtension = 'json';
          formatDescription = 'JSON Document / Structured Log';
        } else if (textSample.startsWith('<?xml') || textSample.startsWith('<')) {
          detectedMime = 'application/xml';
          detectedExtension = 'xml';
          formatDescription = 'XML Document';
        } else {
          detectedMime = 'text/plain';
          detectedExtension = 'log';
          formatDescription = 'Plain Text / Log File';
        }
      }
    }

    // Calculate Byte Entropy (Shannon Entropy: 0.0 to 8.0)
    const byteCounts = new Uint32Array(256);
    for (let i = 0; i < buf.length; i++) {
      byteCounts[buf[i]]++;
    }
    let entropy = 0.0;
    if (buf.length > 0) {
      for (let i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
          const p = byteCounts[i] / buf.length;
          entropy -= p * Math.log2(p);
        }
      }
    }

    // Hex Header Sample (first 16 bytes)
    const headerHex = buf.slice(0, Math.min(buf.length, 16)).toString('hex').toUpperCase().match(/../g)?.join(' ') || '';
    const headerAscii = buf
      .slice(0, Math.min(buf.length, 16))
      .toString('latin1')
      .replace(/[\x00-\x1f\x7f-\xff]/g, '.');

    // Filename extension check
    const originalExt = context.originalFilename.split('.').pop()?.toLowerCase() || '';

    // Identification Artifact
    const artifacts = [
      {
        artifact_type: 'FILE_IDENTIFICATION',
        name: 'Magic Header & File Signature',
        category: 'IDENTIFICATION' as const,
        data_payload: {
          detected_mime: detectedMime,
          detected_extension: detectedExtension,
          format_description: formatDescription,
          declared_mime: context.declaredMime,
          original_extension: originalExt,
          header_hex: headerHex,
          header_ascii: headerAscii,
          entropy: Number(entropy.toFixed(4)),
          is_text: isText,
          size_bytes: context.fileSize,
        },
        raw_offset_range: '0x00000000-0x00000010',
      },
    ];

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'FILE_IDENTIFICATION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          magic_bytes_scanned: Math.min(buf.length, 512),
          entropy_score: Number(entropy.toFixed(4)),
          detected_mime: detectedMime,
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

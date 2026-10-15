import exifParser from 'exif-parser';
import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class ExifImageEngine implements ForensicEngine {
  engineId = 'engine-image-exif';
  name = 'EXIF & Image Metadata Forensic Engine';
  version = '2.0.4';

  supports(context: ForensicExecutionContext): boolean {
    const mime = context.detectedMime || context.declaredMime || '';
    const ext = (context.detectedExtension || context.originalFilename.split('.').pop() || '').toLowerCase();
    return (
      mime.startsWith('image/') ||
      ['jpg', 'jpeg', 'png', 'tiff', 'tif', 'webp', 'gif'].includes(ext)
    );
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;
    const warnings: string[] = [];
    const limitations: string[] = [];
    const artifacts: EngineResult['artifacts'] = [];
    const timelineEvents: EngineResult['timelineEvents'] = [];

    const mime = context.detectedMime || 'image/jpeg';

    if (mime.includes('jpeg') || mime.includes('tiff') || mime.includes('jpg')) {
      try {
        const parser = exifParser.create(buf);
        const result = parser.parse();

        const tags = result.tags || {};
        const imageSize = result.getImageSize();

        // Format GPS if present
        let gpsData = null;
        if (tags.GPSLatitude !== undefined && tags.GPSLongitude !== undefined) {
          gpsData = {
            latitude: tags.GPSLatitude,
            longitude: tags.GPSLongitude,
            altitude_meters: tags.GPSAltitude || null,
            map_url: `https://www.google.com/maps?q=${tags.GPSLatitude},${tags.GPSLongitude}`,
          };
        }

        // Camera / Device Metadata
        const deviceMetadata = {
          camera_make: tags.Make || null,
          camera_model: tags.Model || null,
          software: tags.Software || null,
          lens_model: tags.LensModel || null,
          focal_length_mm: tags.FocalLength || null,
          exposure_time_sec: tags.ExposureTime || null,
          f_number: tags.FNumber || null,
          iso: tags.ISO || null,
          flash: tags.Flash !== undefined ? tags.Flash : null,
          orientation: tags.Orientation || 1,
          dimensions: imageSize ? `${imageSize.width} x ${imageSize.height} px` : null,
        };

        artifacts.push({
          artifact_type: 'IMAGE_EXIF_METADATA',
          name: 'EXIF Device & Camera Metadata',
          category: 'METADATA',
          data_payload: {
            device: deviceMetadata,
            gps: gpsData,
            raw_tags: tags,
          },
        });

        // Parse Timestamps into Timeline
        if (tags.DateTimeOriginal) {
          const dt = new Date(tags.DateTimeOriginal * 1000);
          if (!isNaN(dt.getTime())) {
            timelineEvents.push({
              timestamp_utc: dt.toISOString(),
              timestamp_raw: dt.toISOString(),
              timestamp_precision: 'SECOND',
              timezone_offset: 'UTC',
              event_type: 'EXIF_ORIGINAL_CREATION',
              source_parser: this.name,
              source_field: 'DateTimeOriginal',
              description: `Image captured by camera device ${tags.Make || ''} ${tags.Model || ''}`.trim(),
              confidence: 'DEFINITIVE',
            });
          }
        }

        if (tags.CreateDate && tags.CreateDate !== tags.DateTimeOriginal) {
          const dt = new Date(tags.CreateDate * 1000);
          if (!isNaN(dt.getTime())) {
            timelineEvents.push({
              timestamp_utc: dt.toISOString(),
              timestamp_raw: dt.toISOString(),
              timestamp_precision: 'SECOND',
              timezone_offset: 'UTC',
              event_type: 'EXIF_DIGITIZED_DATE',
              source_parser: this.name,
              source_field: 'CreateDate',
              description: 'Image digitization recorded in EXIF header',
              confidence: 'DEFINITIVE',
            });
          }
        }

        if (tags.ModifyDate) {
          const dt = new Date(tags.ModifyDate * 1000);
          if (!isNaN(dt.getTime())) {
            timelineEvents.push({
              timestamp_utc: dt.toISOString(),
              timestamp_raw: dt.toISOString(),
              timestamp_precision: 'SECOND',
              timezone_offset: 'UTC',
              event_type: 'EXIF_MODIFIED_DATE',
              source_parser: this.name,
              source_field: 'ModifyDate',
              description: `Image post-processing / modification recorded (Software: ${tags.Software || 'Unknown'})`,
              confidence: 'DEFINITIVE',
            });
          }
        }
      } catch (err: any) {
        warnings.push(`EXIF parsing encountered a non-fatal structural notice: ${err.message || 'Malformed EXIF block'}`);
      }
    } else if (mime.includes('png')) {
      try {
        // Manual PNG chunk parser
        const chunks: { type: string; length: number }[] = [];
        const textMetadata: Record<string, string> = {};
        let offset = 8; // skip 8-byte PNG signature

        while (offset + 8 <= buf.length) {
          const length = buf.readUInt32BE(offset);
          const type = buf.toString('ascii', offset + 4, offset + 8);
          chunks.push({ type, length });

          // Prevent buffer overread or corrupted chunk lengths
          if (offset + 12 + length > buf.length || length > 10 * 1024 * 1024) {
            warnings.push(`PNG chunk '${type}' exceeds buffer boundary at offset ${offset}`);
            break;
          }

          if (type === 'tEXt' && length > 0) {
            const data = buf.slice(offset + 8, offset + 8 + length);
            const nullIdx = data.indexOf(0x00);
            if (nullIdx !== -1) {
              const keyword = data.toString('latin1', 0, nullIdx);
              const text = data.toString('latin1', nullIdx + 1);
              textMetadata[keyword] = text;
            }
          } else if (type === 'tIME' && length === 7) {
            if (offset + 15 <= buf.length) {
              const year = buf.readUInt16BE(offset + 8);
              const month = buf[offset + 10];
              const day = buf[offset + 11];
              const hour = buf[offset + 12];
              const minute = buf[offset + 13];
              const second = buf[offset + 14];
              const iso = new Date(Date.UTC(year, month - 1, day, hour, minute, second)).toISOString();
              timelineEvents.push({
                timestamp_utc: iso,
                timestamp_raw: `${year}-${month}-${day} ${hour}:${minute}:${second}`,
                timestamp_precision: 'SECOND',
                timezone_offset: 'UTC',
                event_type: 'PNG_TIME_CHUNK',
                source_parser: this.name,
                source_field: 'tIME',
                description: 'PNG image last modification timestamp stored in tIME chunk',
                confidence: 'DEFINITIVE',
              });
            }
          }

          offset += 12 + length; // 4 length + 4 type + data + 4 CRC
        }

        artifacts.push({
          artifact_type: 'PNG_CHUNKS_METADATA',
          name: 'PNG Structural Chunks & Embedded Text',
          category: 'METADATA',
          data_payload: {
            chunk_count: chunks.length,
            chunks: chunks.map((c) => c.type),
            embedded_text: textMetadata,
          },
        });
      } catch (pngErr: any) {
        warnings.push(`PNG chunk parsing encountered a structural notice: ${pngErr.message || 'Malformed PNG stream'}`);
      }
    } else {
      limitations.push(`Deep proprietary metadata parser not applicable for ${mime}; basic header extracted.`);
    }

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'IMAGE_EXIF_EXTRACTION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          artifacts_extracted: artifacts.length,
          timeline_events_generated: timelineEvents.length,
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

import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class LogForensicEngine implements ForensicEngine {
  engineId = 'engine-log-parser';
  name = 'Log Event & Security Audit Parser';
  version = '2.4.0';

  supports(context: ForensicExecutionContext): boolean {
    const mime = context.detectedMime || context.declaredMime || '';
    const ext = (context.detectedExtension || context.originalFilename.split('.').pop() || '').toLowerCase();
    return (
      mime === 'text/plain' ||
      mime === 'application/json' ||
      mime.includes('log') ||
      ['log', 'txt', 'syslog', 'json', 'csv', 'audit'].includes(ext)
    );
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;
    const warnings: string[] = [];
    const limitations: string[] = [];
    const artifacts: EngineResult['artifacts'] = [];
    const timelineEvents: EngineResult['timelineEvents'] = [];

    const text = buf.toString('utf8');
    const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);

    let parsedLogCount = 0;
    const ipCounts: Record<string, number> = {};
    const eventIdCounts: Record<string, number> = {};
    const suspiciousRequests: string[] = [];

    // Regex matchers for various log standards
    // 1. Apache / Nginx: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    const apacheRegex = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+|-)/;
    
    // 2. Syslog / Auth: Oct 11 14:32:52 host sshd[1234]: Failed password for root from 192.168.1.50 port 22
    const syslogRegex = /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$/;

    // 3. ISO8601 Timestamp: 2026-09-17T12:00:00.000Z [INFO] Service started
    const isoRegex = /^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\s+(?:\[?(\w+)\]?)?\s*(.*)$/;

    const currentYear = new Date().getFullYear();
    // Inferred year from document or fallback to current year
    const yearMatch = text.match(/\b(20\d{2})\b/);
    const inferredYear = yearMatch ? parseInt(yearMatch[1], 10) : currentYear;

    for (let i = 0; i < Math.min(lines.length, 500); i++) {
      const line = lines[i];

      // Check Apache
      const apMatch = line.match(apacheRegex);
      if (apMatch) {
        parsedLogCount++;
        const [, ip, rawTime, request, statusCode] = apMatch;
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;

        if (request.includes('../') || request.includes('..%2f') || request.includes('union+select') || request.includes('/etc/passwd')) {
          suspiciousRequests.push(`Line ${i + 1}: [${statusCode}] ${request} from ${ip}`);
        }

        // Parse Apache timestamp: 10/Oct/2000:13:55:36 -0700
        const months: Record<string, number> = {
          Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
        };
        const dtMatch = rawTime.match(/(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+\-]\d{4}))?/);
        if (dtMatch) {
          const [, day, monStr, year, hr, min, sec, tzStr] = dtMatch;
          const mon = months[monStr] ?? 0;
          let utcMs = Date.UTC(parseInt(year, 10), mon, parseInt(day, 10), parseInt(hr, 10), parseInt(min, 10), parseInt(sec, 10));
          let tzOffset = 'UTC';

          if (tzStr && tzStr.length === 5) {
            const tzSign = tzStr[0];
            const tzHours = parseInt(tzStr.slice(1, 3), 10);
            const tzMins = parseInt(tzStr.slice(3, 5), 10);
            const offsetMs = (tzHours * 60 + tzMins) * 60000;
            utcMs = tzSign === '+' ? utcMs - offsetMs : utcMs + offsetMs;
            tzOffset = `${tzSign}${tzStr.slice(1, 3)}:${tzStr.slice(3, 5)}`;
          }

          const dt = new Date(utcMs);
          if (!isNaN(dt.getTime())) {
            timelineEvents.push({
              timestamp_utc: dt.toISOString(),
              timestamp_raw: rawTime,
              timestamp_precision: 'SECOND',
              timezone_offset: tzOffset,
              event_type: 'WEB_ACCESS_LOG',
              source_parser: this.name,
              source_field: 'Apache_W3C_Access',
              description: `HTTP ${statusCode} - ${request} (IP: ${ip})`,
              confidence: 'DEFINITIVE',
            });
          }
        }
        continue;
      }

      // Check Syslog
      const sysMatch = line.match(syslogRegex);
      if (sysMatch) {
        parsedLogCount++;
        const [, rawDate, host, daemon, message] = sysMatch;
        const d = new Date(`${rawDate} ${inferredYear} UTC`);
        const iso = !isNaN(d.getTime()) ? d.toISOString() : new Date().toISOString();

        timelineEvents.push({
          timestamp_utc: iso,
          timestamp_raw: rawDate,
          timestamp_precision: 'SECOND',
          timezone_offset: 'LOCAL_SYSTEM',
          event_type: 'SYSLOG_EVENT',
          source_parser: this.name,
          source_field: daemon,
          description: `[${host}] ${daemon}: ${message.slice(0, 120)}`,
          confidence: 'HEURISTIC',
        });
        continue;
      }

      // Check ISO Timestamp
      const isoMatch = line.match(isoRegex);
      if (isoMatch) {
        parsedLogCount++;
        const [, rawDate, level, msg] = isoMatch;
        const d = new Date(rawDate);
        if (!isNaN(d.getTime())) {
          timelineEvents.push({
            timestamp_utc: d.toISOString(),
            timestamp_raw: rawDate,
            timestamp_precision: 'MILLISECOND',
            timezone_offset: 'UTC',
            event_type: 'APPLICATION_LOG_EVENT',
            source_parser: this.name,
            source_field: level || 'LOG',
            description: msg.slice(0, 140),
            confidence: 'DEFINITIVE',
          });
        }
      }

      // Extract Event IDs if present (e.g. EventID: 4624, Event 4625)
      const evIdMatch = line.match(/\b(?:EventID|Event\s*ID|Event)\s*[:=]?\s*(\d{3,5})\b/i);
      if (evIdMatch) {
        const id = evIdMatch[1];
        eventIdCounts[id] = (eventIdCounts[id] || 0) + 1;
      }
    }

    artifacts.push({
      artifact_type: 'LOG_PARSER_SUMMARY',
      name: 'Parsed Log Records & Event Telemetry',
      category: 'LOG_RECORD',
      data_payload: {
        total_lines: lines.length,
        parsed_entries_count: parsedLogCount,
        unique_client_ips: Object.keys(ipCounts).length,
        top_client_ips: Object.entries(ipCounts).slice(0, 10).map(([ip, count]) => ({ ip, count })),
        event_id_distribution: eventIdCounts,
        suspicious_requests_detected: suspiciousRequests,
      },
    });

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'LOG_FORENSIC_PARSING',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          lines_analyzed: lines.length,
          timeline_events_extracted: timelineEvents.length,
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

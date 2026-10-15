import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import { InvestigationFullDetails, ForensicReport } from '@/types/forensics';
import { MerkleSealer } from './merkle-sealer';
import { generateEntityId, generateVerificationToken } from '@/lib/security/auth';
import { ForensicRepository } from '@/lib/db/database';

export class ForensicPdfGenerator {
  static async generateReport(details: InvestigationFullDetails): Promise<ForensicReport> {
    const pdfDoc = await PDFDocument.create();

    const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);
    const fontMonoBold = await pdfDoc.embedFont(StandardFonts.CourierBold);

    const primaryColor = rgb(0.04, 0.04, 0.06); // Dark
    const amberColor = rgb(0.96, 0.62, 0.04); // #f59e0b
    const textDark = rgb(0.1, 0.1, 0.15);
    const textMuted = rgb(0.4, 0.4, 0.45);
    const lineBorder = rgb(0.85, 0.85, 0.88);
    const bgPanel = rgb(0.96, 0.96, 0.98);

    const pageSize: [number, number] = [595.28, 841.89]; // A4
    const margin = 40;
    const contentWidth = pageSize[0] - margin * 2;

    let currentPage = pdfDoc.addPage(pageSize);
    let y = pageSize[1] - margin;

    // --- Text Wrapping Helper (Guarantees zero margin overflow and no character truncation) ---
    const wrapText = (
      text: string,
      font: any,
      size: number,
      maxWidth: number
    ): string[] => {
      if (!text) return [];
      const lines: string[] = [];
      const rawParagraphs = String(text).split(/\r?\n/);

      for (const paragraph of rawParagraphs) {
        const trimmed = paragraph.trim();
        if (!trimmed) continue;

        const words = trimmed.split(/\s+/);
        let currentLine = '';

        for (const word of words) {
          if (!word) continue;

          // If a single word/token exceeds maxWidth (e.g. long paths, URLs, hashes)
          if (font.widthOfTextAtSize(word, size) > maxWidth) {
            if (currentLine) {
              lines.push(currentLine);
              currentLine = '';
            }

            // Break word character-by-character
            let subWord = '';
            for (let i = 0; i < word.length; i++) {
              const char = word[i];
              if (font.widthOfTextAtSize(subWord + char, size) <= maxWidth) {
                subWord += char;
              } else {
                if (subWord) lines.push(subWord);
                subWord = char;
              }
            }
            if (subWord) {
              currentLine = subWord;
            }
            continue;
          }

          const testLine = currentLine ? `${currentLine} ${word}` : word;
          if (font.widthOfTextAtSize(testLine, size) <= maxWidth) {
            currentLine = testLine;
          } else {
            if (currentLine) lines.push(currentLine);
            currentLine = word;
          }
        }

        if (currentLine) {
          lines.push(currentLine);
        }
      }

      return lines;
    };

    const checkNewPage = (neededHeight: number) => {
      if (y - neededHeight < margin + 40) {
        currentPage = pdfDoc.addPage(pageSize);
        y = pageSize[1] - margin;

        // Subtle top continuation header for subsequent pages
        currentPage.drawLine({
          start: { x: margin, y: y },
          end: { x: pageSize[0] - margin, y: y },
          color: lineBorder,
          thickness: 0.5,
        });
        currentPage.drawText('SILHOUETTE REAPER // DIGITAL FORENSICS EXAMINATION REPORT (CONTINUED)', {
          x: margin,
          y: y - 10,
          size: 6.5,
          font: fontMono,
          color: textMuted,
        });
        y -= 24;
        return true;
      }
      return false;
    };

    // --- Header Helper ---
    const drawHeader = (title: string) => {
      checkNewPage(60); // Ensure header + following item have space together
      currentPage.drawRectangle({
        x: margin,
        y: y - 24,
        width: contentWidth,
        height: 24,
        color: primaryColor,
      });
      currentPage.drawRectangle({
        x: margin,
        y: y - 24,
        width: 4,
        height: 24,
        color: amberColor,
      });
      currentPage.drawText(title.toUpperCase(), {
        x: margin + 12,
        y: y - 16,
        size: 10,
        font: fontBold,
        color: rgb(1, 1, 1),
      });
      y -= 34;
    };

    // --- COVER / TITLE BLOCK ---
    currentPage.drawRectangle({
      x: margin,
      y: y - 75,
      width: contentWidth,
      height: 75,
      color: primaryColor,
    });
    currentPage.drawRectangle({
      x: margin,
      y: y - 75,
      width: contentWidth,
      height: 3,
      color: amberColor,
    });

    currentPage.drawText('SILHOUETTE REAPER // DIGITAL FORENSICS LAB', {
      x: margin + 16,
      y: y - 24,
      size: 9,
      font: fontBold,
      color: amberColor,
    });

    currentPage.drawText('TECHNICAL FORENSIC EXAMINATION REPORT', {
      x: margin + 16,
      y: y - 46,
      size: 16,
      font: fontBold,
      color: rgb(1, 1, 1),
    });

    currentPage.drawText(`INVESTIGATION ID: ${details.session.investigation_id}  |  DATE: ${new Date().toISOString()}`, {
      x: margin + 16,
      y: y - 62,
      size: 8,
      font: fontMono,
      color: rgb(0.8, 0.8, 0.85),
    });

    y -= 95;

    // --- SECTION 1: INVESTIGATION METADATA & CHAIN OF CUSTODY ---
    drawHeader('1. Investigation Scope & Custody Overview');

    currentPage.drawRectangle({
      x: margin,
      y: y - 65,
      width: contentWidth,
      height: 65,
      color: bgPanel,
      borderColor: lineBorder,
      borderWidth: 1,
    });

    const metaLabels = [
      `Session ID: ${details.session.investigation_id}`,
      `Created (UTC): ${details.session.created_at}`,
      `Retention: ${details.session.retention_hours} Hours`,
      `Preservation Mode: Bit-Stream Read-Only (0400)`,
      `Evidence Items: ${details.evidence.length}`,
      `Generated Artifacts: ${details.artifacts.length}`,
      `Identified Findings: ${details.findings.length}`,
      `Examination Status: COMPLETED`,
    ];

    for (let i = 0; i < metaLabels.length; i++) {
      const col = i % 2;
      const row = Math.floor(i / 2);
      currentPage.drawText(metaLabels[i], {
        x: margin + 12 + col * (contentWidth / 2),
        y: y - 18 - row * 13,
        size: 8.5,
        font: fontRegular,
        color: textDark,
      });
    }

    y -= 80;

    // --- SECTION 2: EVIDENCE INVENTORY & CRYPTOGRAPHIC HASHES ---
    drawHeader('2. Evidence Intake & Hash Verification');

    const innerWidthSec2 = contentWidth - 24;

    for (const ev of details.evidence) {
      const nameLines = wrapText(
        `Item: ${ev.original_filename} (${(ev.size_bytes / 1024).toFixed(2)} KB)`,
        fontBold,
        9,
        innerWidthSec2
      );
      const mimeLines = wrapText(
        `MIME (Detected): ${ev.detected_mime}  |  Preservation: ${ev.preservation_status}`,
        fontRegular,
        8,
        innerWidthSec2
      );
      const sha256Lines = wrapText(
        `SHA-256: ${ev.primary_sha256}`,
        fontMonoBold,
        7.5,
        innerWidthSec2
      );
      const sha1Lines = wrapText(
        `SHA-1:   ${ev.sha1}`,
        fontMono,
        7,
        innerWidthSec2
      );
      const md5Lines = wrapText(
        `MD5:     ${ev.md5}`,
        fontMono,
        7,
        innerWidthSec2
      );

      // Dynamic Card Height calculation
      let cardHeight = 12; // top padding
      cardHeight += nameLines.length * 12;
      cardHeight += 2;
      cardHeight += mimeLines.length * 11;
      cardHeight += 4;
      cardHeight += sha256Lines.length * 11;
      cardHeight += 2;
      cardHeight += sha1Lines.length * 10;
      cardHeight += 2;
      cardHeight += md5Lines.length * 10;
      cardHeight += 10; // bottom padding

      checkNewPage(cardHeight + 10);

      // Card bounding box
      currentPage.drawRectangle({
        x: margin,
        y: y - cardHeight,
        width: contentWidth,
        height: cardHeight,
        color: bgPanel,
        borderColor: lineBorder,
        borderWidth: 1,
      });

      // Left green preservation indicator bar
      currentPage.drawRectangle({
        x: margin,
        y: y - cardHeight,
        width: 3.5,
        height: cardHeight,
        color: rgb(0.1, 0.55, 0.3),
      });

      let textY = y - 13;
      const textX = margin + 12;

      for (const line of nameLines) {
        currentPage.drawText(line, {
          x: textX,
          y: textY,
          size: 9,
          font: fontBold,
          color: textDark,
        });
        textY -= 12;
      }
      textY -= 2;

      for (const line of mimeLines) {
        currentPage.drawText(line, {
          x: textX,
          y: textY,
          size: 8,
          font: fontRegular,
          color: textMuted,
        });
        textY -= 11;
      }
      textY -= 4;

      for (const line of sha256Lines) {
        currentPage.drawText(line, {
          x: textX,
          y: textY,
          size: 7.5,
          font: fontMonoBold,
          color: rgb(0.1, 0.45, 0.25),
        });
        textY -= 11;
      }
      textY -= 2;

      for (const line of sha1Lines) {
        currentPage.drawText(line, {
          x: textX,
          y: textY,
          size: 7,
          font: fontMono,
          color: textMuted,
        });
        textY -= 10;
      }
      textY -= 2;

      for (const line of md5Lines) {
        currentPage.drawText(line, {
          x: textX,
          y: textY,
          size: 7,
          font: fontMono,
          color: textMuted,
        });
        textY -= 10;
      }

      y -= cardHeight + 10;
    }

    // --- SECTION 3: TOOLS & METHODOLOGY ---
    drawHeader('3. Forensic Examination Methodology & Tools');

    const toolsIntro = [
      'The examination was conducted via automated, isolated, non-destructive forensic engines.',
      'All parsers operate directly in memory without shell command interpolation or untrusted binary execution.',
      'Active Tools & Forensic Execution Modules:',
    ];

    for (const line of toolsIntro) {
      const wrapped = wrapText(line, fontRegular, 8, contentWidth - 16);
      for (const wl of wrapped) {
        checkNewPage(14);
        currentPage.drawText(wl, {
          x: margin + 8,
          y: y - 10,
          size: 8,
          font: fontRegular,
          color: textDark,
        });
        y -= 13;
      }
    }
    y -= 4;

    for (const s of details.stages) {
      const stageStr = `• ${s.tool_name} (v${s.tool_version}) — Status: ${s.status}`;
      const wrapped = wrapText(stageStr, fontMono, 7.5, contentWidth - 24);
      for (const wl of wrapped) {
        checkNewPage(13);
        currentPage.drawText(wl, {
          x: margin + 12,
          y: y - 10,
          size: 7.5,
          font: fontMono,
          color: textDark,
        });
        y -= 12;
      }
    }
    y -= 12;

    // --- SECTION 4: KEY FORENSIC FINDINGS ---
    drawHeader('4. Forensic Findings & Traceable Observations');

    if (details.findings.length === 0) {
      checkNewPage(35);
      currentPage.drawText('No anomalies or malicious indicators identified during this examination.', {
        x: margin + 10,
        y: y - 15,
        size: 8.5,
        font: fontRegular,
        color: textMuted,
      });
      y -= 30;
    } else {
      const innerWidthSec4 = contentWidth - 24;

      for (let i = 0; i < details.findings.length; i++) {
        const fnd = details.findings[i];

        // Pre-wrap all textual fields to avoid truncation and overflow
        const titleText = `[${fnd.severity}] ${fnd.title}`;
        const titleLines = wrapText(titleText, fontBold, 9, innerWidthSec4);

        const metaText = `Category: ${fnd.category}  |  Module: ${fnd.source_module}`;
        const metaLines = wrapText(metaText, fontRegular, 7.5, innerWidthSec4);

        const descText = `Description: ${fnd.description}`;
        const descLines = wrapText(descText, fontRegular, 8, innerWidthSec4);

        const rationaleText = `Technical Rationale: ${fnd.technical_rationale}`;
        const rationaleLines = wrapText(rationaleText, fontRegular, 7.5, innerWidthSec4);

        const artifactListStr = fnd.supporting_artifact_ids && fnd.supporting_artifact_ids.length > 0
          ? fnd.supporting_artifact_ids.join(', ')
          : 'None documented';
        const artifactText = `Supporting Artifacts: ${artifactListStr}`;
        const artifactLines = wrapText(artifactText, fontMonoBold, 7, innerWidthSec4);

        const limitationLines = fnd.limitations
          ? wrapText(`Limitations: ${fnd.limitations}`, fontRegular, 7, innerWidthSec4)
          : [];

        // Exact dynamic card height calculation
        let cardHeight = 12; // top padding
        cardHeight += titleLines.length * 12;
        cardHeight += 3;
        cardHeight += metaLines.length * 11;
        cardHeight += 5;
        cardHeight += descLines.length * 11.5;
        cardHeight += 4;
        cardHeight += rationaleLines.length * 11;
        cardHeight += 4;
        cardHeight += artifactLines.length * 10;
        if (limitationLines.length > 0) {
          cardHeight += 4;
          cardHeight += limitationLines.length * 9.5;
        }
        cardHeight += 10; // bottom padding

        // Ensure page break before card if needed
        checkNewPage(cardHeight + 12);

        // Styling based on severity
        const isCriticalOrHigh = fnd.severity === 'HIGH' || fnd.severity === 'CRITICAL';
        const isMedium = fnd.severity === 'MEDIUM';

        const cardBg = isCriticalOrHigh
          ? rgb(0.99, 0.95, 0.95)
          : isMedium
          ? rgb(0.99, 0.98, 0.94)
          : bgPanel;

        const cardBorder = isCriticalOrHigh
          ? rgb(0.9, 0.3, 0.3)
          : isMedium
          ? rgb(0.92, 0.65, 0.15)
          : lineBorder;

        const titleColor = isCriticalOrHigh
          ? rgb(0.8, 0.1, 0.1)
          : isMedium
          ? rgb(0.7, 0.4, 0.0)
          : textDark;

        const accentBarColor = isCriticalOrHigh
          ? rgb(0.85, 0.2, 0.2)
          : isMedium
          ? amberColor
          : rgb(0.2, 0.6, 0.4);

        // Draw card bounding box
        currentPage.drawRectangle({
          x: margin,
          y: y - cardHeight,
          width: contentWidth,
          height: cardHeight,
          color: cardBg,
          borderColor: cardBorder,
          borderWidth: 1,
        });

        // Draw left tactical accent bar (3.5px width)
        currentPage.drawRectangle({
          x: margin,
          y: y - cardHeight,
          width: 3.5,
          height: cardHeight,
          color: accentBarColor,
        });

        // Render card content line-by-line
        let textY = y - 13;
        const textX = margin + 12;

        for (const line of titleLines) {
          currentPage.drawText(line, {
            x: textX,
            y: textY,
            size: 9,
            font: fontBold,
            color: titleColor,
          });
          textY -= 12;
        }
        textY -= 3;

        for (const line of metaLines) {
          currentPage.drawText(line, {
            x: textX,
            y: textY,
            size: 7.5,
            font: fontRegular,
            color: textMuted,
          });
          textY -= 11;
        }
        textY -= 5;

        for (const line of descLines) {
          currentPage.drawText(line, {
            x: textX,
            y: textY,
            size: 8,
            font: fontRegular,
            color: textDark,
          });
          textY -= 11.5;
        }
        textY -= 4;

        for (const line of rationaleLines) {
          currentPage.drawText(line, {
            x: textX,
            y: textY,
            size: 7.5,
            font: fontRegular,
            color: rgb(0.3, 0.3, 0.35),
          });
          textY -= 11;
        }
        textY -= 4;

        for (const line of artifactLines) {
          currentPage.drawText(line, {
            x: textX,
            y: textY,
            size: 7,
            font: fontMonoBold,
            color: primaryColor,
          });
          textY -= 10;
        }

        if (limitationLines.length > 0) {
          textY -= 4;
          for (const line of limitationLines) {
            currentPage.drawText(line, {
              x: textX,
              y: textY,
              size: 7,
              font: fontRegular,
              color: rgb(0.45, 0.45, 0.5),
            });
            textY -= 9.5;
          }
        }

        y -= cardHeight + 12;
      }
    }

    // --- SECTION 5: UNIFIED TIMELINE ---
    drawHeader('5. Normalized Chronological Timeline');

    if (details.timeline.length === 0) {
      checkNewPage(35);
      currentPage.drawText('No timestamped events extracted from evidence.', {
        x: margin + 10,
        y: y - 15,
        size: 8.5,
        font: fontRegular,
        color: textMuted,
      });
      y -= 30;
    } else {
      const timeColWidth = 140;
      const descColX = margin + timeColWidth + 12;
      const descMaxWidth = contentWidth - timeColWidth - 16;

      // Table Header Drawer
      const drawTimelineTableHeader = () => {
        currentPage.drawRectangle({
          x: margin,
          y: y - 18,
          width: contentWidth,
          height: 18,
          color: rgb(0.12, 0.13, 0.18),
        });
        currentPage.drawText('TIMESTAMP (UTC)', {
          x: margin + 8,
          y: y - 12,
          size: 7,
          font: fontMonoBold,
          color: rgb(0.9, 0.9, 0.95),
        });
        currentPage.drawText('EVENT CLASSIFICATION & TELEMETRY DESCRIPTION', {
          x: descColX,
          y: y - 12,
          size: 7,
          font: fontMonoBold,
          color: rgb(0.9, 0.9, 0.95),
        });
        y -= 22;
      };

      checkNewPage(45);
      drawTimelineTableHeader();

      for (let i = 0; i < details.timeline.length; i++) {
        const tle = details.timeline[i];

        // Format description & classification lines safely wrapped
        const descText = `[${tle.event_type}] ${tle.description}`;
        const descLines = wrapText(descText, fontRegular, 7.5, descMaxWidth);

        // Include source parser provenance if available
        const sourceText = `Source: ${tle.source_parser} (${tle.source_field})`;
        const sourceLines = wrapText(sourceText, fontMono, 6.5, descMaxWidth);

        const descBlockHeight = descLines.length * 10 + sourceLines.length * 8.5 + 2;
        const timeBlockHeight = 10 + 9; // timestamp + confidence label
        const rowHeight = Math.max(24, Math.max(descBlockHeight, timeBlockHeight) + 8);

        // Check page break; if triggered, redraw table header on continuation page
        if (checkNewPage(rowHeight + 6)) {
          drawTimelineTableHeader();
        }

        // Alternate subtle row background for tabular scannability
        const rowBg = i % 2 === 0 ? rgb(0.97, 0.97, 0.99) : rgb(1, 1, 1);
        currentPage.drawRectangle({
          x: margin,
          y: y - rowHeight,
          width: contentWidth,
          height: rowHeight,
          color: rowBg,
        });

        // Bottom border divider
        currentPage.drawLine({
          start: { x: margin, y: y - rowHeight },
          end: { x: margin + contentWidth, y: y - rowHeight },
          color: lineBorder,
          thickness: 0.5,
        });

        // Render Column 1: Timestamp (UTC) and Confidence
        const timeY = y - 11;
        currentPage.drawText(tle.timestamp_utc, {
          x: margin + 8,
          y: timeY,
          size: 7.2,
          font: fontMonoBold,
          color: rgb(0.15, 0.35, 0.55),
        });

        const confColor =
          tle.confidence === 'DEFINITIVE'
            ? rgb(0.1, 0.5, 0.25)
            : tle.confidence === 'HEURISTIC'
            ? rgb(0.7, 0.4, 0.0)
            : rgb(0.4, 0.4, 0.5);

        currentPage.drawText(`[${tle.confidence}]`, {
          x: margin + 8,
          y: timeY - 9.5,
          size: 6.2,
          font: fontMonoBold,
          color: confColor,
        });

        // Render Column 2: Wrapped Description & Source Traceability
        let descY = y - 11;
        for (const dl of descLines) {
          currentPage.drawText(dl, {
            x: descColX,
            y: descY,
            size: 7.5,
            font: fontRegular,
            color: textDark,
          });
          descY -= 10;
        }

        for (const sl of sourceLines) {
          currentPage.drawText(sl, {
            x: descColX,
            y: descY,
            size: 6.5,
            font: fontMono,
            color: textMuted,
          });
          descY -= 8.5;
        }

        y -= rowHeight;
      }
    }
    y -= 15;

    // --- SECTION 6: LIMITATIONS & DISCLAIMER ---
    drawHeader('6. Limitations & Examination Disclaimers');

    const disclaimers = [
      '1. This automated technical forensic report was compiled algorithmically without manual examiner testimony.',
      '2. All findings represent deterministic technical observations derived strictly from extracted artifacts.',
      '3. The platform guarantees bit-stream evidence preservation during acquisition but does not verify physical chain of custody before upload.',
      '4. Results are provided for technical analysis and incident response triage.',
    ];

    for (const disc of disclaimers) {
      const wrapped = wrapText(disc, fontRegular, 7.5, contentWidth - 16);
      for (const line of wrapped) {
        checkNewPage(13);
        currentPage.drawText(line, {
          x: margin + 8,
          y: y - 10,
          size: 7.5,
          font: fontRegular,
          color: textMuted,
        });
        y -= 12;
      }
      y -= 3;
    }
    y -= 12;

    // --- SECTION 7: CRYPTOGRAPHIC VERIFICATION SEAL ---
    const merkleRoot = MerkleSealer.generateMerkleRoot(details.artifacts, details.findings);
    const verificationToken = generateVerificationToken();

    const sealInnerWidth = contentWidth - 28;
    const merkleLines = wrapText(`Merkle Root:        ${merkleRoot}`, fontMono, 7.5, sealInnerWidth);
    const tokenLines = wrapText(`Verification Token: ${verificationToken}`, fontMonoBold, 8.5, sealInnerWidth);
    const urlLines = wrapText('Online Verification: https://forensics.silhouette-reaper.local/verify', fontMono, 7.5, sealInnerWidth);

    const sealBoxHeight = 22 + (merkleLines.length * 11) + (tokenLines.length * 13) + (urlLines.length * 11) + 14;

    checkNewPage(sealBoxHeight + 40);
    drawHeader('7. Cryptographic Merkle Seal & Integrity Verification');

    currentPage.drawRectangle({
      x: margin,
      y: y - sealBoxHeight,
      width: contentWidth,
      height: sealBoxHeight,
      color: primaryColor,
    });

    let sealY = y - 18;
    currentPage.drawText('CRYPTOGRAPHIC INVESTIGATION SEAL', {
      x: margin + 14,
      y: sealY,
      size: 9,
      font: fontBold,
      color: amberColor,
    });
    sealY -= 16;

    for (const ml of merkleLines) {
      currentPage.drawText(ml, {
        x: margin + 14,
        y: sealY,
        size: 7.5,
        font: fontMono,
        color: rgb(0.9, 0.9, 0.95),
      });
      sealY -= 11;
    }

    for (const tl of tokenLines) {
      currentPage.drawText(tl, {
        x: margin + 14,
        y: sealY,
        size: 8.5,
        font: fontMonoBold,
        color: rgb(0.5, 0.9, 0.6),
      });
      sealY -= 13;
    }

    for (const ul of urlLines) {
      currentPage.drawText(ul, {
        x: margin + 14,
        y: sealY,
        size: 7.5,
        font: fontMono,
        color: rgb(0.7, 0.7, 0.8),
      });
      sealY -= 11;
    }

    y -= sealBoxHeight + 15;

    // --- Page Numbering & Footers on all pages ---
    const totalPages = pdfDoc.getPageCount();
    for (let i = 0; i < totalPages; i++) {
      const page = pdfDoc.getPage(i);
      page.drawLine({
        start: { x: margin, y: margin + 15 },
        end: { x: pageSize[0] - margin, y: margin + 15 },
        color: lineBorder,
        thickness: 0.5,
      });

      page.drawText(`SILHOUETTE REAPER // FORENSIC REPORT // ${details.session.investigation_id}`, {
        x: margin,
        y: margin + 5,
        size: 7,
        font: fontMono,
        color: textMuted,
      });

      page.drawText(`PAGE ${i + 1} OF ${totalPages}`, {
        x: pageSize[0] - margin - 60,
        y: margin + 5,
        size: 7,
        font: fontMonoBold,
        color: textMuted,
      });
    }

    const pdfBytes = await pdfDoc.save();
    const reportSha256 = crypto.createHash('sha256').update(pdfBytes).digest('hex');

    // Save PDF to storage
    const reportDir = path.join(process.cwd(), 'storage', 'reports_registry', details.session.investigation_id);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    const reportId = generateEntityId('RPT');
    const reportFilePath = path.join(reportDir, `${reportId}.pdf`);
    fs.writeFileSync(reportFilePath, pdfBytes);

    const nowIso = new Date().toISOString();
    const expiresAtIso = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    const report: ForensicReport = {
      report_id: reportId,
      investigation_id: details.session.investigation_id,
      report_sha256: reportSha256,
      verification_token: verificationToken,
      merkle_root: merkleRoot,
      generated_at: nowIso,
      expires_at: expiresAtIso,
      session_purged: false,
      storage_path: reportFilePath,
      file_size_bytes: pdfBytes.length,
      report_manifest: {
        investigation_id: details.session.investigation_id,
        generated_at: nowIso,
        evidence_count: details.evidence.length,
        artifact_count: details.artifacts.length,
        finding_count: details.findings.length,
        timeline_event_count: details.timeline.length,
        tools_used: details.stages.map((s) => ({ name: s.tool_name, version: s.tool_version })),
      },
    };

    ForensicRepository.createReport(report);
    ForensicRepository.updateInvestigationStatus(details.session.investigation_id, 'REPORT_READY');

    ForensicRepository.createAuditEvent({
      event_id: generateEntityId('AUD'),
      investigation_id: details.session.investigation_id,
      timestamp: new Date().toISOString(),
      actor_type: 'REPORT_GENERATOR',
      action: 'REPORT_GENERATED',
      object_type: 'REPORT',
      object_id: reportId,
      result: 'SUCCESS',
      metadata: { reportSha256, verificationToken },
    });

    return report;
  }
}

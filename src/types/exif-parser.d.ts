declare module 'exif-parser' {
  export interface ExifParser {
    parse(): {
      tags: Record<string, any>;
      getImageSize(): { width: number; height: number };
    };
  }

  export function create(buffer: Buffer): ExifParser;
}

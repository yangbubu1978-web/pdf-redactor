import { pdfjs } from 'react-pdf';
import { PDFDocument } from 'pdf-lib';
import type { RedactionRect } from '../types';

// 直接從本地套件載入 worker，避免依賴 CDN
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url
).toString();

export { pdfjs };

interface ExportOptions {
  file: File;
  redactions: RedactionRect[];
  watermarkText: string;
  /** 輸出解析度倍率：2 已等同 2x 印刷級 */
  renderScale?: number;
  onProgress?: (done: number, total: number) => void;
}

function drawWatermark(
  ctx: CanvasRenderingContext2D,
  w: number,
  h: number,
  text: string
) {
  if (!text.trim()) return;
  const content = text.trim();
  // 以實際字寬量測，確保旋轉 45° 後完整落在頁面內（不被裁切）
  // 旋轉後 bounding 寬 ≈ (文字寬 + 字高) * 0.707，故可用長度 ≈ 1.414*min(w,h) - 字高
  let fontSize = Math.max(14, Math.min(h * 0.18, w * 0.4));
  ctx.save();
  ctx.font = `900 ${fontSize}px "Noto Sans TC", system-ui, sans-serif`;
  const measured = ctx.measureText(content).width || 1;
  const limit =
    (Math.SQRT2 * Math.min(w, h) - fontSize) * 0.92;
  if (measured > limit) {
    fontSize = Math.max(10, fontSize * (limit / measured));
  }
  ctx.restore();

  ctx.save();
  ctx.translate(w / 2, h / 2);
  ctx.rotate((-45 * Math.PI) / 180);
  ctx.globalAlpha = 0.13;
  ctx.fillStyle = '#dc2626';
  ctx.font = `900 ${fontSize}px "Noto Sans TC", system-ui, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(content, 0, 0);
  ctx.restore();
}

/**
 * 導出：把每一頁「光柵化」成圖片再組回 PDF。
 * 這樣被遮蔽的文字不存在於輸出檔的任何文字層裡，複製/搜尋都取不到，
 * 才是真正的遮蔽（在文字上疊黑方塊是騙人的做法）。
 */
export async function exportRedactedPdf(opts: ExportOptions): Promise<Blob> {
  const { file, redactions, watermarkText, renderScale = 2, onProgress } = opts;

  const buffer = await file.arrayBuffer();
  const pdf = await pdfjs.getDocument({ data: buffer }).promise;
  const outDoc = await PDFDocument.create();

  try {
    for (let p = 1; p <= pdf.numPages; p++) {
      const page = await pdf.getPage(p);
      const vp = page.getViewport({ scale: renderScale });
      const ptViewport = page.getViewport({ scale: 1 });

      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.floor(vp.width));
      canvas.height = Math.max(1, Math.floor(vp.height));
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('無法建立畫布');

      // 白底，避免 PNG/JPEG 透明變黑
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const renderTask = page.render({
        canvasContext: ctx,
        viewport: vp,
        intent: 'print',
      } as never);
      await renderTask.promise;

      // 畫遮蔽（燒進圖片）
      const pageRects = redactions.filter((r) => r.pageIndex === p - 1);
      ctx.fillStyle = '#000000';
      for (const r of pageRects) {
        ctx.fillRect(
          r.x * canvas.width,
          r.y * canvas.height,
          r.width * canvas.width,
          r.height * canvas.height
        );
      }

      // 畫浮水印（燒進圖片，輸出一樣有）
      drawWatermark(ctx, canvas.width, canvas.height, watermarkText);

      const jpegUrl = canvas.toDataURL('image/jpeg', 0.92);
      const jpegBytes = Uint8Array.from(
        atob(jpegUrl.split(',')[1]),
        (c) => c.charCodeAt(0)
      );
      const img = await outDoc.embedJpg(jpegBytes);
      const outPage = outDoc.addPage([ptViewport.width, ptViewport.height]);
      outPage.drawImage(img, {
        x: 0,
        y: 0,
        width: ptViewport.width,
        height: ptViewport.height,
      });

      page.cleanup();
      onProgress?.(p, pdf.numPages);
    }

    const bytes = await outDoc.save();
    return new Blob([bytes as unknown as BlobPart], { type: 'application/pdf' });
  } finally {
    await pdf.destroy();
  }
}

/** 讀取整份 PDF 的文字，逐頁跑規則偵測 */
export async function detectAllPages(
  file: File,
  detect: (
    items: unknown[],
    viewport: unknown,
    pageIndex: number
  ) => unknown[],
  onProgress?: (done: number, total: number) => void
) {
  const buffer = await file.arrayBuffer();
  const pdf = await pdfjs.getDocument({ data: buffer }).promise;
  const all: unknown[] = [];
  try {
    for (let p = 1; p <= pdf.numPages; p++) {
      const page = await pdf.getPage(p);
      const vp = page.getViewport({ scale: 1 });
      const text = await page.getTextContent();
      const found = detect(text.items as unknown[], vp, p - 1);
      all.push(...found);
      page.cleanup();
      onProgress?.(p, pdf.numPages);
    }
  } finally {
    await pdf.destroy();
  }
  return all;
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

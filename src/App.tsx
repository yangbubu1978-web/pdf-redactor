import React, {
  useState,
  useRef,
  useCallback,
  useEffect,
  useMemo,
} from 'react';
import { Document, Page } from 'react-pdf';
import {
  Upload,
  Download,
  Trash2,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  FileText,
  ZoomIn,
  ZoomOut,
  Eraser,
  Sparkles,
  Settings2,
  X,
  Lock,
  Stamp,
  ScanText,
  MousePointer2,
  Info,
} from 'lucide-react';

import { pdfjs, exportRedactedPdf, downloadBlob } from './lib/pdf';
import { detectPage, categoryColor } from './lib/detect';
import type { RedactionRect, Detection } from './types';
import { Button } from './components/Button';

const clamp = (v: number, min: number, max: number) =>
  Math.max(min, Math.min(max, v));

const generateId = () =>
  `m${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [numPages, setNumPages] = useState(0);
  const [pageNumber, setPageNumber] = useState(1);
  const [scale, setScale] = useState(1);
  const [pagePt, setPagePt] = useState({ w: 595, h: 842 });

  const [redactions, setRedactions] = useState<RedactionRect[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [watermarkText, setWatermarkText] = useState('');

  const [markMode, setMarkMode] = useState(false);
  const [isDrawing, setIsDrawing] = useState(false);
  const [currentRect, setCurrentRect] = useState<{
    x: number;
    y: number;
    w: number;
    h: number;
  } | null>(null);

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [toast, setToast] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const startPosRef = useRef<{ x: number; y: number } | null>(null);
  const fitKeyRef = useRef('');
  const toastTimer = useRef<number | null>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 2600);
  }, []);

  /* ---------------- 檔案 ---------------- */

  const loadFile = useCallback((f: File) => {
    if (f.type !== 'application/pdf' && !f.name.toLowerCase().endsWith('.pdf')) {
      showToast('只能上傳 PDF 檔');
      return;
    }
    setFile(f);
    setPageNumber(1);
    setRedactions([]);
    setDetections([]);
    setWatermarkText('');
    setScale(1);
    fitKeyRef.current = '';
    setMarkMode(false);
  }, [showToast]);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) loadFile(f);
    e.target.value = '';
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files?.[0];
    if (f) loadFile(f);
  };

  /* ---------------- 頁面載入：自動 fit 寬度 ---------------- */

  const onPageLoadSuccess = useCallback(
    (page: { getViewport: (o: { scale: number }) => { width: number; height: number } }) => {
      const vp = page.getViewport({ scale: 1 });
      setPagePt({ w: vp.width, h: vp.height });
      const key = `${file?.name ?? ''}_${pageNumber}_${numPages}`;
      if (fitKeyRef.current !== key) {
        fitKeyRef.current = key;
        const cw = scrollRef.current?.clientWidth ?? window.innerWidth;
        const available = cw - (window.innerWidth < 768 ? 24 : 64);
        if (available > 0) setScale(clamp(available / vp.width, 0.25, 1));
      }
    },
    [file?.name, pageNumber, numPages]
  );

  /* ---------------- 拖曳框選 ---------------- */

  const getLocal = (e: React.PointerEvent) => {
    const rect = wrapperRef.current!.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
      rectW: rect.width,
      rectH: rect.height,
    };
  };

  const onPointerDown = (e: React.PointerEvent) => {
    if (!markMode || !file) return;
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    e.preventDefault();
    const { x, y } = getLocal(e);
    startPosRef.current = { x, y };
    setIsDrawing(true);
    setCurrentRect({ x, y, w: 0, h: 0 });
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    if (!isDrawing || !startPosRef.current) return;
    const { x, y } = getLocal(e);
    const s = startPosRef.current;
    setCurrentRect({
      x: Math.min(x, s.x),
      y: Math.min(y, s.y),
      w: Math.abs(x - s.x),
      h: Math.abs(y - s.y),
    });
  };

  const finishDraw = (e: React.PointerEvent) => {
    if (!isDrawing) return;
    setIsDrawing(false);
    const start = startPosRef.current;
    const cur = currentRect;
    startPosRef.current = null;
    setCurrentRect(null);
    if (!start || !cur || !wrapperRef.current) return;
    const { rectW, rectH } = getLocal(e);
    if (cur.w < 6 || cur.h < 6) return; // 太小視為誤觸

    const r: RedactionRect = {
      id: generateId(),
      pageIndex: pageNumber - 1,
      x: cur.x / rectW,
      y: cur.y / rectH,
      width: cur.w / rectW,
      height: cur.h / rectH,
      category: '手動',
    };
    setRedactions((prev) => [...prev, r]);
    if (navigator.vibrate) navigator.vibrate(12);
  };

  const removeRedaction = (id: string) => {
    setRedactions((prev) => prev.filter((r) => r.id !== id));
    setDetections((prev) => prev.filter((d) => d.id !== id));
  };

  const clearAll = () => {
    setRedactions([]);
    setDetections([]);
    showToast('已清除全部遮蔽');
  };

  /* ---------------- 自動偵測（本地規則引擎） ---------------- */

  const handleAnalyze = async () => {
    if (!file) return;
    if (isAnalyzing) return;
    setIsAnalyzing(true);
    setProgress({ done: 0, total: numPages });
    try {
      const buffer = await file.arrayBuffer();
      const pdf = await pdfjs.getDocument({ data: buffer }).promise;
      const found: Detection[] = [];
      for (let p = 1; p <= pdf.numPages; p++) {
        const page = await pdf.getPage(p);
        const vp = page.getViewport({ scale: 1 });
        const text = await page.getTextContent();
        const hits = detectPage(
          text.items as never[],
          vp as never,
          p - 1
        );
        found.push(...hits);
        setProgress({ done: p, total: pdf.numPages });
        page.cleanup();
      }
      await pdf.destroy();

      setDetections(found);
      setRedactions((prev) => [
        ...prev,
        ...found.map((d) => ({
          id: d.id,
          pageIndex: d.pageIndex,
          x: d.rect.x,
          y: d.rect.y,
          width: d.rect.width,
          height: d.rect.height,
          category: d.category,
        })),
      ]);
      showToast(
        found.length
          ? `找到 ${found.length} 處敏感資訊`
          : '這份 PDF 沒抓到常見敏感格式'
      );
    } catch (err) {
      console.error(err);
      showToast('掃描失敗，請確認檔案是否正常');
    } finally {
      setIsAnalyzing(false);
    }
  };

  /* ---------------- 導出 ---------------- */

  const handleExport = async () => {
    if (!file || isExporting) return;
    setIsExporting(true);
    setProgress({ done: 0, total: numPages });
    try {
      const blob = await exportRedactedPdf({
        file,
        redactions,
        watermarkText,
        renderScale: 2,
        onProgress: (done, total) => setProgress({ done, total }),
      });
      const base = file.name.replace(/\.pdf$/i, '');
      downloadBlob(blob, `${base}_已遮蔽.pdf`);
      showToast('已導出（文字層已移除，無法複製原文）');
    } catch (err) {
      console.error(err);
      showToast('導出失敗，請再試一次');
    } finally {
      setIsExporting(false);
    }
  };

  /* ---------------- 衍生資料 ---------------- */

  const pageRedactions = useMemo(
    () => redactions.filter((r) => r.pageIndex === pageNumber - 1),
    [redactions, pageNumber]
  );

  const displaySize = useMemo(
    () => ({ w: pagePt.w * scale, h: pagePt.h * scale }),
    [pagePt, scale]
  );

  const watermarkStyle = useMemo<React.CSSProperties>(() => {
    if (!watermarkText.trim()) return {};
    const len = watermarkText.trim().length || 1;
    const w = displaySize.w;
    const h = displaySize.h;
    // 旋轉 45° 後 bounding ≈ (字寬 + 字高) × 0.707，取保守值避免被裁
    const fontSize = Math.max(
      12,
      Math.min(h * 0.18, (Math.SQRT2 * Math.min(w, h) / (len + 1)) * 0.92)
    );
    return {
      fontSize: `${fontSize}px`,
      transform: 'rotate(-45deg)',
      whiteSpace: 'nowrap',
      color: 'rgba(220,38,38,0.13)',
      fontWeight: 900,
      textAlign: 'center',
      lineHeight: 1,
      maxWidth: 'none',
    };
  }, [watermarkText, displaySize]);

  const busy = isAnalyzing || isExporting;

  /* ---------------- 面板 ---------------- */

  const panel = (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-6 pt-6 pb-4 border-b border-slate-200/70">
        <div className="flex items-center gap-3">
          <div className="bg-gradient-to-tr from-cyan-400 to-violet-500 p-2.5 rounded-2xl shadow-lg shadow-cyan-500/25">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-black text-slate-900 tracking-tight leading-none">
              安全遮蔽
            </h1>
            <p className="text-[10px] font-bold text-cyan-600 tracking-widest uppercase mt-1">
              Local Engine · 不上傳
            </p>
          </div>
        </div>
        <div className="mt-3 flex items-start gap-2 bg-emerald-50 border border-emerald-100 rounded-xl px-3 py-2">
          <Lock className="w-3.5 h-3.5 text-emerald-600 mt-0.5 shrink-0" />
          <p className="text-[11px] font-bold text-emerald-700 leading-snug">
            檔案只在你的瀏覽器處理，不會上傳到任何伺服器。
          </p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar p-5 pb-10 space-y-5">
        {/* 上傳 */}
        <section>
          <input
            type="file"
            accept="application/pdf"
            ref={fileInputRef}
            onChange={onFileChange}
            className="hidden"
          />
          {!file ? (
            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-full border-2 border-dashed border-slate-300 rounded-2xl py-8 px-4 text-center hover:border-cyan-400 hover:bg-cyan-50/50 transition-all"
            >
              <Upload className="w-8 h-8 mx-auto mb-2 text-cyan-500" />
              <p className="text-sm font-black text-slate-700">選擇 PDF 檔</p>
              <p className="text-[11px] font-bold text-slate-400 mt-1">
                或把檔案拖進來
              </p>
            </button>
          ) : (
            <div className="flex items-center gap-2 bg-cyan-50 border border-cyan-100 rounded-xl p-3">
              <FileText className="w-4 h-4 text-cyan-600 shrink-0" />
              <span className="text-xs font-black text-slate-700 truncate flex-1">
                {file.name}
              </span>
              <button
                onClick={() => {
                  setFile(null);
                  setRedactions([]);
                  setDetections([]);
                  setNumPages(0);
                }}
                className="text-slate-400 hover:text-rose-500 p-1"
                aria-label="移除檔案"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          )}
        </section>

        {file && (
          <>
            {/* 自動偵測 */}
            <section className="space-y-2">
              <h2 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                <ScanText className="w-3.5 h-3.5" /> 自動偵測
              </h2>
              <Button
                onClick={handleAnalyze}
                isLoading={isAnalyzing}
                variant="purple"
                className="w-full"
                icon={<Sparkles className="w-4 h-4" />}
              >
                {isAnalyzing
                  ? `掃描中 ${progress.done}/${progress.total}`
                  : '掃描全部頁面'}
              </Button>
              <p className="text-[10px] font-bold text-slate-400 px-1 leading-relaxed">
                本機規則辨識：金額、電話、身分證、Email、信用卡、帳號、地址。
              </p>

              {detections.length > 0 && (
                <div className="space-y-1.5 max-h-56 overflow-y-auto custom-scrollbar pr-1 pt-1">
                  {detections.map((d) => (
                    <div
                      key={d.id}
                      className="flex items-center gap-2 bg-white border border-slate-200 rounded-lg px-2.5 py-1.5"
                      style={{ borderLeft: `3px solid ${categoryColor(d.category)}` }}
                    >
                      <button
                        onClick={() => {
                          setPageNumber(d.pageIndex + 1);
                          setPanelOpen(false);
                        }}
                        className="flex-1 text-left min-w-0"
                      >
                        <div className="text-[9px] font-black text-slate-400 uppercase tracking-wider">
                          {d.category} · P{d.pageIndex + 1}
                        </div>
                        <div className="text-[11px] font-bold font-mono text-slate-700 truncate">
                          {d.text}
                        </div>
                      </button>
                      <button
                        onClick={() => removeRedaction(d.id)}
                        className="text-slate-300 hover:text-rose-500 p-1"
                        aria-label="移除"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* 框選模式 */}
            <section className="space-y-2">
              <h2 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                <MousePointer2 className="w-3.5 h-3.5" /> 手動遮蔽
              </h2>
              <button
                onClick={() => {
                  setMarkMode((v) => !v);
                  setPanelOpen(false);
                }}
                className={`w-full rounded-xl px-4 py-3 text-sm font-black transition-all flex items-center justify-center gap-2 ${
                  markMode
                    ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/30'
                    : 'bg-white text-slate-700 border border-slate-200'
                }`}
              >
                <MousePointer2 className="w-4 h-4" />
                {markMode ? '框選模式：開（可拖曳）' : '開啟框選模式'}
              </button>
              <p className="text-[10px] font-bold text-slate-400 px-1">
                關閉時可正常滑動／捲動頁面
              </p>
            </section>

            {/* 浮水印 */}
            <section className="space-y-2">
              <h2 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                <Stamp className="w-3.5 h-3.5" /> 浮水印
              </h2>
              <input
                type="text"
                value={watermarkText}
                onChange={(e) => setWatermarkText(e.target.value)}
                placeholder="例如：僅供內部審核"
                className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-sm font-bold focus:outline-none focus:border-cyan-400 transition-all"
              />
              <p className="text-[10px] font-bold text-slate-400 px-1">
                會直接印在導出的檔案上（預覽可先看位置）
              </p>
            </section>

            {/* 遮蔽清單 */}
            <section className="space-y-2">
              <div className="flex items-center justify-between">
                <h2 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Eraser className="w-3.5 h-3.5" /> 已標記 {redactions.length} 處
                </h2>
                {redactions.length > 0 && (
                  <button
                    onClick={clearAll}
                    className="text-[10px] font-black text-rose-500 hover:text-rose-600"
                  >
                    全部清除
                  </button>
                )}
              </div>
              {redactions.length === 0 && (
                <p className="text-[11px] font-bold text-slate-400 bg-slate-50 rounded-xl px-3 py-3 text-center">
                  還沒有任何遮蔽
                </p>
              )}
            </section>
          </>
        )}
      </div>

      {file && (
        <div className="p-5 pt-3 border-t border-slate-200/70 bg-white/60">
          <Button
            onClick={handleExport}
            isLoading={isExporting}
            variant="rainbow"
            className="w-full py-4"
            icon={<Download className="w-5 h-5" />}
          >
            {isExporting
              ? `產生中 ${progress.done}/${progress.total}`
              : '下載遮蔽後 PDF'}
          </Button>
          <p className="text-[10px] font-bold text-slate-400 text-center mt-2">
            輸出為圖片化 PDF，原文無法被複製
          </p>
        </div>
      )}
    </div>
  );

  /* ---------------- 主畫面 ---------------- */

  return (
    <div
      className="h-[100dvh] w-full flex bg-[#f8fafc] text-slate-800 overflow-hidden"
      onDragOver={(e) => e.preventDefault()}
      onDrop={onDrop}
    >
      {/* 桌面側欄 */}
      <aside className="hidden md:flex w-[340px] shrink-0 glass-card border-r border-white/60 shadow-xl z-20">
        {panel}
      </aside>

      <main className="flex-1 flex flex-col min-w-0 relative">
        {/* 頂部工具列 */}
        <div className="h-auto py-2.5 px-3 md:px-6 flex items-center gap-2 md:gap-4 border-b border-slate-200/70 bg-white/70 backdrop-blur shrink-0">
          <div className="md:hidden flex items-center gap-2 mr-auto">
            <div className="bg-gradient-to-tr from-cyan-400 to-violet-500 p-1.5 rounded-xl">
              <ShieldCheck className="w-4 h-4 text-white" />
            </div>
            <span className="text-sm font-black tracking-tight">安全遮蔽</span>
          </div>

          {file ? (
            <>
              <div className="flex items-center bg-slate-100 rounded-xl p-1">
                <button
                  disabled={pageNumber <= 1}
                  onClick={() => setPageNumber((p) => Math.max(1, p - 1))}
                  className="p-2 hover:bg-white rounded-lg disabled:opacity-20 transition-all"
                  aria-label="上一頁"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="px-2 text-xs font-black tabular-nums whitespace-nowrap">
                  {pageNumber} / {numPages}
                </span>
                <button
                  disabled={pageNumber >= numPages}
                  onClick={() => setPageNumber((p) => Math.min(numPages, p + 1))}
                  className="p-2 hover:bg-white rounded-lg disabled:opacity-20 transition-all"
                  aria-label="下一頁"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>

              <div className="flex items-center bg-slate-100 rounded-xl p-1">
                <button
                  onClick={() => setScale((s) => clamp(s - 0.15, 0.25, 3))}
                  className="p-2 hover:bg-white rounded-lg transition-all"
                  aria-label="縮小"
                >
                  <ZoomOut className="w-4 h-4" />
                </button>
                <span className="px-1.5 text-[10px] font-black min-w-[42px] text-center tabular-nums">
                  {Math.round(scale * 100)}%
                </span>
                <button
                  onClick={() => setScale((s) => clamp(s + 0.15, 0.25, 3))}
                  className="p-2 hover:bg-white rounded-lg transition-all"
                  aria-label="放大"
                >
                  <ZoomIn className="w-4 h-4" />
                </button>
              </div>

              <div className="hidden md:flex items-center gap-1.5 bg-rose-50 border border-rose-100 px-3 py-1.5 rounded-full ml-auto">
                <div className="w-1.5 h-1.5 bg-rose-500 rounded-full" />
                <span className="text-[10px] font-black text-rose-600 uppercase tracking-widest">
                  已標記 {redactions.length} 處
                </span>
              </div>

              <button
                onClick={() => setMarkMode((v) => !v)}
                className={`md:hidden ml-auto p-2 rounded-xl transition-all ${
                  markMode ? 'bg-cyan-500 text-white' : 'bg-slate-100 text-slate-500'
                }`}
                aria-label="框選模式"
              >
                <MousePointer2 className="w-4 h-4" />
              </button>
            </>
          ) : (
            <span className="text-xs font-bold text-slate-400 ml-auto">
              PDF 個資遮蔽工具
            </span>
          )}
        </div>

        {/* 文件區 */}
        <div
          ref={scrollRef}
          className="flex-1 overflow-auto custom-scrollbar p-3 md:p-8 flex justify-center items-start"
        >
          {file ? (
            <div className="inline-block shadow-2xl rounded-lg overflow-hidden bg-white h-fit">
              <Document
                file={file}
                onLoadSuccess={({ numPages }) => setNumPages(numPages)}
                loading={
                  <div className="p-16 text-sm font-bold text-slate-400">
                    載入 PDF…
                  </div>
                }
                error={
                  <div className="p-16 text-sm font-bold text-rose-500">
                    PDF 載入失敗
                  </div>
                }
              >
                <div
                  ref={wrapperRef}
                  className="relative select-none no-select"
                  style={{
                    width: displaySize.w,
                    height: displaySize.h,
                    touchAction: markMode ? 'none' : 'pan-x pan-y',
                    cursor: markMode ? 'crosshair' : 'default',
                  }}
                  onPointerDown={onPointerDown}
                  onPointerMove={onPointerMove}
                  onPointerUp={finishDraw}
                  onPointerCancel={finishDraw}
                  onContextMenu={(e) => e.preventDefault()}
                >
                  <Page
                    pageNumber={pageNumber}
                    scale={scale}
                    renderTextLayer={false}
                    renderAnnotationLayer={false}
                    onLoadSuccess={onPageLoadSuccess as never}
                    canvasBackground="#ffffff"
                  />

                  {/* 浮水印預覽 */}
                  {watermarkText.trim() && (
                    <div className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden z-0">
                      <p style={watermarkStyle}>{watermarkText}</p>
                    </div>
                  )}

                  {/* 遮蔽框 */}
                  {pageRedactions.map((r) => (
                    <div
                      key={r.id}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (!markMode) removeRedaction(r.id);
                      }}
                      style={{
                        position: 'absolute',
                        left: `${r.x * 100}%`,
                        top: `${r.y * 100}%`,
                        width: `${r.width * 100}%`,
                        height: `${r.height * 100}%`,
                      }}
                      className={`bg-black z-10 shadow-sm ${
                        markMode ? '' : 'cursor-pointer'
                      }`}
                      title={markMode ? '' : '點擊移除'}
                    />
                  ))}

                  {/* 拖曳中的框 */}
                  {currentRect && (
                    <div
                      style={{
                        position: 'absolute',
                        left: currentRect.x,
                        top: currentRect.y,
                        width: currentRect.w,
                        height: currentRect.h,
                      }}
                      className="bg-cyan-500/25 border-2 border-cyan-500 border-dashed pointer-events-none z-20"
                    />
                  )}
                </div>
              </Document>
            </div>
          ) : (
            <div
              className="flex flex-col items-center justify-center h-full w-full text-center px-6"
              onClick={() => fileInputRef.current?.click()}
            >
              <div className="bg-white rounded-[32px] p-10 shadow-xl border border-slate-100 cursor-pointer hover:shadow-2xl transition-all">
                <Upload className="w-14 h-14 mx-auto text-cyan-500 mb-4" />
                <h3 className="text-xl font-black tracking-tight text-slate-800">
                  上傳 PDF 開始
                </h3>
                <p className="text-xs font-bold text-slate-400 mt-2 leading-relaxed">
                  自動找出金額、電話、個資
                  <br />
                  檔案不離開這台裝置
                </p>
              </div>
            </div>
          )}
        </div>

        {/* 手機底部列 */}
        {file && (
          <div className="md:hidden shrink-0 border-t border-slate-200 bg-white/90 backdrop-blur px-2.5 py-2.5 pb-[calc(0.625rem+env(safe-area-inset-bottom))] flex items-center gap-2">
            <button
              onClick={() => {
                setPanelOpen(true);
                handleAnalyze();
              }}
              className="flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-2xl bg-violet-50 text-violet-600 text-[10px] font-black"
            >
              <Sparkles className="w-[18px] h-[18px]" />
              掃描
            </button>
            <button
              onClick={() => setPanelOpen(true)}
              className="flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-2xl bg-slate-100 text-slate-600 text-[10px] font-black"
            >
              <Settings2 className="w-[18px] h-[18px]" />
              設定
            </button>
            <Button
              onClick={handleExport}
              isLoading={isExporting}
              variant="rainbow"
              className="flex-1 py-3"
              icon={<Download className="w-4 h-4" />}
            >
              {isExporting ? `${progress.done}/${progress.total}` : '下載 PDF'}
            </Button>
          </div>
        )}

        {/* 提示 */}
        {!file && (
          <div className="md:hidden shrink-0 px-4 pb-[calc(1rem+env(safe-area-inset-bottom))]">
            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-full py-3.5 rounded-2xl bg-slate-900 text-white text-sm font-black"
            >
              選擇 PDF
            </button>
          </div>
        )}

        {/* 手機面板抽屜 */}
        {panelOpen && (
          <div className="md:hidden fixed inset-0 z-50 flex flex-col justify-end">
            <div
              className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm"
              onClick={() => setPanelOpen(false)}
            />
            <div className="relative bg-white rounded-t-[28px] max-h-[88dvh] flex flex-col overflow-hidden shadow-2xl">
              <div className="flex justify-center pt-3 pb-1">
                <div className="w-10 h-1 rounded-full bg-slate-200" />
              </div>
              <div className="flex-1 min-h-0 overflow-hidden">{panel}</div>
            </div>
          </div>
        )}

        {/* Toast */}
        {toast && (
          <div className="fixed left-1/2 -translate-x-1/2 bottom-24 md:bottom-8 z-[60] px-4 py-2.5 rounded-2xl bg-slate-900 text-white text-xs font-bold shadow-2xl max-w-[90vw] text-center">
            {toast}
          </div>
        )}
      </main>
    </div>
  );
}

import type { Detection, RiskLevel } from '../types';

export interface DetectRule {
  category: string;
  riskLevel: RiskLevel;
  pattern: RegExp;
  /** 數字越大越優先（重疊時保留高者） */
  priority: number;
}

/**
 * 本地規則引擎：完全在瀏覽器執行，不上傳檔案。
 * 針對「有固定格式」的敏感資料（金額、電話、證號、Email…），
 * regex 的穩定度與召回率都比 LLM 好，而且結果可預期、可測試。
 */
export const RULES: DetectRule[] = [
  {
    category: '身分證字號',
    riskLevel: 'HIGH',
    priority: 100,
    pattern: /[A-Z][12]\d{8}/g,
  },
  {
    category: '信用卡號',
    riskLevel: 'HIGH',
    priority: 100,
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  },
  {
    category: 'Email',
    riskLevel: 'HIGH',
    priority: 95,
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    category: '手機號碼',
    riskLevel: 'HIGH',
    priority: 95,
    pattern: /09\d{2}[-\s]?\d{3}[-\s]?\d{3}/g,
  },
  {
    category: '市話號碼',
    riskLevel: 'MEDIUM',
    priority: 85,
    pattern: /0[2-8][-\s]?\d{3,4}[-\s]?\d{4}/g,
  },
  {
    category: '銀行帳號',
    riskLevel: 'HIGH',
    priority: 80,
    pattern: /\b\d{10,16}\b/g,
  },
  {
    category: '出生日期',
    riskLevel: 'MEDIUM',
    priority: 75,
    pattern: /\b(?:19|20)\d{2}[\/.-]\d{1,2}[\/.-]\d{1,2}\b/g,
  },
  {
    category: '金額',
    riskLevel: 'MEDIUM',
    priority: 70,
    pattern: /(?:NT\$|＄|\$|新台幣|台幣)?\s?\d{1,3}(?:,\d{3})+(?:\.\d+)?/g,
  },
  {
    category: '金額',
    riskLevel: 'MEDIUM',
    priority: 68,
    pattern: /\b\d+(?:\.\d+)?\s?元\b/g,
  },
  {
    category: '統一編號',
    riskLevel: 'LOW',
    priority: 40,
    pattern: /\b\d{8}\b/g,
  },
  {
    category: '地址',
    riskLevel: 'LOW',
    priority: 35,
    pattern: /[\u4e00-\u9fa5]{2,4}(?:市|縣)[\u4e00-\u9fa5]{1,4}(?:區|鄉|鎮|市)[\u4e00-\u9fa5\d之段巷弄號樓F\s-]{2,30}/g,
  },
];

const CHAR_SPACE = ' ';
const isCJKChar = (s: string) => /[\u3400-\u9fff\u3000-\u303f\uff00-\uffef]/.test(s);

/** 同一筆命中被 PDF 拆成多個 item 時，把重疊的片段併回一個框 */
function mergeSameHit(
  rects: { x: number; y: number; width: number; height: number }[]
) {
  if (rects.length <= 1) return rects;
  const out = rects.map((r) => ({ ...r }));
  let changed = true;
  while (changed) {
    changed = false;
    outer: for (let i = 0; i < out.length; i++) {
      for (let j = i + 1; j < out.length; j++) {
        const a = out[i];
        const b = out[j];
        const xOverlap = a.x < b.x + b.width && b.x < a.x + a.width;
        const xGap = Math.max(a.x, b.x) - Math.min(a.x + a.width, b.x + b.width);
        const close = xOverlap || xGap < Math.max(a.height, b.height) * 1.2;
        if (close) {
          const x1 = Math.min(a.x, b.x);
          const x2 = Math.max(a.x + a.width, b.x + b.width);
          const y1 = Math.min(a.y, b.y);
          const y2 = Math.max(a.y + a.height, b.y + b.height);
          out[i] = { x: x1, y: y1, width: x2 - x1, height: y2 - y1 };
          out.splice(j, 1);
          changed = true;
          break outer;
        }
      }
    }
  }
  return out;
}

interface CharMap {
  itemIdx: number;
  charIdx: number; // -1 代表 item 之間的填充空白
}

interface RawHit {
  category: string;
  riskLevel: RiskLevel;
  priority: number;
  text: string;
  start: number;
  end: number; // exclusive
}

type PdfTextItem = {
  str?: string;
  transform?: number[];
  width?: number;
  height?: number;
};

type AnyViewport = {
  width: number;
  height: number;
  convertToViewportRectangle: (rect: number[]) => number[];
};

/** 在整頁文字上跑所有規則，回傳字元區間命中 */
function findHits(fullText: string): RawHit[] {
  const hits: RawHit[] = [];
  for (const rule of RULES) {
    // 每次使用前重設 lastIndex，避免 g flag 的狀態污染
    rule.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.pattern.exec(fullText)) !== null) {
      const text = m[0];
      if (!text || !text.trim()) {
        if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++;
        continue;
      }
      // 避免純空白/純符號命中
      if (!/[\dA-Za-z\u4e00-\u9fa5]/.test(text)) {
        if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++;
        continue;
      }
      hits.push({
        category: rule.category,
        riskLevel: rule.riskLevel,
        priority: rule.priority,
        text: text.trim(),
        start: m.index,
        end: m.index + text.length,
      });
      if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++;
    }
  }
  // 去重：同區間只留優先度最高的
  hits.sort((a, b) => b.priority - a.priority || b.end - b.start - (a.end - a.start));
  const accepted: RawHit[] = [];
  for (const h of hits) {
    const conflict = accepted.some(
      (a) => h.start < a.end && h.end > a.start && h.start !== a.start
    );
    const exactDup = accepted.some((a) => a.start === h.start && a.end === h.end);
    if (conflict || exactDup) continue;
    accepted.push(h);
  }
  return accepted;
}

/** 將單一 item 內的字元區間換算成 viewport 矩形 */
function itemRect(
  item: PdfTextItem,
  localStart: number,
  localEnd: number,
  viewport: AnyViewport
): { x: number; y: number; width: number; height: number } | null {
  const str = item.str ?? '';
  const tr = item.transform;
  if (!str || !tr || tr.length < 6) return null;
  const len = str.length || 1;
  const width = item.width ?? 0;
  const e = tr[4];
  const f = tr[5];
  const fontHeight = Math.abs(item.height || tr[3] || 10);
  const ratioA = Math.max(0, Math.min(1, localStart / len));
  const ratioB = Math.max(0, Math.min(1, localEnd / len));
  const x1 = e + width * ratioA;
  const x2 = e + width * ratioB;
  const y1 = f - fontHeight * 0.22; // 稍微往下含字身
  const y2 = f + fontHeight * 0.95;

  const [vx1, vy1, vx2, vy2] = viewport.convertToViewportRectangle([x1, y1, x2, y2]);
  const left = Math.min(vx1, vx2);
  const top = Math.min(vy1, vy2);
  const w = Math.abs(vx2 - vx1);
  const h = Math.abs(vy2 - vy1);
  if (w < 0.5 || h < 0.5) return null;
  return {
    x: left / viewport.width,
    y: top / viewport.height,
    width: w / viewport.width,
    height: h / viewport.height,
  };
}

/** 合併同一行相鄰/重疊的矩形，避免一堆碎框 */
export function mergeRects<
  T extends { x: number; y: number; width: number; height: number }
>(rects: T[]): T[] {
  if (rects.length <= 1) return rects;
  const sorted = [...rects].sort((a, b) => a.y - b.y || a.x - b.x);
  const merged: T[] = [];
  for (const cur of sorted) {
    let done = false;
    for (const ex of merged) {
      const sameLine = Math.abs(cur.y - ex.y) < 0.012;
      const overlapX =
        cur.x < ex.x + ex.width + 0.012 && cur.x + cur.width > ex.x - 0.012;
      if (sameLine && overlapX) {
        const x1 = Math.min(ex.x, cur.x);
        const x2 = Math.max(ex.x + ex.width, cur.x + cur.width);
        const y1 = Math.min(ex.y, cur.y);
        const y2 = Math.max(ex.y + ex.height, cur.y + cur.height);
        ex.x = x1;
        ex.y = y1;
        ex.width = x2 - x1;
        ex.height = y2 - y1;
        done = true;
        break;
      }
    }
    if (!done) merged.push({ ...cur });
  }
  return merged;
}

let uid = 0;
const nextId = () => `d${Date.now().toString(36)}_${uid++}`;

/** 對單一頁的文字物件跑偵測，回傳帶座標的命中 */
export function detectPage(
  items: PdfTextItem[],
  viewport: AnyViewport,
  pageIndex: number
): Detection[] {
  const charMap: CharMap[] = [];
  let fullText = '';

  items.forEach((item, itemIdx) => {
    const str = item.str ?? '';
    if (!str) return;
    if (fullText.length > 0) {
      // 判斷是否需要插入分隔空白。對中日韓文字直接串接（PDF 常逐字切開），
      // 拉丁/數字只在水平間距明顯時補空白，避免把同一串數字斷開。
      const prev = items[itemIdx - 1];
      const tr = item.transform;
      const ptr = prev?.transform;
      const gap =
        tr && ptr && tr.length >= 6 && ptr.length >= 6
          ? tr[4] - (ptr[4] + (prev?.width ?? 0))
          : 0;
      const lineH = Math.abs(item.height || (tr ? tr[3] : 10) || 10);
      const prevLast = (prev?.str ?? '').slice(-1);
      const curFirst = str[0] ?? '';
      const cjkJoin = isCJKChar(prevLast) || isCJKChar(curFirst);
      if (!cjkJoin && gap > lineH * 0.5) {
        charMap.push({ itemIdx, charIdx: -1 });
        fullText += CHAR_SPACE;
      }
    }
    for (let i = 0; i < str.length; i++) {
      charMap.push({ itemIdx, charIdx: i });
    }
    fullText += str;
  });

  if (!fullText.trim()) return [];

  const hits = findHits(fullText);
  const out: Detection[] = [];

  for (const hit of hits) {
    // 收集此命中涉及的 item 與其字元區間
    const perItem = new Map<number, { min: number; max: number }>();
    for (let i = hit.start; i < hit.end && i < charMap.length; i++) {
      const cm = charMap[i];
      if (!cm || cm.charIdx === -1) continue;
      const prev = perItem.get(cm.itemIdx);
      if (prev) {
        prev.min = Math.min(prev.min, cm.charIdx);
        prev.max = Math.max(prev.max, cm.charIdx);
      } else {
        perItem.set(cm.itemIdx, { min: cm.charIdx, max: cm.charIdx });
      }
    }

    const rects: { x: number; y: number; width: number; height: number }[] = [];
    perItem.forEach((range, itemIdx) => {
      const r = itemRect(items[itemIdx], range.min, range.max + 1, viewport);
      if (r) rects.push(r);
    });
    if (!rects.length) continue;

    // 同一筆命中若被 PDF 拆成多段，併回一個框
    const lineGroups = mergeSameHit(rects);
    for (const r of lineGroups) {
      out.push({
        id: nextId(),
        category: hit.category,
        text: hit.text,
        riskLevel: hit.riskLevel,
        pageIndex,
        rect: r,
      });
    }
  }

  return out;
}

export function categoryColor(category: string): string {
  const map: Record<string, string> = {
    身分證字號: '#dc2626',
    信用卡號: '#dc2626',
    銀行帳號: '#ea580c',
    Email: '#9333ea',
    手機號碼: '#0ea5e9',
    市話號碼: '#0284c7',
    出生日期: '#4f46e5',
    金額: '#f59e0b',
    統一編號: '#059669',
    地址: '#64748b',
    手動: '#111827',
  };
  return map[category] ?? '#64748b';
}

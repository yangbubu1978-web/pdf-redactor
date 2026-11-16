import type { Detection, RiskLevel, Confidence } from '../types';

export interface DetectRule {
  category: string;
  riskLevel: RiskLevel;
  pattern: RegExp;
  /** 數字越大越優先（重疊時保留高者） */
  priority: number;
  /**
   * 上下文關鍵字：只有在 match 前後 window 字元內出現其中任一個，
   * 才視為命中。純數字規則（統編、帳號、日期）必須靠這個避免誤判。
   */
  require?: string[];
  /** 附近出現這些字就排除 */
  exclude?: string[];
  /** 只遮蔽指定的捕獲組（預設整個 match） */
  captureGroup?: number;
  /** 自訂上下文視窗字元數（預設前 30 / 後 18） */
  window?: number;
  /** require 的搜尋範圍：local＝只找附近字元（預設）；page＝整頁找 */
  scope?: 'local' | 'page';
  /** 是否也往後找關鍵字（預設否） */
  scanAfter?: boolean;
  /** 沒有上下文也能命中 → high；需要上下文 → medium */
  confidence: Confidence;
}

const AMOUNT_WORDS = [
  '金額', '薪資', '薪水', '價', '費', '合計', '總計', '小計', '單價',
  '本薪', '撥款', '匯款', '收入', '支出', '應付', '實付', '稅', '扣款',
  '加班', '獎金', '津貼', '補助', '保費', '給付', '報酬',
];

const PHONE_WORDS = [
  '電話', 'TEL', 'Tel', 'tel', '手機', '傳真', 'FAX', 'Fax', '分機',
  '聯絡', '連絡', '專線', '熱線',
];

const ACCOUNT_WORDS = [
  '帳號', '帳戶', '匯款', '銀行', '戶名', '存摺', '轉帳', 'ATM',
  '收款', '付款', '撥款', '入帳',
];

const TAX_ID_WORDS = ['統編', '統一編號', '營業人', '營利事業', '公司統編'];

const DATE_WORDS = [
  '生日', '出生', '到職', '入職', '年資', '結婚', '發證', '有效',
  '生效', '離職', '報到',
];

const CARD_WORDS = ['卡號', '信用卡', 'VISA', 'Master', 'MASTER', '簽帳', '金融卡'];

/**
 * 本地規則引擎：完全在瀏覽器執行，不上傳檔案。
 *
 * 設計原則：
 * 1. 格式本身就唯一的（身分證、Email、手機、帶分隔的卡號）→ 直接抓。
 * 2. 純數字（統編、帳號、8~16 碼數字）→ **必須有上下文關鍵字**才抓，
 *    否則日期、發票號、訂單號、頁碼全部都會被誤遮。
 */
export const RULES: DetectRule[] = [
  { category: '身分證字號', riskLevel: 'HIGH', priority: 100, confidence: 'high',
    pattern: /[A-Z][12]\d{8}/g },

  { category: 'Email', riskLevel: 'HIGH', priority: 98, confidence: 'high',
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },

  { category: '手機號碼', riskLevel: 'HIGH', priority: 97, confidence: 'high',
    pattern: /(?<!\d)(?:\+886[ -]?9|09)\d{2}[ -]?\d{3}[ -]?\d{3}(?!\d)/g },

  // 帶分隔的 4-4-4-4 幾乎只能是卡號
  { category: '信用卡號', riskLevel: 'HIGH', priority: 96, confidence: 'high',
    pattern: /\b(?:\d{4}[ -]){3}\d{4}\b/g },

  // 連續 16 碼沒有分隔 → 可能是卡號也可能是帳號，需上下文
  { category: '信用卡號', riskLevel: 'HIGH', priority: 70, confidence: 'medium',
    pattern: /\b\d{16}\b/g, require: CARD_WORDS },

  // 市話必須有分隔符或有電話字樣
  { category: '市話號碼', riskLevel: 'MEDIUM', priority: 90, confidence: 'high',
    pattern: /\(?0[2-8]\)?[ -]\d{3,4}[ -]\d{4}/g },

  { category: '市話號碼', riskLevel: 'MEDIUM', priority: 60, confidence: 'medium',
    pattern: /\b0[2-8]\d{6,8}\b/g, require: PHONE_WORDS },

  // 銀行帳號：一定要有帳號/匯款/銀行等字樣
  { category: '銀行帳號', riskLevel: 'HIGH', priority: 85, confidence: 'medium',
    pattern: /\b\d{10,16}\b/g, require: ACCOUNT_WORDS, window: 25 },

  // 統編：一定要有統編字樣，否則任何 8 位數字都會中
  { category: '統一編號', riskLevel: 'MEDIUM', priority: 75, confidence: 'medium',
    pattern: /\b\d{8}\b/g, require: TAX_ID_WORDS, window: 25 },

  // 日期：只有跟生日/到職等字樣相鄰才抓
  { category: '出生日期', riskLevel: 'MEDIUM', priority: 65, confidence: 'medium',
    pattern: /\b(?:19|20)\d{2}[\/.\-]\d{1,2}[\/.\-]\d{1,2}\b/g, require: DATE_WORDS, window: 14 },

  // 姓名：靠「姓名：」「聯絡人：」這類標籤抓
  { category: '姓名', riskLevel: 'MEDIUM', priority: 72, confidence: 'medium',
    pattern: /(?:姓名|名字|聯絡人|連絡人|申請人|填表人|收件人|寄件人|負責人|員工姓名|客戶名稱|承辦人|經辦人|處理人)[：: ]{0,4}([\u4e00-\u9fa5]{2,4})(?![ \u4e00-\u9fa5])/g,
    captureGroup: 1 },

  // 金額：有幣別符號就直接抓
  { category: '金額', riskLevel: 'MEDIUM', priority: 80, confidence: 'high',
    pattern: /(?:NT\$|N\$|＄|\$)[ ]?\d{1,3}(?:,\d{3})*(?:\.\d+)?/g },

  // 金額：有「元」字結尾
  { category: '金額', riskLevel: 'MEDIUM', priority: 78, confidence: 'high',
    pattern: /\d[\d,]*(?:\.\d+)?[ ]?元/g },

  // 金額：純千分位數字，需要金額相關字樣在附近
  { category: '金額', riskLevel: 'MEDIUM', priority: 66, confidence: 'medium',
    pattern: /\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b/g, require: AMOUNT_WORDS, scope: 'page' },

  // 地址：格式夠獨特，直接抓
  { category: '地址', riskLevel: 'LOW', priority: 50, confidence: 'high',
    pattern: /[\u4e00-\u9fa5]{2,4}(?:市|縣)[\u4e00-\u9fa5]{1,4}(?:區|鄉|鎮|市)[^\n]{2,30}/g },
];

/** 上下文視窗：往前 30 字、往後 18 字 */
const CTX_BEFORE = 30;
const CTX_AFTER = 18;

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
  confidence: Confidence;
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
      if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++;
      const raw = m[0];
      if (!raw) continue;

      // 只取指定捕獲組（例如姓名標籤後面的名字）
      let text = raw;
      let offset = 0;
      if (rule.captureGroup != null && m[rule.captureGroup]) {
        text = m[rule.captureGroup];
        const at = raw.indexOf(text);
        offset = at >= 0 ? at : 0;
      }
      if (!text.trim()) continue;
      if (!/[\dA-Za-z\u4e00-\u9fa5]/.test(text)) continue;

      const start = m.index + offset;
      const end = start + text.length;

      // 上下文檢查：純數字規則必須有相關字樣在附近
      if (rule.require || rule.exclude) {
        const before = rule.window ?? CTX_BEFORE;
        const after = rule.window ?? CTX_AFTER;
        // 預設只看「前面」：中文欄位標籤幾乎都在資料之前，
        // 若連後面一起看，下一段的關鍵字會污染判斷（例：日期誤判為到職日）。
        const beforeText = fullText.slice(Math.max(0, start - before), start);
        const afterText = rule.scanAfter
          ? fullText.slice(end, Math.min(fullText.length, end + after))
          : '';
        const scopeText =
          rule.scope === 'page' ? fullText : beforeText + afterText;
        if (rule.require && !rule.require.some((k) => scopeText.includes(k)))
          continue;
        if (rule.exclude && rule.exclude.some((k) => scopeText.includes(k)))
          continue;
      }

      hits.push({
        category: rule.category,
        riskLevel: rule.riskLevel,
        priority: rule.priority,
        text: text.trim(),
        start,
        end,
        confidence: rule.confidence,
      });
    }
  }
  // 去重：任何區間重疊都只留優先度最高的那筆（已依 priority 排序）
  hits.sort((a, b) => b.priority - a.priority || b.end - b.start - (a.end - a.start));
  const accepted: RawHit[] = [];
  for (const h of hits) {
    const overlap = accepted.some((a) => h.start < a.end && h.end > a.start);
    if (overlap) continue;
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

      // y 明顯改變 → 換行，保留行結構（避免跨行的假匹配，也讓規則能判斷行界）
      const prevY = ptr && ptr.length >= 6 ? ptr[5] : null;
      const curY = tr && tr.length >= 6 ? tr[5] : null;
      const newLine =
        prevY != null && curY != null && Math.abs(curY - prevY) > lineH * 1.2;

      if (newLine) {
        charMap.push({ itemIdx, charIdx: -1 });
        fullText += '\n';
      } else if (!cjkJoin && gap > lineH * 0.5) {
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
        confidence: hit.confidence,
        pageIndex,
        rect: r,
      });
    }
  }

  // 表格欄位推斷：姓名沒有格式可循，靠「姓名」表頭對齊下方欄位
  out.push(...detectTableNames(items, viewport, pageIndex, out));

  return out;
}

const NAME_HEADER = /^(姓名|名字|員工姓名|客戶名稱|聯絡人|連絡人|人員)$/;
const NAME_STOP = /^(備註|附註|說明|合計|總計|小計|地址|住址|電話|傳真|日期|簽章|單位|部門|職稱|金額|數量|頁次|簽名|核章)$/;

/** 從「姓名」表頭往下對齊找出姓名欄內容 */
function detectTableNames(
  items: PdfTextItem[],
  viewport: AnyViewport,
  pageIndex: number,
  existing: Detection[]
): Detection[] {
  type Header = { x1: number; x2: number; y: number; h: number };
  const headers: Header[] = [];

  items.forEach((it) => {
    const s = (it.str ?? '').trim().replace(/\s/g, '');
    const tr = it.transform;
    if (!s || !tr) return;
    if (NAME_HEADER.test(s)) {
      headers.push({
        x1: tr[4],
        x2: tr[4] + (it.width ?? 0),
        y: tr[5],
        h: Math.abs(it.height || tr[3] || 10),
      });
    }
  });
  if (!headers.length) return [];

  type Cand = {
    text: string;
    y: number;
    x1: number;
    x2: number;
    item: PdfTextItem;
  };
  const cands: Cand[] = [];
  items.forEach((it) => {
    const raw = (it.str ?? '').trim();
    if (!raw) return;
    if (!/^[\u4e00-\u9fa5]{2,4}$/.test(raw)) return;
    if (NAME_HEADER.test(raw) || NAME_STOP.test(raw)) return;
    const tr = it.transform;
    if (!tr) return;
    cands.push({
      text: raw,
      y: tr[5],
      x1: tr[4],
      x2: tr[4] + (it.width ?? 0),
      item: it,
    });
  });
  if (!cands.length) return [];

  const out: Detection[] = [];

  headers.forEach((hd) => {
    // 只取表頭下方、x 落在姓名欄範圍內的候選
    const inCol = cands
      .filter((c) => {
        const cx = (c.x1 + c.x2) / 2;
        return c.y < hd.y - 2 && cx >= hd.x1 - 14 && cx <= hd.x2 + 14;
      })
      .sort((a, b) => b.y - a.y);
    if (!inCol.length) return;

    // 由上往下走，遇到明顯斷行（表格結束）就停
    const gapLimit = Math.max(30, hd.h * 3.2);
    let prevY = hd.y;
    for (const c of inCol) {
      const gap = prevY - c.y;
      if (gap > gapLimit) break;
      if (gap <= 0) continue;
      prevY = c.y;

      const r = itemRect(c.item, 0, c.text.length, viewport);
      if (!r) continue;
      const dup = existing.some(
        (d) =>
          d.pageIndex === pageIndex &&
          Math.abs(d.rect.x - r.x) < 0.01 &&
          Math.abs(d.rect.y - r.y) < 0.01
      );
      if (dup) continue;

      out.push({
        id: nextId(),
        category: '姓名',
        text: c.text,
        riskLevel: 'MEDIUM',
        confidence: 'medium',
        pageIndex,
        rect: r,
      });
    }
  });

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
    姓名: '#7c3aed',
    地址: '#64748b',
    手動: '#111827',
  };
  return map[category] ?? '#64748b';
}

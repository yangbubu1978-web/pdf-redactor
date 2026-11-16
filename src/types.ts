export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';
export type Confidence = 'high' | 'medium';

/** 遮蔽框（比例座標 0~1，相對頁面） */
export interface RedactionRect {
  id: string;
  pageIndex: number; // 0-based
  x: number;
  y: number;
  width: number;
  height: number;
  category: string;
  confidence?: Confidence;
}

/** 規則引擎偵測結果 */
export interface Detection {
  id: string;
  category: string;
  text: string;
  riskLevel: RiskLevel;
  confidence: Confidence;
  pageIndex: number;
  rect: { x: number; y: number; width: number; height: number };
}

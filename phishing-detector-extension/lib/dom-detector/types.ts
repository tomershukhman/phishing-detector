// DOM detector types and interfaces

export interface DomFeature {
  name: string;
  value: boolean | number | string;
  weight: number;
  impact: number; // Impact on the final score (-1 to 1, where positive means more likely to be phishing)
}

export interface DomFeatures {
  url: string;
  features: DomFeature[];
  suspiciousScore: number; // 0-1 score where higher means more suspicious
  timestamp: number;
}

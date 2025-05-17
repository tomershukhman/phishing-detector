// DOM-based phishing detector
// This file re-exports all functionality from the dom-detector module
import { analyzeDom } from "./lib/dom-detector";
import type { DomFeature, DomFeatures } from "./lib/dom-detector/types";

export { analyzeDom };
export type { DomFeature, DomFeatures };

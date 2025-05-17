// Link features extraction for DOM detector
import type { DomFeature } from "./types"
import { domLogger as logger } from "../logger"

// Extract link-related features
export function extractLinkFeatures(features: DomFeature[]): void {
  const links = document.links;
  const currentDomain = window.location.hostname;
  
  // 1. Count mismatch between link text and href
  let linkMismatchCount = 0;
  let fakeHttpsInLinks = 0;
  let anchorWithIPAddress = 0;
  
  Array.from(links).forEach(link => {
    const href = link.href.toLowerCase();
    const linkText = link.textContent?.toLowerCase() || '';
    
    // Check for mismatch between link text and actual URL
    if (linkText.includes('http') && !linkText.includes(link.hostname)) {
      linkMismatchCount++;
    }
    
    // Check for IP addresses in links
    if (/href="https?:\/\/\d+\.\d+\.\d+\.\d+/.test(link.outerHTML)) {
      anchorWithIPAddress++;
    }
  });
  
  features.push({
    name: "linkMismatchCount",
    value: linkMismatchCount,
    weight: 0.7,
    impact: linkMismatchCount > 0 ? 0.6 : -0.1
  });
  
  features.push({
    name: "anchorWithIPAddress",
    value: anchorWithIPAddress,
    weight: 0.6,
    impact: anchorWithIPAddress > 0 ? 0.5 : -0.1
  });
  
  // 2. Count of external links
  const externalLinkCount = Array.from(links).filter(link => {
    return link.hostname && link.hostname !== currentDomain;
  }).length;
  
  features.push({
    name: "externalLinkCount",
    value: externalLinkCount,
    weight: 0.3,
    impact: externalLinkCount > 10 ? 0.2 : -0.1
  });

}

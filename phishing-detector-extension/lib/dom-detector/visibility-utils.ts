// Visibility utilities for DOM detection
import { domLogger as logger } from "../logger"

/**
 * Check if an element is actually visible to the user
 * Takes into account CSS visibility, dimensions, viewport position, and overlapping elements
 */
export const isElementVisible = (element: Element): boolean => {
  // Check all ancestors for visibility
  let currentElement: Element | null = element;
  while (currentElement) {
    const style = window.getComputedStyle(currentElement);
    
    // Check CSS visibility properties
    if (style.display === 'none' || 
        style.visibility === 'hidden' || 
        style.opacity === '0' || 
        parseFloat(style.opacity) < 0.2) {
      return false;
    }
    
    // Check if element is clipped by overflow
    if (style.overflow === 'hidden' || style.overflowY === 'hidden' || style.overflowX === 'hidden') {
      const parentRect = currentElement.getBoundingClientRect();
      const elementRect = element.getBoundingClientRect();
      
      // Check if element is outside the parent's bounds
      if (elementRect.top > parentRect.bottom || 
          elementRect.bottom < parentRect.top || 
          elementRect.left > parentRect.right || 
          elementRect.right < parentRect.left) {
        return false;
      }
    }
    
    // Move up the DOM tree
    currentElement = currentElement.parentElement;
  }
  
  // Get element dimensions and position
  const rect = element.getBoundingClientRect();
  
  // Check if element has zero dimensions or very small size (likely not visible text)
  if (rect.width <= 1 || rect.height <= 1) {
    return false;
  }
  
  // Check if element is outside the viewport
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
  
  if (rect.right < 0 || rect.bottom < 0 || 
      rect.left > viewportWidth || rect.top > viewportHeight) {
    return false;
  }
  
  // Check for text clipped by CSS overflow hidden with zero text-overflow
  const currentStyle = window.getComputedStyle(element);
  if (currentStyle.textOverflow === 'clip' || 
      (currentStyle.overflow === 'hidden' && !currentStyle.textOverflow)) {
    // If the text is likely clipped and too long, consider it not fully visible
    const contentWidth = element.scrollWidth;
    const visibleWidth = element.clientWidth;
    
    // If significant content is clipped, count this as not fully visible
    if (contentWidth > visibleWidth * 1.5) {
      return false;
    }
  }
  
  // Advanced check: sample multiple points on the element to detect partial visibility
  // For larger elements, check corners and center
  const pointsToCheck = [
    { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 }, // Center
    { x: rect.left + 5, y: rect.top + 5 },                          // Top-left 
    { x: rect.right - 5, y: rect.top + 5 },                         // Top-right
    { x: rect.left + 5, y: rect.bottom - 5 },                       // Bottom-left
    { x: rect.right - 5, y: rect.bottom - 5 }                       // Bottom-right
  ];
  
  // Filter to points that are within viewport
  const validPoints = pointsToCheck.filter(point => 
    point.x >= 0 && point.x <= viewportWidth && 
    point.y >= 0 && point.y <= viewportHeight
  );
  
  // If no valid points (all outside viewport), element is not visible
  if (validPoints.length === 0) return false;
  
  // Check each valid point to see if our element is visible there
  let visiblePointCount = 0;
  
  validPoints.forEach(point => {
    const elementsAtPoint = document.elementsFromPoint(point.x, point.y);
    let foundSelf = false;
    let foundObstruction = false;
    
    for (let i = 0; i < elementsAtPoint.length; i++) {
      const current = elementsAtPoint[i];
      
      // If we find our element, mark it
      if (current === element || element.contains(current) || current.contains(element)) {
        foundSelf = true;
        continue;
      }
      
      // Check if this element is before our target element and would hide it
      if (!foundSelf) {
        const style = window.getComputedStyle(current);
        const bgColor = style.backgroundColor;
        const bgImage = style.backgroundImage;
        
        if ((bgColor && bgColor !== 'rgba(0, 0, 0, 0)' && bgColor !== 'transparent') ||
            (bgImage && bgImage !== 'none')) {
          foundObstruction = true;
          break;
        }
      }
    }
    
    // Count this point as visible if we found our element and there was no obstruction
    if (foundSelf && !foundObstruction) {
      visiblePointCount++;
    }
  });
  
  // If at least one point is visible, consider the element visible
  return visiblePointCount > 0;
};

/**
 * Check if an element should be skipped because it's a child of an already processed element
 */
export const shouldSkipDueToProcessedParent = (element: Element, processedElements: Set<Element>): boolean => {
  let parent = element.parentElement;
  
  while (parent) {
    if (processedElements.has(parent)) {
      return true;
    }
    parent = parent.parentElement;
  }
  
  return false;
};

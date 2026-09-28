// Browser API shims that jsdom lacks (React Flow, matchMedia, clipboard...).
class RO { observe() {} unobserve() {} disconnect() {} }
(globalThis as any).ResizeObserver = RO;
(globalThis as any).IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } };
(globalThis as any).DOMMatrixReadOnly = class { m22 = 1; constructor(_?: any) {} };
Object.defineProperty(window, 'matchMedia', { writable: true, value: (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }) });
(Element.prototype as any).scrollIntoView = () => {};
(window as any).scrollTo = () => {};
Object.defineProperty(navigator, 'clipboard', { value: { writeText: async () => {} }, configurable: true });

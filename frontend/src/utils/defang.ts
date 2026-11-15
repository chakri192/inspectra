/**
 * Cybersecurity URL defanging utility.
 * Replaces schemes and periods with non-clickable tokens (hxxps:// and [.])
 * to prevent auto-unfurling, preview scraping, and accidental clicks when sharing.
 */
export function defangUrl(url: string): string {
  if (!url) return '';
  return url
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}

export function refangUrl(url: string): string {
  if (!url) return '';
  return url
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[\.\]/g, '.');
}

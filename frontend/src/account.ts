export type AccountProfile = { name: string; email: string; title: string; organization: string; timezone: string; bio: string };
export const defaultProfile: AccountProfile = { name: 'Alex Morgan', email: 'alex@apexbank.example', title: 'Security analyst', organization: 'Apex Global Bank', timezone: 'Asia/Calcutta', bio: 'Keeping our brand’s digital perimeter in focus.' };
export function readProfile(): AccountProfile {
  try { const saved = JSON.parse(localStorage.getItem('aegis-account-v1') ?? 'null'); return saved && typeof saved.name === 'string' && typeof saved.email === 'string' ? { ...defaultProfile, ...saved } : defaultProfile; } catch { return defaultProfile; }
}
export function initials(name: string) { return name.trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase() || 'AM'; }
export function saveProfile(profile: AccountProfile) { localStorage.setItem('aegis-account-v1', JSON.stringify(profile)); }

import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Bell, Check, ChevronRight, Fingerprint, Globe2, KeyRound, Laptop, LockKeyhole, LogOut, Mail, Shield, ShieldCheck, SlidersHorizontal, UserRound, X } from 'lucide-react';
import { initials, type AccountProfile } from './account';
import './account-theme.css';
import './account.css';
function AccountPanel({ title, sub, children, className = '' }: {
    title: string;
    sub: string;
    children: ReactNode;
    className?: string;
}) { return <section className={`panel account-panel ${className}`}><div className="panel-top"><div><h3>{title}</h3><span className="panel-sub">{sub}</span></div></div>{children}</section>; }
type Preferences = {
    critical: boolean;
    reviews: boolean;
    digest: boolean;
    product: boolean;
};
const defaultPreferences: Preferences = { critical: true, reviews: true, digest: false, product: false };
export function AccountPage({ profile, onSave, onSignOut }: {
    profile: AccountProfile;
    onSave: (profile: AccountProfile) => void;
    onSignOut: () => void;
}) {
    const [tab, setTab] = useState('profile');
    const [draft, setDraft] = useState(profile);
    const [status, setStatus] = useState('');
    const [confirm, setConfirm] = useState(false);
    const [preferences, setPreferences] = useState<Preferences>(() => { try {
        return { ...defaultPreferences, ...JSON.parse(localStorage.getItem('aegis-notifications-v1') ?? '{}') };
    }
    catch {
        return defaultPreferences;
    } });
    const navigate = useNavigate();
    const trigger = useRef<HTMLButtonElement>(null);
    const cancel = useRef<HTMLButtonElement>(null);
    const dialog = useRef<HTMLDivElement>(null);
    useEffect(() => { if (!confirm)
        return; cancel.current?.focus(); const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') {
        setConfirm(false);
        trigger.current?.focus();
    } if (e.key === 'Tab') {
        const buttons = dialog.current?.querySelectorAll<HTMLButtonElement>('button');
        if (!buttons?.length)
            return;
        const first = buttons[0], last = buttons[buttons.length - 1];
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
        }
        else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    } }; document.addEventListener('keydown', onKey); return () => document.removeEventListener('keydown', onKey); }, [confirm]);
    function save(e: FormEvent) { e.preventDefault(); const next = { ...draft, name: draft.name.trim(), email: draft.email.trim() }; if (!next.name) {
        setStatus('Enter a display name before saving.');
        return;
    } onSave(next); setDraft(next); setStatus('Profile saved on this device.'); }
    function savePreferences() { localStorage.setItem('aegis-notifications-v1', JSON.stringify(preferences)); setStatus('Preferences saved on this device. Notification delivery is not connected.'); }
    function logout() { onSignOut(); navigate('/login'); }
    const tabs = [{ id: 'profile', label: 'My profile', icon: UserRound }, { id: 'security', label: 'Security & access', icon: ShieldCheck }, { id: 'notifications', label: 'Notifications', icon: Bell }];
    return <><div className="page-title"><div><span className="eyebrow">YOUR IDENTITY / YOUR WORKSPACE</span><h1>Account settings<span>.</span></h1><p>A little more you. A workspace that works your way.</p></div><span className="account-preview-tag"><span className="dot"/> LOCAL DEMO ACCOUNT</span></div><section className="account-identity"><div className="account-avatar">{initials(profile.name)}<span><Check size={12}/></span></div><div><h2>{profile.name}</h2><p>{profile.email}</p><span className="account-role"><Shield size={11}/> Analyst · {profile.organization}</span></div><div className="account-identity-meta"><span className="eyebrow">ACCESS LEVEL</span><strong>Preview workspace</strong><span>Personal account / demo</span></div></section><div className="account-layout"><nav className="account-nav" aria-label="Account settings sections">{tabs.map(t => <button key={t.id} className={tab === t.id ? 'active' : ''} aria-pressed={tab === t.id} onClick={() => { setTab(t.id); setStatus(''); }}><t.icon size={17}/><span>{t.label}</span><ChevronRight size={13}/></button>)}<div className="account-nav-note"><Fingerprint size={29} strokeWidth={1}/><strong>Your space.<br />Your preferences.</strong><p>Profile and preferences are stored only on this device.</p></div><button className="account-signout" ref={trigger} onClick={() => setConfirm(true)}><LogOut size={16}/> Sign out of preview</button></nav><div className="account-content" key={tab}><div className="account-message" role="status" aria-live="polite">{status}</div>{tab === 'profile' && <form onSubmit={save}><AccountPanel title="Personal information" sub="The details your workspace knows you by."><div className="account-avatar-edit"><span>{initials(draft.name)}</span><div><strong>Your workspace avatar</strong><p>Generated from your display name.</p></div><span className="neutral-chip">AUTO INITIALS</span></div><div className="form"><div className="account-field-grid"><label>Display name<input required maxLength={70} autoComplete="name" value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })}/></label><label>Work email<input required type="email" autoComplete="email" value={draft.email} onChange={e => setDraft({ ...draft, email: e.target.value })}/></label><label>Job title<input maxLength={80} value={draft.title} onChange={e => setDraft({ ...draft, title: e.target.value })}/></label><label>Organization<input maxLength={80} autoComplete="organization" value={draft.organization} onChange={e => setDraft({ ...draft, organization: e.target.value })}/></label></div><label>About you<textarea rows={3} maxLength={240} value={draft.bio} onChange={e => setDraft({ ...draft, bio: e.target.value })}/><small className="field-hint">{draft.bio.length} / 240 characters</small></label></div></AccountPanel><AccountPanel title="Regional preferences" sub="Make the workspace feel closer to home."><div className="form account-region"><Globe2 size={22}/><label>Preferred time zone<select value={draft.timezone} onChange={e => setDraft({ ...draft, timezone: e.target.value })}><option value="Asia/Calcutta">India · Asia/Calcutta (UTC+05:30)</option><option value="UTC">Universal · UTC</option><option value="America/New_York">New York · America/New_York</option><option value="Europe/London">London · Europe/London</option><option value="Asia/Singapore">Singapore · Asia/Singapore</option></select><small className="field-hint">Saved as a profile preference; detection timestamps use your browser’s time zone.</small></label></div></AccountPanel><div className="account-save"><span><LockKeyhole size={12}/> Saved locally in this preview</span><button type="button" className="button subtle" onClick={() => { setDraft(profile); setStatus('Unsaved changes discarded.'); }}>Discard changes</button><button className="button primary" type="submit">Save changes <Check size={15}/></button></div></form>}{tab === 'security' && <><AccountPanel title="Sign-in & security" sub="A clear view of how you access your workspace."><div className="security-provider"><span><ShieldCheck size={25}/></span><div><strong>Authentication provider</strong><p>Connect a provider to enable verified login, password recovery, and two-factor authentication.</p></div><span className="neutral-chip">NOT CONNECTED</span></div><div className="security-row"><KeyRound size={19}/><div><strong>Password management</strong><p>Password changes require a connected authentication provider.</p></div><span className="security-unavailable">Unavailable in preview</span></div><div className="security-row"><Fingerprint size={21}/><div><strong>Two-factor authentication</strong><p>Add another layer of protection once authentication is connected.</p></div><span className="security-unavailable">Not configured</span></div></AccountPanel><AccountPanel title="This preview session" sub="Local browser access. No server session or token is issued."><div className="session-row"><span className="session-device"><Laptop size={25}/></span><div><strong>Current browser</strong><p>Local demo workspace</p><span className="verified"><span className="dot"/> THIS DEVICE</span></div><button className="button subtle" ref={trigger} onClick={() => setConfirm(true)}>End preview <LogOut size={14}/></button></div></AccountPanel><div className="info-note"><Shield size={19}/><span>Demo sign-out clears the local preview session. It does not revoke backend access; existing workspace routes remain available for preview.</span></div></>}{tab === 'notifications' && <><AccountPanel title="Make the signal yours" sub="Choose which updates should matter to you."><div className="notification-intro"><Bell size={28}/><p>Stay close to important decisions.<br /><span>These preferences are a local preview; no messages are sent.</span></p></div>{([{ key: 'critical', title: 'Critical threat alerts', text: 'High-priority identities and applications that need attention.', icon: Shield }, { key: 'reviews', title: 'Investigation updates', text: 'Case reviews and activity in your investigation queue.', icon: UserRound }, { key: 'digest', title: 'Weekly intelligence digest', text: 'A quieter summary of signals and brand protection activity.', icon: Mail }, { key: 'product', title: 'Platform updates', text: 'New capabilities and improvements to your workspace.', icon: SlidersHorizontal }] as const).map(n => <div className="notification-row" key={n.key}><n.icon size={19}/><div><strong>{n.title}</strong><p>{n.text}</p></div><button className={`toggle ${preferences[n.key] ? 'on' : ''}`} type="button" role="switch" aria-checked={preferences[n.key]} aria-label={n.title} onClick={() => setPreferences({ ...preferences, [n.key]: !preferences[n.key] })}><span /></button></div>)}</AccountPanel><div className="account-save"><span><Bell size={12}/> Delivery provider not connected</span><button className="button primary" onClick={savePreferences}>Save preferences <Check size={15}/></button></div></>}</div></div>{confirm && <div className="modal-backdrop account-modal-backdrop"><div className="account-confirm" ref={dialog} role="dialog" aria-modal="true" aria-labelledby="signout-title" aria-describedby="signout-description"><span className="confirm-icon"><LogOut size={27}/></span><h2 id="signout-title">Step out of the workspace?</h2><p id="signout-description">Your saved profile and preferences stay on this device. The local demo session will be cleared.</p><div><button ref={cancel} className="button subtle" onClick={() => { setConfirm(false); trigger.current?.focus(); }}>Stay here</button><button className="button primary" onClick={logout}>Sign out <ArrowRight size={15}/></button></div><button className="icon-button confirm-close" aria-label="Close sign-out dialog" onClick={() => { setConfirm(false); trigger.current?.focus(); }}><X size={17}/></button></div></div>}</>;
}

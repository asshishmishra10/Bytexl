import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield, Lock, Mail, User, Eye, EyeOff, ArrowRight, ShieldCheck,
  CheckCircle2, AlertCircle, Database, Sparkles, KeyRound
} from 'lucide-react';
import { signIn, signUp, SUPABASE_PROJECT_REF, type AnalystProfile } from './supabase';
import { readProfile, saveProfile } from './account';

interface AuthPageProps {
  mode?: 'login' | 'signup';
  onAuthSuccess?: (profile: AnalystProfile) => void;
}

export default function AuthPage({ mode = 'login', onAuthSuccess }: AuthPageProps) {
  const [isLogin, setIsLogin] = useState(mode === 'login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<AnalystProfile['role']>('Tier 1 SOC Analyst');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const navigate = useNavigate();

  React.useEffect(() => {
    setIsLogin(mode === 'login');
    setError(null);
    setSuccess(null);
  }, [mode]);

  const handleQuickFill = (analystEmail: string, name: string, userRole: AnalystProfile['role']) => {
    setEmail(analystEmail);
    setPassword('ApexSecure2026!');
    setFullName(name);
    setRole(userRole);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setBusy(true);

    try {
      if (isLogin) {
        const { user, error: loginError } = await signIn(email, password);
        if (loginError) {
          setError(loginError);
        } else if (user) {
          saveProfile({
            ...readProfile(),
            name: user.full_name,
            email: user.email,
            title: user.role,
          });
          setSuccess(`Authenticated as ${user.full_name} (${user.role}). Initializing SOC session…`);
          if (onAuthSuccess) onAuthSuccess(user);
          setTimeout(() => navigate('/app'), 800);
        }
      } else {
        if (!fullName.trim()) {
          setError('Full name is required to issue SOC credentials.');
          setBusy(false);
          return;
        }
        const { user, error: signupError, confirmationRequired } = await signUp(email, password, fullName, role);
        if (signupError) {
          setError(signupError);
        } else if (user) {
          saveProfile({
            ...readProfile(),
            name: user.full_name,
            email: user.email,
            title: user.role,
          });
          if (confirmationRequired) {
            setSuccess('Registration received. Check your email for Supabase verification or sign in directly.');
          } else {
            setSuccess(`SOC Analyst profile provisioned for ${user.full_name}. Routing to dashboard…`);
            if (onAuthSuccess) onAuthSuccess(user);
            setTimeout(() => navigate('/app'), 800);
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication service temporarily unreachable.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-viewport">
      {/* Background ambient lighting */}
      <div className="auth-backdrop" />

      <header className="auth-nav wrap">
        <Link className="logo" to="/">
          <span className="logo-symbol"><Shield size={23} strokeWidth={1.7} /></span>
          <span>AEGIS<span className="logo-light">SHIELD</span><small>DIGITAL RISK INTELLIGENCE</small></span>
        </Link>
        <Link className="button subtle" to="/">
          Back to overview <ArrowRight size={15} />
        </Link>
      </header>

      <main className="auth-container">
        <div className="auth-card">
          {/* Header */}
          <div className="auth-header">
            <div className="auth-badge">
              <Database size={13} style={{ color: 'var(--mint)' }} />
              <span>SUPABASE AUTH CONNECTED</span>
              <span className="mono" style={{ opacity: 0.7, fontSize: '10px' }}>({SUPABASE_PROJECT_REF})</span>
            </div>
            <h2>{isLogin ? 'Access Security Console' : 'Provision Analyst Access'}</h2>
            <p>
              {isLogin
                ? 'Authenticate your enterprise identity to inspect brand threat feeds and ML models.'
                : 'Create verified SOC credentials backed by Supabase Cloud RBAC and SQLite audit logs.'}
            </p>
          </div>

          {/* Mode Switcher */}
          <div className="auth-tabs" role="tablist">
            <button
              type="button"
              className={isLogin ? 'active' : ''}
              onClick={() => { setIsLogin(true); setError(null); setSuccess(null); }}
            >
              Sign In
            </button>
            <button
              type="button"
              className={!isLogin ? 'active' : ''}
              onClick={() => { setIsLogin(false); setError(null); setSuccess(null); }}
            >
              Register Analyst
            </button>
          </div>

          {/* Form */}
          <form className="auth-form" onSubmit={handleSubmit}>
            {!isLogin && (
              <>
                <label>
                  <span>Full Name</span>
                  <div className="input-affix">
                    <User size={16} />
                    <input
                      type="text"
                      required
                      placeholder="e.g. Elena Rostova"
                      value={fullName}
                      onChange={e => setFullName(e.target.value)}
                    />
                  </div>
                </label>

                <label>
                  <span>SOC Role / Permission Tier</span>
                  <select
                    value={role}
                    onChange={e => setRole(e.target.value as AnalystProfile['role'])}
                  >
                    <option value="Tier 1 SOC Analyst">Tier 1 SOC Analyst (Triage & Verify)</option>
                    <option value="Threat Intelligence Lead">Threat Intelligence Lead (Full Control)</option>
                    <option value="Incident Commander">Incident Commander (Escalations)</option>
                    <option value="Compliance Auditor">Compliance Auditor (Read-Only)</option>
                  </select>
                </label>
              </>
            )}

            <label>
              <span>Enterprise Email</span>
              <div className="input-affix">
                <Mail size={16} />
                <input
                  type="email"
                  required
                  placeholder="analyst@apexbank.com"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                />
              </div>
            </label>

            <label>
              <span>Password</span>
              <div className="input-affix">
                <Lock size={16} />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  className="icon-affix"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </label>

            {error && (
              <div className="auth-alert error">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            {success && (
              <div className="auth-alert success">
                <CheckCircle2 size={16} />
                <span>{success}</span>
              </div>
            )}

            <button type="submit" disabled={busy} className="button primary full auth-submit">
              {busy ? (
                <><span className="spinner" /> Communicating with Supabase Auth…</>
              ) : isLogin ? (
                <><KeyRound size={16} /> Authenticate into Console <ArrowRight size={16} /></>
              ) : (
                <><ShieldCheck size={16} /> Register Verified Credentials <ArrowRight size={16} /></>
              )}
            </button>
            <div style={{ textAlign: 'center', marginTop: '12px' }}>
              <button
                type="button"
                className="text-button"
                style={{ fontSize: '12px', color: 'var(--accent)', textDecoration: 'underline', background: 'transparent', border: 'none', cursor: 'pointer' }}
                onClick={() => {
                  setIsLogin(!isLogin);
                  setError(null);
                  setSuccess(null);
                }}
              >
                {isLogin
                  ? "Don't have an account? Sign up with Supabase →"
                  : "Already registered? Sign in to your SOC account →"}
              </button>
            </div>
          </form>

          {/* Quick-fill sample credentials for evaluators / hackathon judges */}
          <div className="quick-fill-box">
            <span className="eyebrow" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Sparkles size={12} style={{ color: 'var(--amber)' }} />
              1-CLICK DEMO ACCOUNTS (HACKATHON QUICK TEST)
            </span>
            <div className="quick-buttons">
              <button
                type="button"
                className="button subtle tiny"
                onClick={() => handleQuickFill('arthur.vance@apexbank.com', 'Arthur Vance', 'Threat Intelligence Lead')}
              >
                Lead Analyst (Arthur)
              </button>
              <button
                type="button"
                className="button subtle tiny"
                onClick={() => handleQuickFill('elena.rostova@apexbank.com', 'Elena Rostova', 'Incident Commander')}
              >
                Commander (Elena)
              </button>
              <button
                type="button"
                className="button subtle tiny"
                onClick={() => handleQuickFill('soc.analyst@apexbank.com', 'Kunal Kumar', 'Tier 1 SOC Analyst')}
              >
                SOC Tier 1 (Kunal)
              </button>
              <button
                type="button"
                className="button subtle tiny"
                onClick={() => handleQuickFill('compliance@apexbank.com', 'Dr. Sarah Chen', 'Compliance Auditor')}
              >
                Auditor (Sarah)
              </button>
            </div>
          </div>

          {/* Security details footer */}
          <div className="auth-footer">
            <span><ShieldCheck size={13} /> 256-bit TLS Encrypted Session</span>
            <span><Database size={13} /> Supabase Auth v2</span>
          </div>
        </div>
      </main>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Link2,
  Send,
  RotateCcw,
  Layers,
  AlertTriangle,
  Lock,
} from 'lucide-react';
import { scanMessage, checkHealth } from './services/api';
import RiskMeter from './components/RiskMeter';
import VerdictBanner from './components/VerdictBanner';
import HighlightedMessage from './components/HighlightedMessage';
import BilingualAdvice from './components/BilingualAdvice';
import TechnicalDetails from './components/TechnicalDetails';
import ScanHistoryView from './components/ScanHistoryView';
import AnalyticsView from './components/AnalyticsView';

// Preset test scenarios
const PRESETS = [
  {
    label: 'Bank KYC Scam',
    text: 'URGENT: Your SBI account has been blocked due to pending KYC verification. Click http://sbi-secure-kyc.com/update immediately to verify. Call +91 9876543210 with OTP 489201 to unblock.',
    url: 'http://sbi-secure-kyc.com/update',
  },
  {
    label: 'Electricity Disconnection',
    text: 'Dear Customer, your electricity power will be disconnected tonight at 9:30 PM from the electricity office. Call our electricity officer at +91 9812345678 or update your bill immediately.',
    url: 'http://power-bill-update.example.com/pay',
  },
  {
    label: 'Lottery Prize Trap',
    text: 'Congratulations! Your mobile number has won Rs. 25,00,000 in the All India Lucky Draw. To claim your prize, send your Aadhaar card details and pay processing fee at http://lucky-draw-claim.example.com',
    url: 'http://lucky-draw-claim.example.com',
  },
  {
    label: 'Genuine Bank Alert (Safe)',
    text: 'Hi Priya, the quarterly project presentation has been shared in the team folder. Please look it over before our sync tomorrow.',
    url: 'https://www.google.com',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner'); // 'scanner' | 'history' | 'analytics' | 'about'
  const [inputText, setInputText] = useState('');
  const [inputUrl, setInputUrl] = useState('');
  const [languagePreference, setLanguagePreference] = useState('both');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    checkHealth()
      .then((data) => setHealth(data))
      .catch(() => setHealth({ status: 'offline' }));
  }, []);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!inputText.trim() && !inputUrl.trim()) {
      setError('Please provide at least a text message or a URL to analyze.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = await scanMessage({
        text: inputText.trim() || undefined,
        url: inputUrl.trim() || undefined,
        language_preference: languagePreference,
      });
      setResult(data);
    } catch (err) {
      setError(err.message || 'Analysis request failed. Please ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setInputText('');
    setInputUrl('');
    setResult(null);
    setError(null);
  };

  const loadPreset = (preset) => {
    setInputText(preset.text);
    setInputUrl(preset.url);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#EBEBD8] text-[#455230] flex flex-col font-sans">
      {/* 1. Header with botanical linen styling */}
      <header className="border-b border-[#D6D8C2] bg-[#F7F7EE] sticky top-0 z-30 shadow-2xs">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-[#E5EADF] border border-[#9BA685] flex items-center justify-center text-[#455230] shadow-2xs">
              <Shield className="w-5 h-5 text-[#637545]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-[#455230]">ScaMail AI</h1>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#EBEBD8] border border-[#C8CBB3] text-[#455230] font-semibold">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-[#637545] leading-none hidden sm:block">
                Hybrid Scam & Phishing Decision-Support
              </p>
            </div>
          </div>

          {/* Navigation Tabs & Health Indicator */}
          <div className="flex items-center gap-3">
            <nav className="flex items-center bg-[#EBEBD8] rounded-xl p-1 border border-[#D6D8C2] text-xs">
              <button
                onClick={() => setActiveTab('scanner')}
                className={`px-3 py-1.5 rounded-lg transition-all ${
                  activeTab === 'scanner'
                    ? 'bg-[#455230] text-[#EBEBD8] font-semibold shadow-xs'
                    : 'text-[#637545] hover:text-[#455230]'
                }`}
              >
                Detector
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={`px-3 py-1.5 rounded-lg transition-all ${
                  activeTab === 'history'
                    ? 'bg-[#455230] text-[#EBEBD8] font-semibold shadow-xs'
                    : 'text-[#637545] hover:text-[#455230]'
                }`}
              >
                Audit History
              </button>
              <button
                onClick={() => setActiveTab('analytics')}
                className={`px-3 py-1.5 rounded-lg transition-all ${
                  activeTab === 'analytics'
                    ? 'bg-[#455230] text-[#EBEBD8] font-semibold shadow-xs'
                    : 'text-[#637545] hover:text-[#455230]'
                }`}
              >
                Analytics
              </button>
              <button
                onClick={() => setActiveTab('about')}
                className={`px-3 py-1.5 rounded-lg transition-all hidden md:block ${
                  activeTab === 'about'
                    ? 'bg-[#455230] text-[#EBEBD8] font-semibold shadow-xs'
                    : 'text-[#637545] hover:text-[#455230]'
                }`}
              >
                Architecture
              </button>
            </nav>

            {/* Health pill */}
            <div className="hidden sm:flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-[#EBEBD8] border border-[#D6D8C2]">
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.status === 'healthy' ? 'bg-[#637545] animate-pulse' : 'bg-[#DEBF7A]'
                }`}
              />
              <span className="text-[11px] text-[#455230] font-mono font-medium">
                {health?.status === 'healthy' ? 'Engine Ready' : 'Connecting'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* 2. Main Workspace */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-8">
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            {/* Input Form Card */}
            <div className="bg-white rounded-2xl border border-[#D6D8C2] p-5 sm:p-6 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                <div>
                  <h2 className="text-base font-bold text-[#455230]">Threat Input Analysis</h2>
                  <p className="text-xs text-[#637545] mt-0.5">
                    Paste any suspicious SMS, WhatsApp message, email, or website link for evaluation.
                  </p>
                </div>

                {/* Preset Chips */}
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] text-[#7D8A68] mr-1 hidden lg:inline font-medium">Presets:</span>
                  {PRESETS.map((p, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => loadPreset(p)}
                      className="px-2.5 py-1 rounded-lg text-xs bg-[#F4F4E8] border border-[#D6D8C2] text-[#455230] hover:border-[#637545] hover:bg-[#EBEBD8] transition-colors font-medium"
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              <form onSubmit={handleScan} className="space-y-4">
                {/* Text Message Field */}
                <div>
                  <label className="block text-xs font-bold text-[#455230] mb-1.5 uppercase tracking-wider">
                    Message Body (SMS / WhatsApp / Email)
                  </label>
                  <textarea
                    rows={4}
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    placeholder="e.g. URGENT: Your bank account will be deactivated today. Complete KYC verification now at http://fake-bank-update.com or send OTP..."
                    className="w-full px-4 py-3 rounded-xl bg-[#FAFBF5] border border-[#D6D8C2] text-[#2F3721] placeholder-[#7D8A68] focus:outline-none focus:border-[#637545] focus:ring-1 focus:ring-[#637545] text-sm leading-relaxed transition-all resize-y shadow-2xs"
                  />
                </div>

                {/* URL and Language Options */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="md:col-span-2">
                    <label className="block text-xs font-bold text-[#455230] mb-1.5 uppercase tracking-wider">
                      Website URL (Optional)
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#637545]">
                        <Link2 className="w-4 h-4" />
                      </div>
                      <input
                        type="text"
                        value={inputUrl}
                        onChange={(e) => setInputUrl(e.target.value)}
                        placeholder="http://sbi-secure-kyc.com/login"
                        className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#FAFBF5] border border-[#D6D8C2] text-[#2F3721] placeholder-[#7D8A68] focus:outline-none focus:border-[#637545] focus:ring-1 focus:ring-[#637545] text-sm font-mono transition-all shadow-2xs"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-[#455230] mb-1.5 uppercase tracking-wider">
                      Advice Language
                    </label>
                    <select
                      value={languagePreference}
                      onChange={(e) => setLanguagePreference(e.target.value)}
                      className="w-full px-3 py-2.5 rounded-xl bg-[#FAFBF5] border border-[#D6D8C2] text-[#455230] focus:outline-none focus:border-[#637545] focus:ring-1 focus:ring-[#637545] text-sm cursor-pointer font-medium shadow-2xs"
                    >
                      <option value="both" className="bg-white">Both (English & Hindi)</option>
                      <option value="en" className="bg-white">English Only</option>
                      <option value="hi" className="bg-white">हिंदी Only (Hindi)</option>
                    </select>
                  </div>
                </div>

                {/* Error Banner */}
                {error && (
                  <div className="p-3.5 rounded-xl bg-[#FAECEB] border border-[#DDA19E] text-[#8A2A24] text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 text-[#B34033]" />
                    <span>{error}</span>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex items-center justify-between pt-2">
                  <button
                    type="button"
                    onClick={handleClear}
                    className="flex items-center gap-1.5 text-xs text-[#637545] hover:text-[#455230] transition-colors px-3 py-2 rounded-lg hover:bg-[#F4F4E8] font-medium"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Clear Fields</span>
                  </button>

                  <button
                    type="submit"
                    disabled={loading}
                    className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-[#455230] hover:bg-[#637545] active:bg-[#344023] text-[#EBEBD8] font-semibold text-sm shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                  >
                    {loading ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        <span>Scanning Multi-Layer Signals...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4" />
                        <span>Run Threat Scan</span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>

            {/* Results Section */}
            {result && (
              <div className="space-y-6">
                {/* 1. Verdict Banner */}
                <VerdictBanner
                  verdict={result.verdict}
                  summary={result.summary}
                  riskScore={result.risk_score}
                />

                {/* 2. Core Insights Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Left Column: Risk Meter & Redacted Text */}
                  <div className="space-y-6">
                    <RiskMeter score={result.risk_score} level={result.risk_level} />

                    <HighlightedMessage
                      text={result.redacted_text}
                      highlightedTerms={result.detections?.rules?.highlighted_terms || []}
                    />
                  </div>

                  {/* Right Column: Bilingual Guidance & Technical Breakdown */}
                  <div className="lg:col-span-2 space-y-6">
                    <BilingualAdvice explanation={result.explanation} />
                    <TechnicalDetails detections={result.detections} />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'history' && <ScanHistoryView />}

        {activeTab === 'analytics' && <AnalyticsView />}

        {activeTab === 'about' && (
          <div className="bg-white rounded-2xl border border-[#D6D8C2] p-6 sm:p-8 space-y-6 shadow-sm">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#637545] mb-2">
                <Layers className="w-4 h-4" />
                <span>Multi-Tier Defense Architecture</span>
              </div>
              <h2 className="text-xl font-bold text-[#455230]">How ScaMail AI Protects Users</h2>
              <p className="text-sm text-[#4D5A38] leading-relaxed mt-2">
                ScaMail AI couples deterministic safety rules with statistical machine learning and decoupled LLM translations to catch sophisticated cyber extortion without privacy compromises.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-5 rounded-xl bg-[#F8F8F0] border border-[#D6D8C2] space-y-2">
                <span className="text-xs font-mono font-bold text-[#637545] block">Step 1</span>
                <h3 className="text-sm font-bold text-[#455230]">PII Redaction & Privacy</h3>
                <p className="text-xs text-[#4D5A38] leading-relaxed">
                  Scans and strips Indian phone numbers, Aadhaar numbers, card numbers, and OTPs before storage or LLM processing.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-[#F8F8F0] border border-[#D6D8C2] space-y-2">
                <span className="text-xs font-mono font-bold text-[#637545] block">Step 2</span>
                <h3 className="text-sm font-bold text-[#455230]">Rules & ML Fusion</h3>
                <p className="text-xs text-[#4D5A38] leading-relaxed">
                  Heuristic rules catch OTP/AnyDesk extortion; classical ML models evaluate text linguistics and URL character entropy with safety floor overrides.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-[#F8F8F0] border border-[#D6D8C2] space-y-2">
                <span className="text-xs font-mono font-bold text-[#637545] block">Step 3</span>
                <h3 className="text-sm font-bold text-[#455230]">Bilingual Safety Guide</h3>
                <p className="text-xs text-[#4D5A38] leading-relaxed">
                  Translates technical threat flags into clear English & Hindi actionable steps with verified reporting helplines (1930 / cybercrime.gov.in).
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* 3. Footer */}
      <footer className="border-t border-[#D6D8C2] bg-[#E2E2CD] py-6 text-center text-xs text-[#637545]">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 font-medium">
            <Lock className="w-3.5 h-3.5 text-[#637545]" />
            <span>Privacy Preserved: All personal details are redacted before processing</span>
          </div>

          <div className="flex items-center gap-4 text-[#455230]">
            <span>FastAPI Backend: <strong className="font-mono">http://localhost:8000</strong></span>
            <span>National Cyber Helpline: <strong>1930</strong></span>
          </div>
        </div>
      </footer>
    </div>
  );
}

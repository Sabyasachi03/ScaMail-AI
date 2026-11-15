import React, { useState } from 'react';
import { ShieldAlert, PhoneCall, Globe, CheckCircle2, Languages } from 'lucide-react';

export default function BilingualAdvice({ explanation = {} }) {
  const [langTab, setLangTab] = useState('both'); // 'both' | 'en' | 'hi'

  const en = explanation?.en;
  const hi = explanation?.hi;

  if (!en && !hi) return null;

  return (
    <div className="bg-white rounded-2xl border border-[#D6D8C2] p-5 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#EBEBD8] mb-5">
        <div className="flex items-center gap-2">
          <Languages className="w-4 h-4 text-[#637545]" />
          <h3 className="text-sm font-bold text-[#455230] tracking-wide uppercase">
            Actionable Safety Guidance
          </h3>
        </div>

        <div className="flex items-center bg-[#F4F4E8] rounded-xl p-1 border border-[#D6D8C2] self-start sm:self-auto text-xs">
          <button
            onClick={() => setLangTab('both')}
            className={`px-3 py-1 rounded-lg transition-all ${
              langTab === 'both'
                ? 'bg-[#455230] text-[#EBEBD8] font-medium shadow-xs'
                : 'text-[#637545] hover:text-[#455230]'
            }`}
          >
            Both (द्विभाषी)
          </button>
          <button
            onClick={() => setLangTab('en')}
            className={`px-3 py-1 rounded-lg transition-all ${
              langTab === 'en'
                ? 'bg-[#455230] text-[#EBEBD8] font-medium shadow-xs'
                : 'text-[#637545] hover:text-[#455230]'
            }`}
          >
            English
          </button>
          <button
            onClick={() => setLangTab('hi')}
            className={`px-3 py-1 rounded-lg transition-all ${
              langTab === 'hi'
                ? 'bg-[#455230] text-[#EBEBD8] font-medium shadow-xs'
                : 'text-[#637545] hover:text-[#455230]'
            }`}
          >
            हिंदी
          </button>
        </div>
      </div>

      <div className={`grid gap-5 ${langTab === 'both' && en && hi ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
        {/* English Advice */}
        {(langTab === 'both' || langTab === 'en') && en && (
          <div className="bg-[#F8F8F0] rounded-xl border border-[#D6D8C2] p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#637545] mb-2">
                <span>English Advisory</span>
              </div>
              <h4 className="text-base font-bold text-[#2F3721] mb-2">
                {en.title}
              </h4>
              <p className="text-sm text-[#4D5A38] leading-relaxed mb-4">
                {en.description}
              </p>

              {en.actions && en.actions.length > 0 && (
                <div className="space-y-2.5 mt-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-[#637545] block">
                    Recommended Actions:
                  </span>
                  {en.actions.map((act, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs text-[#2F3721] leading-normal">
                      <CheckCircle2 className="w-4 h-4 text-[#637545] shrink-0 mt-0.5" />
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Hindi Advice */}
        {(langTab === 'both' || langTab === 'hi') && hi && (
          <div className="bg-[#F8F8F0] rounded-xl border border-[#D6D8C2] p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#637545] mb-2">
                <span>हिंदी परामर्श (Hindi Guidance)</span>
              </div>
              <h4 className="text-base font-bold text-[#2F3721] mb-2">
                {hi.title}
              </h4>
              <p className="text-sm text-[#4D5A38] leading-relaxed mb-4">
                {hi.description}
              </p>

              {hi.actions && hi.actions.length > 0 && (
                <div className="space-y-2.5 mt-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-[#637545] block">
                    सुरक्षा के लिए आवश्यक कदम:
                  </span>
                  {hi.actions.map((act, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs text-[#2F3721] leading-normal">
                      <CheckCircle2 className="w-4 h-4 text-[#637545] shrink-0 mt-0.5" />
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Official Government Helplines */}
      <div className="mt-5 pt-4 border-t border-[#EBEBD8] flex flex-wrap items-center justify-between gap-3 text-xs text-[#637545]">
        <div className="flex items-center gap-1.5">
          <PhoneCall className="w-3.5 h-3.5 text-[#637545]" />
          <span>National Cyber Helpline: <strong className="text-[#455230]">1930</strong></span>
        </div>
        <div className="flex items-center gap-1.5">
          <Globe className="w-3.5 h-3.5 text-[#637545]" />
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-[#455230] underline font-medium transition-colors"
          >
            cybercrime.gov.in
          </a>
        </div>
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-[#637545]" />
          <a
            href="https://sancharsaathi.gov.in"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-[#455230] underline font-medium transition-colors"
          >
            Chakshu (sancharsaathi.gov.in)
          </a>
        </div>
      </div>
    </div>
  );
}

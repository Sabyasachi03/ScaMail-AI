import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert } from 'lucide-react';

export default function VerdictBanner({ verdict = 'Safe', summary = '', riskScore = 0 }) {
  const isScam = verdict === 'Likely Scam';
  const isSuspicious = verdict === 'Suspicious';

  let bgClass = 'bg-[#EDF3E8] border-[#A4C69D] text-[#2A5223]';
  let badgeClass = 'bg-[#D6E8D1] border-[#7DAA76] text-[#22481C]';
  let Icon = ShieldCheck;
  let title = 'Legitimate & Safe';

  if (isScam) {
    bgClass = 'bg-[#FAECEB] border-[#DDA19E] text-[#8A2A24]';
    badgeClass = 'bg-[#F5D6D4] border-[#C46C67] text-[#741F1A]';
    Icon = ShieldAlert;
    title = 'Likely Fraud / Phishing Scam';
  } else if (isSuspicious) {
    bgClass = 'bg-[#FAF3E3] border-[#DEBF7A] text-[#7D5310]';
    badgeClass = 'bg-[#F3E6C6] border-[#C49E48] text-[#6B450A]';
    Icon = AlertTriangle;
    title = 'Suspicious Signals Detected';
  }

  return (
    <div className={`rounded-2xl border p-5 shadow-sm transition-all ${bgClass}`}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-white/60 shrink-0 shadow-xs">
            <Icon className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-widest font-bold opacity-80">
                Evaluation Verdict
              </span>
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${badgeClass}`}>
                {verdict}
              </span>
            </div>
            <h2 className="text-lg font-bold mt-1 tracking-tight">
              {title}
            </h2>
            {summary && (
              <p className="text-sm mt-1 leading-normal opacity-90">
                {summary}
              </p>
            )}
          </div>
        </div>

        <div className="shrink-0 text-left sm:text-right pt-2 sm:pt-0 border-t sm:border-t-0 border-black/10">
          <span className="text-xs uppercase tracking-wider block opacity-75 font-medium">
            Composite Threat Score
          </span>
          <span className="text-2xl font-bold font-mono">
            {Number(riskScore).toFixed(1)}
            <span className="text-xs font-normal opacity-60"> / 100</span>
          </span>
        </div>
      </div>
    </div>
  );
}

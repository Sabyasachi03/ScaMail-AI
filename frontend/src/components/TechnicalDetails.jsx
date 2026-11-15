import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Cpu, Binary, Link2, AlertTriangle } from 'lucide-react';

export default function TechnicalDetails({ detections = {} }) {
  const [open, setOpen] = useState(false);

  const rules = detections?.rules || {};
  const textMl = detections?.text_ml || {};
  const urlMl = detections?.url_ml || {};

  const flags = rules?.flags || [];

  return (
    <div className="bg-white rounded-2xl border border-[#D6D8C2] overflow-hidden shadow-sm transition-all">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-5 py-4 flex items-center justify-between text-left hover:bg-[#F4F4E8] transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <Cpu className="w-4 h-4 text-[#637545]" />
          <span className="text-sm font-bold text-[#455230]">
            Technical Subsystem Detections
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-[#EBEBD8] border border-[#C8CBB3] text-[#455230] font-medium">
            {flags.length} Heuristic Flag{flags.length === 1 ? '' : 's'}
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-xs text-[#637545] font-medium">
          <span>{open ? 'Hide Details' : 'View Breakdown'}</span>
          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {open && (
        <div className="p-5 border-t border-[#EBEBD8] space-y-5 bg-[#FAFBF5]">
          {/* 1. Rule Engine Flags */}
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#637545] mb-3">
              <AlertTriangle className="w-3.5 h-3.5 text-[#637545]" />
              <span>Triggered Heuristic Rules</span>
            </div>

            {flags.length === 0 ? (
              <p className="text-xs text-[#7D8A68] italic">No heuristic rules triggered.</p>
            ) : (
              <div className="grid gap-2.5">
                {flags.map((flag, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-white border border-[#D6D8C2] flex flex-col sm:flex-row sm:items-center justify-between gap-2 shadow-2xs"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-[#2F3721] font-mono">
                          {flag.rule}
                        </span>
                        <span
                          className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                            flag.severity === 'critical'
                              ? 'bg-[#FAECEB] text-[#8A2A24] border border-[#DDA19E]'
                              : flag.severity === 'high'
                              ? 'bg-[#FAF3E3] text-[#7D5310] border border-[#DEBF7A]'
                              : 'bg-[#EDF3E8] text-[#2A5223] border border-[#A4C69D]'
                          }`}
                        >
                          {flag.severity}
                        </span>
                      </div>
                      <p className="text-xs text-[#4D5A38] mt-1">{flag.description}</p>
                    </div>

                    {flag.matched_text && (
                      <div className="text-[11px] font-mono bg-[#F4F4E8] px-2 py-1 rounded border border-[#D6D8C2] text-[#455230] shrink-0 self-start sm:self-auto font-medium">
                        Matched: "{flag.matched_text}"
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 2. Machine Learning Classifiers Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            {/* Text ML */}
            <div className="p-4 rounded-xl bg-white border border-[#D6D8C2] shadow-2xs">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Binary className="w-4 h-4 text-[#637545]" />
                  <span className="text-xs font-bold text-[#455230]">Text ML Classifier</span>
                </div>
                <span className="text-[11px] text-[#7D8A68] font-mono font-medium">TF-IDF + Logistic Reg</span>
              </div>

              {textMl.analyzed ? (
                <div className="space-y-1.5 text-xs text-[#2F3721]">
                  <div className="flex justify-between">
                    <span className="text-[#637545]">Prediction:</span>
                    <span className={`font-semibold capitalize ${textMl.prediction === 'scam' ? 'text-[#8A2A24]' : 'text-[#2A5223]'}`}>
                      {textMl.prediction}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#637545]">Scam Probability:</span>
                    <span className="font-mono font-medium">
                      {(textMl.probability * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-[#7D8A68] italic">
                  {textMl.error || 'Text was not submitted for ML analysis'}
                </p>
              )}
            </div>

            {/* URL ML */}
            <div className="p-4 rounded-xl bg-white border border-[#D6D8C2] shadow-2xs">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-[#637545]" />
                  <span className="text-xs font-bold text-[#455230]">URL Phishing Classifier</span>
                </div>
                <span className="text-[11px] text-[#7D8A68] font-mono font-medium">Random Forest</span>
              </div>

              {urlMl.analyzed ? (
                <div className="space-y-1.5 text-xs text-[#2F3721]">
                  <div className="flex justify-between">
                    <span className="text-[#637545]">Prediction:</span>
                    <span className={`font-semibold capitalize ${urlMl.prediction === 'phishing' ? 'text-[#8A2A24]' : 'text-[#2A5223]'}`}>
                      {urlMl.prediction}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#637545]">Phishing Probability:</span>
                    <span className="font-mono font-medium">
                      {(urlMl.probability * 100).toFixed(1)}%
                    </span>
                  </div>
                  {urlMl.flags && urlMl.flags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {urlMl.flags.map((fl, idx) => (
                        <span key={idx} className="text-[10px] px-1.5 py-0.5 bg-[#F4F4E8] rounded border border-[#D6D8C2] text-[#455230] font-medium">
                          {fl}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-[#7D8A68] italic">
                  {urlMl.error || 'No URL submitted for analysis'}
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

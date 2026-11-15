import React, { useState } from 'react';
import { Copy, Check, AlertCircle } from 'lucide-react';

export default function HighlightedMessage({ text = '', highlightedTerms = [] }) {
  const [copied, setCopied] = useState(false);

  if (!text) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const piiTokens = [
    '\\[PHONE_REDACTED\\]',
    '\\[OTP_REDACTED\\]',
    '\\[AADHAAR_REDACTED\\]',
    '\\[CARD_REDACTED\\]',
    '\\[ACCOUNT_REDACTED\\]',
    '\\[PAN_REDACTED\\]',
    '\\[UPI_REDACTED\\]',
    '\\[EMAIL_REDACTED\\]',
    '\\[IFSC_REDACTED\\]',
  ];

  const termsToHighlight = (highlightedTerms || [])
    .filter(Boolean)
    .map((term) => term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

  const allPatterns = [...termsToHighlight, ...piiTokens].filter(Boolean);

  let renderedContent = text;
  if (allPatterns.length > 0) {
    const regex = new RegExp(`(${allPatterns.join('|')})`, 'gi');
    const parts = text.split(regex);

    renderedContent = parts.map((part, index) => {
      const isPii = piiTokens.some((pt) =>
        new RegExp(`^${pt}$`, 'i').test(part)
      );
      const isKeyword = termsToHighlight.some((kt) =>
        new RegExp(`^${kt}$`, 'i').test(part)
      );

      if (isPii) {
        return (
          <span
            key={index}
            className="inline-flex items-center px-1.5 py-0.5 mx-0.5 rounded bg-[#E7EBDD] border border-[#9BA685] text-[#384825] text-xs font-mono font-medium"
            title="Personally Identifiable Information masked for privacy"
          >
            {part}
          </span>
        );
      }

      if (isKeyword) {
        return (
          <mark
            key={index}
            className="bg-[#FAECEB] border-b-2 border-[#B34033] text-[#8A2A24] px-1 py-0.5 rounded-xs font-semibold inline-block mx-0.5"
            title="Suspicious scam trigger keyword"
          >
            {part}
          </mark>
        );
      }

      return <span key={index}>{part}</span>;
    });
  }

  return (
    <div className="bg-white rounded-2xl border border-[#D6D8C2] p-5 shadow-sm">
      <div className="flex items-center justify-between pb-3 border-b border-[#EBEBD8] mb-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-[#455230]">
          <AlertCircle className="w-4 h-4 text-[#637545]" />
          <span>Analyzed Message Content</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-lg bg-[#F4F4E8] border border-[#D6D8C2] text-[#455230] hover:text-[#2A331D] hover:bg-[#EBEBD8] transition-colors"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-[#637545]" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied' : 'Copy Text'}</span>
        </button>
      </div>

      <div className="text-sm leading-relaxed text-[#2F3721] font-sans whitespace-pre-wrap select-text">
        {renderedContent}
      </div>

      {highlightedTerms.length > 0 && (
        <div className="mt-4 pt-3 border-t border-[#EBEBD8] flex flex-wrap items-center gap-2 text-xs">
          <span className="text-[#637545] font-medium">Scam Red Flags:</span>
          {highlightedTerms.map((term, i) => (
            <span
              key={i}
              className="px-2 py-0.5 rounded bg-[#FAECEB] border border-[#DDA19E] text-[#8A2A24] font-mono text-[11px]"
            >
              {term}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

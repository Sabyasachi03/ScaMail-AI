import React from 'react';

export default function RiskMeter({ score = 0, level = 'low' }) {
  const numericScore = Math.min(100, Math.max(0, Number(score) || 0));
  const radius = 64;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (numericScore / 100) * circumference;

  let color = '#637545'; // Forest Olive (Safe)
  let bgColor = '#EDF3E8';
  let textColor = '#2A5223';
  let label = 'Low Risk';

  if (numericScore >= 70) {
    color = '#B34033'; // Terracotta Red (Likely Scam)
    bgColor = '#FAECEB';
    textColor = '#8A2A24';
    label = 'High Risk';
  } else if (numericScore >= 35) {
    color = '#B87B2E'; // Warm Amber (Suspicious)
    bgColor = '#FAF3E3';
    textColor = '#7D5310';
    label = 'Moderate Risk';
  }

  return (
    <div className="flex flex-col items-center justify-center p-6 bg-white rounded-2xl border border-[#D6D8C2] shadow-sm">
      <div className="relative w-40 h-40 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
          {/* Background circle track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="#E7E9D7"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-bold tracking-tight text-[#455230]">
            {numericScore.toFixed(1)}
          </span>
          <span className="text-xs uppercase tracking-widest text-[#7D8A68] mt-0.5">
            out of 100
          </span>
        </div>
      </div>

      <div className="mt-3 text-center">
        <span
          className="inline-block px-3 py-1 rounded-full text-xs font-semibold tracking-wide border"
          style={{
            backgroundColor: bgColor,
            borderColor: color,
            color: textColor,
          }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}

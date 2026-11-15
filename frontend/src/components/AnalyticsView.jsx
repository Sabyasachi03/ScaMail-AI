import React, { useState, useEffect } from 'react';
import { BarChart3, PieChart, Activity, RefreshCw } from 'lucide-react';
import { getStats } from '../services/api';

export default function AnalyticsView() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStatsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getStats();
      setStats(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch analytics statistics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatsData();
  }, []);

  if (loading) {
    return <div className="text-center py-16 text-[#637545] text-sm">Loading security intelligence metrics...</div>;
  }

  if (error) {
    return (
      <div className="p-4 rounded-xl bg-[#FAECEB] border border-[#DDA19E] text-[#8A2A24] text-xs">
        {error}
      </div>
    );
  }

  const total = stats?.total_scans || 0;
  const breakdown = stats?.verdict_breakdown || { safe: 0, suspicious: 0, likely_scam: 0 };
  const categories = stats?.top_threat_categories || [];
  const avgScore = stats?.average_risk_score || 0;

  const safePct = total > 0 ? ((breakdown.safe / total) * 100).toFixed(1) : 0;
  const suspPct = total > 0 ? ((breakdown.suspicious / total) * 100).toFixed(1) : 0;
  const scamPct = total > 0 ? ((breakdown.likely_scam / total) * 100).toFixed(1) : 0;

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex items-center justify-between bg-white p-5 rounded-2xl border border-[#D6D8C2] shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-[#637545]" />
            <h2 className="text-base font-bold text-[#455230]">Threat Analytics & Model Insights</h2>
          </div>
          <p className="text-xs text-[#637545] mt-1">
            Aggregated decision telemetry across all analyzed communications.
          </p>
        </div>

        <button
          onClick={fetchStatsData}
          className="p-2 rounded-xl bg-[#F8F8F0] border border-[#D6D8C2] text-[#455230] hover:text-[#2A331D] hover:bg-[#EBEBD8] transition-colors"
          title="Refresh metrics"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-white border border-[#D6D8C2] shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-[#637545] block">
            Total Ingested Scans
          </span>
          <span className="text-3xl font-bold font-mono text-[#455230] mt-2 block">
            {total}
          </span>
          <span className="text-[11px] text-[#7D8A68] mt-1 block">Live database records</span>
        </div>

        <div className="p-5 rounded-2xl bg-white border border-[#D6D8C2] shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-[#637545] block">
            Average Risk Score
          </span>
          <span className="text-3xl font-bold font-mono text-[#455230] mt-2 block">
            {avgScore.toFixed(1)}
            <span className="text-xs font-normal text-[#7D8A68]"> / 100</span>
          </span>
          <span className="text-[11px] text-[#7D8A68] mt-1 block">Weighted composite average</span>
        </div>

        <div className="p-5 rounded-2xl bg-white border border-[#D6D8C2] shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-[#8A2A24] block">
            Scam Detection Rate
          </span>
          <span className="text-3xl font-bold font-mono text-[#8A2A24] mt-2 block">
            {scamPct}%
          </span>
          <span className="text-[11px] text-[#7D8A68] mt-1 block">{breakdown.likely_scam} identified scams</span>
        </div>

        <div className="p-5 rounded-2xl bg-white border border-[#D6D8C2] shadow-sm">
          <span className="text-xs font-bold uppercase tracking-wider text-[#2A5223] block">
            Benign Messages
          </span>
          <span className="text-3xl font-bold font-mono text-[#2A5223] mt-2 block">
            {safePct}%
          </span>
          <span className="text-[11px] text-[#7D8A68] mt-1 block">{breakdown.safe} cleared communications</span>
        </div>
      </div>

      {/* Visual Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Verdict Distribution Bar */}
        <div className="p-5 rounded-2xl bg-white border border-[#D6D8C2] space-y-4 shadow-sm">
          <div className="flex items-center gap-2">
            <PieChart className="w-4 h-4 text-[#637545]" />
            <h3 className="text-sm font-bold text-[#455230]">Verdict Proportion</h3>
          </div>

          <div className="w-full h-4 rounded-full overflow-hidden flex bg-[#EBEBD8]">
            <div style={{ width: `${safePct}%` }} className="bg-[#637545] transition-all duration-700" title={`Safe: ${safePct}%`} />
            <div style={{ width: `${suspPct}%` }} className="bg-[#B87B2E] transition-all duration-700" title={`Suspicious: ${suspPct}%`} />
            <div style={{ width: `${scamPct}%` }} className="bg-[#B34033] transition-all duration-700" title={`Scam: ${scamPct}%`} />
          </div>

          <div className="grid grid-cols-3 gap-2 pt-2 text-xs">
            <div className="p-2.5 rounded-xl bg-[#EDF3E8] border border-[#A4C69D]">
              <span className="text-[#2A5223] font-bold block">{breakdown.safe}</span>
              <span className="text-[#3E6637] text-[11px]">Safe ({safePct}%)</span>
            </div>
            <div className="p-2.5 rounded-xl bg-[#FAF3E3] border border-[#DEBF7A]">
              <span className="text-[#7D5310] font-bold block">{breakdown.suspicious}</span>
              <span className="text-[#8F651C] text-[11px]">Suspicious ({suspPct}%)</span>
            </div>
            <div className="p-2.5 rounded-xl bg-[#FAECEB] border border-[#DDA19E]">
              <span className="text-[#8A2A24] font-bold block">{breakdown.likely_scam}</span>
              <span className="text-[#A13A33] text-[11px]">Scam ({scamPct}%)</span>
            </div>
          </div>
        </div>

        {/* Top Threat Categories */}
        <div className="p-5 rounded-2xl bg-white border border-[#D6D8C2] space-y-4 shadow-sm">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-[#637545]" />
            <h3 className="text-sm font-bold text-[#455230]">Top Detected Threat Vectors</h3>
          </div>

          {categories.length === 0 ? (
            <p className="text-xs text-[#7D8A68] italic py-6 text-center">No threat categories logged yet.</p>
          ) : (
            <div className="space-y-3">
              {categories.map((cat, i) => {
                const maxCount = Math.max(...categories.map((c) => c.count), 1);
                const pct = ((cat.count / maxCount) * 100).toFixed(0);
                return (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-mono text-[#2F3721] capitalize font-medium">{cat.category.replace(/_/g, ' ')}</span>
                      <span className="text-[#637545] font-mono">{cat.count} scan{cat.count === 1 ? '' : 's'}</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-[#EBEBD8] overflow-hidden">
                      <div
                        style={{ width: `${pct}%` }}
                        className="h-full bg-[#637545] rounded-full transition-all duration-700"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

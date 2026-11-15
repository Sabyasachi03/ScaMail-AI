import React, { useState, useEffect } from 'react';
import { History, Filter, RefreshCw, AlertCircle, Clock } from 'lucide-react';
import { getHistory } from '../services/api';

export default function ScanHistoryView() {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filterVerdict, setFilterVerdict] = useState('');
  const [error, setError] = useState(null);

  const fetchHistoryData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getHistory({
        limit: 50,
        verdict: filterVerdict || undefined,
      });
      setScans(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to fetch scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistoryData();
  }, [filterVerdict]);

  const getBadge = (verdict) => {
    if (verdict === 'Likely Scam') {
      return 'bg-[#FAECEB] text-[#8A2A24] border-[#DDA19E]';
    }
    if (verdict === 'Suspicious') {
      return 'bg-[#FAF3E3] text-[#7D5310] border-[#DEBF7A]';
    }
    return 'bg-[#EDF3E8] text-[#2A5223] border-[#A4C69D]';
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-5 rounded-2xl border border-[#D6D8C2] shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-[#637545]" />
            <h2 className="text-base font-bold text-[#455230]">Scan Audit History</h2>
          </div>
          <p className="text-xs text-[#637545] mt-1">
            Persisted scans with all personal information (PII) masked for privacy. Total scans logged: <strong className="text-[#455230]">{total}</strong>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center bg-[#F8F8F0] rounded-xl px-2.5 py-1.5 border border-[#D6D8C2] text-xs">
            <Filter className="w-3.5 h-3.5 text-[#637545] mr-1.5" />
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="bg-transparent text-[#455230] focus:outline-none cursor-pointer text-xs font-medium"
            >
              <option value="" className="bg-white text-[#455230]">All Verdicts</option>
              <option value="Likely Scam" className="bg-white text-[#8A2A24]">Likely Scam</option>
              <option value="Suspicious" className="bg-white text-[#7D5310]">Suspicious</option>
              <option value="Safe" className="bg-white text-[#2A5223]">Safe</option>
            </select>
          </div>

          <button
            onClick={fetchHistoryData}
            disabled={loading}
            className="p-2 rounded-xl bg-[#F8F8F0] border border-[#D6D8C2] text-[#455230] hover:text-[#2A331D] hover:bg-[#EBEBD8] transition-colors"
            title="Refresh history"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-[#637545]' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-[#FAECEB] border border-[#DDA19E] text-[#8A2A24] text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-[#637545] text-sm">
          Loading audit logs...
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-white rounded-2xl border border-[#D6D8C2] p-12 text-center text-[#637545] shadow-sm">
          <p className="text-sm font-medium">No scans found matching current filters.</p>
          <span className="text-xs text-[#7D8A68] mt-1 block">Perform a scan to see it logged here.</span>
        </div>
      ) : (
        <div className="bg-white rounded-2xl border border-[#D6D8C2] overflow-hidden shadow-sm">
          <div className="divide-y divide-[#EBEBD8]">
            {scans.map((scan) => (
              <div
                key={scan.scan_id}
                className="p-4 sm:p-5 hover:bg-[#F8F8F0] transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-left"
              >
                <div className="space-y-1.5 flex-1 pr-4">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${getBadge(scan.verdict)}`}>
                      {scan.verdict}
                    </span>
                    <span className="text-xs font-mono font-bold text-[#455230]">
                      Score: {scan.risk_score.toFixed(1)}
                    </span>
                    {scan.top_category && (
                      <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-[#EBEBD8] text-[#455230] border border-[#C8CBB3] font-semibold">
                        {scan.top_category}
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-[#2F3721] font-sans line-clamp-2">
                    {scan.redacted_text_snippet || scan.url || 'No content snippet'}
                  </p>

                  <div className="flex items-center gap-4 text-[11px] text-[#637545]">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(scan.timestamp).toLocaleString()}
                    </span>
                    {scan.url && (
                      <span className="font-mono truncate max-w-xs text-[#455230]">
                        {scan.url}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

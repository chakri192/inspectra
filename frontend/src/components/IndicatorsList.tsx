import React from 'react';
import { AlertTriangle, CheckCircle } from 'lucide-react';
import { Finding, Severity } from '../types/api';

interface IndicatorsListProps {
  findings: Finding[];
}

export const IndicatorsList: React.FC<IndicatorsListProps> = ({ findings }) => {
  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'critical':
        return {
          label: 'Critical',
          class: 'bg-red-100 text-red-800 dark:bg-rose-950/70 dark:text-rose-300 border-red-600 dark:border-rose-800',
        };
      case 'high':
        return {
          label: 'High',
          class: 'bg-orange-100 text-orange-800 dark:bg-amber-950/70 dark:text-amber-300 border-orange-600 dark:border-amber-800',
        };
      case 'medium':
        return {
          label: 'Medium',
          class: 'bg-amber-100 text-amber-800 dark:bg-yellow-950/70 dark:text-yellow-300 border-amber-600 dark:border-yellow-800',
        };
      case 'low':
      default:
        return {
          label: 'Low',
          class: 'bg-stone-100 text-stone-700 dark:bg-stone-800 dark:text-stone-300 border-stone-300 dark:border-stone-700',
        };
    }
  };

  return (
    <div className="p-5 sm:p-6 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[4px_4px_0px_#000] space-y-4 transition-colors">
      <div className="flex items-center justify-between pb-3 border-b-2 border-black dark:border-[#27272A]">
        <h3 className="text-sm font-bold uppercase tracking-wide text-black dark:text-white">
          Detected indicators
        </h3>
        <span className="text-xs font-mono font-semibold px-2 py-0.5 bg-stone-100 dark:bg-[#25252A] text-black dark:text-stone-200 border border-stone-300 dark:border-stone-700">
          {findings.length} {findings.length === 1 ? 'indicator' : 'indicators'}
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="flex items-center gap-2.5 p-3.5 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-800 dark:text-emerald-200 border-2 border-emerald-600 dark:border-emerald-500 text-xs sm:text-sm font-medium">
          <CheckCircle className="w-5 h-5 flex-shrink-0 text-emerald-600 dark:text-emerald-400 stroke-[2.2]" />
          <span>No suspicious indicators were detected across completed evaluation rules.</span>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((finding, idx) => {
            const badge = getSeverityBadge(finding.severity);
            return (
              <div
                key={`${finding.rule_id}-${idx}`}
                className="p-3.5 bg-stone-50 dark:bg-[#18181B] border-2 border-black dark:border-stone-700 space-y-2"
              >
                {/* Header: Name and Severity */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-stone-200 dark:border-stone-800 pb-1.5">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2.2]" />
                    <h4 className="text-xs sm:text-sm font-bold text-black dark:text-white">
                      {finding.name}
                    </h4>
                  </div>
                  <span
                    className={`text-[11px] font-semibold px-2 py-0.5 border ${badge.class}`}
                  >
                    {badge.label}
                  </span>
                </div>

                {/* Evidence snippet */}
                {finding.evidence && (
                  <div className="p-2 bg-white dark:bg-[#101012] border border-stone-300 dark:border-stone-700 text-xs font-mono text-black dark:text-stone-200 overflow-x-auto">
                    <span className="text-[10px] uppercase font-bold text-stone-500 dark:text-stone-400 block mb-0.5">
                      Matched excerpt:
                    </span>
                    <span className="break-all bg-[#FFE600]/30 dark:bg-[#FFE600]/20 text-black dark:text-stone-100 px-1 py-0.5">
                      "{finding.evidence}"
                    </span>
                  </div>
                )}

                {/* Explanation */}
                <p className="text-xs text-stone-700 dark:text-stone-300 leading-relaxed font-medium">
                  {finding.explanation}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

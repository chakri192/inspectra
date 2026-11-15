import React from 'react';

interface RiskMeterProps {
  score: number;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ score }) => {
  const clampedScore = Math.max(0, Math.min(100, score));

  let tierLabel = 'Low risk';
  let tierBadge = 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-600 dark:border-emerald-800';
  let barColor = 'bg-emerald-500 dark:bg-emerald-400';

  if (clampedScore >= 75) {
    tierLabel = 'High risk';
    tierBadge = 'bg-red-100 text-red-800 dark:bg-rose-950/70 dark:text-rose-300 border-red-600 dark:border-rose-800';
    barColor = 'bg-red-600 dark:bg-rose-500';
  } else if (clampedScore >= 50) {
    tierLabel = 'Elevated risk';
    tierBadge = 'bg-orange-100 text-orange-800 dark:bg-amber-950/70 dark:text-amber-300 border-orange-600 dark:border-amber-800';
    barColor = 'bg-orange-500 dark:bg-amber-500';
  } else if (clampedScore >= 25) {
    tierLabel = 'Moderate risk';
    tierBadge = 'bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 border-amber-600 dark:border-amber-800';
    barColor = 'bg-amber-500 dark:bg-amber-400';
  }

  return (
    <div className="space-y-2.5 p-3.5 bg-stone-50 dark:bg-[#18181B] border-2 border-black dark:border-stone-700">
      <div className="flex items-center justify-between">
        <div>
          <span className="text-xs font-bold text-stone-600 dark:text-stone-400 uppercase tracking-wide">
            Risk score
          </span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-2xl sm:text-3xl font-mono font-bold text-black dark:text-white">
              {clampedScore}
            </span>
            <span className="text-xs font-mono text-stone-500 dark:text-stone-400">/ 100</span>
          </div>
        </div>

        <span className={`px-2.5 py-1 border text-xs font-semibold ${tierBadge}`}>
          {tierLabel}
        </span>
      </div>

      {/* Progress bar meter */}
      <div className="w-full h-4 bg-white dark:bg-[#0C0C0E] border-2 border-black dark:border-stone-700 p-0.5">
        <div
          className={`h-full border-r border-black dark:border-white transition-all duration-300 ${barColor}`}
          style={{ width: `${Math.max(2, clampedScore)}%` }}
          role="progressbar"
          aria-valuenow={clampedScore}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Risk score ${clampedScore} out of 100`}
        />
      </div>

      <div className="flex justify-between text-[11px] font-mono text-stone-500 dark:text-stone-400">
        <span>0 (Safe)</span>
        <span>25 (Threshold)</span>
        <span>50 (High)</span>
        <span>100</span>
      </div>
    </div>
  );
};

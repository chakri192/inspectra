import React from 'react';
import { Info } from 'lucide-react';

interface LimitationsNoticeProps {
  limitations: string[];
}

export const LimitationsNotice: React.FC<LimitationsNoticeProps> = ({ limitations }) => {
  return (
    <div className="p-5 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[4px_4px_0px_#000] space-y-3 transition-colors">
      <div className="flex items-center gap-2">
        <Info className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2.2]" />
        <h4 className="text-xs font-bold uppercase tracking-wide text-black dark:text-white">
          Assessment limitation
        </h4>
      </div>

      <div className="p-3.5 bg-stone-100 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700 text-xs sm:text-sm text-stone-800 dark:text-stone-200 space-y-1.5">
        <p className="font-semibold leading-relaxed">
          “This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent.”
        </p>
        <p className="text-xs text-stone-600 dark:text-stone-400">
          The risk score represents detected heuristic threat patterns, not a statistically validated probability of fraud or sender verification.
        </p>
      </div>

      {limitations.length > 1 && (
        <ul className="text-xs text-stone-600 dark:text-stone-400 space-y-1 pl-4 list-disc">
          {limitations.slice(1).map((lim, idx) => (
            <li key={idx} className="leading-snug">
              {lim}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

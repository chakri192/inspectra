import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Code2 } from 'lucide-react';
import { Finding } from '../types/api';

interface TechnicalDetailsProps {
  findings: Finding[];
  engineVersion: string;
  category: string;
  riskScore: number;
}

export const TechnicalDetails: React.FC<TechnicalDetailsProps> = ({
  findings,
  engineVersion,
  category,
  riskScore,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="border-2 border-black dark:border-stone-700 bg-white dark:bg-[#161619] shadow-[4px_4px_0px_#000] transition-colors">
      <button
        type="button"
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-5 py-3 flex items-center justify-between text-xs sm:text-sm font-bold uppercase tracking-wide text-black dark:text-white bg-stone-50 dark:bg-[#18181B] hover:bg-stone-100 dark:hover:bg-[#202024] transition-colors"
      >
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 stroke-[2.2]" />
          <span>Technical details</span>
        </div>
        <div className="flex items-center gap-1 text-xs text-stone-600 dark:text-stone-400 font-medium">
          <span>{isExpanded ? 'Hide' : 'Show'}</span>
          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {isExpanded && (
        <div className="p-4 sm:p-5 border-t-2 border-black dark:border-[#27272A] bg-white dark:bg-[#161619] space-y-4 text-xs">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div className="p-2.5 bg-stone-50 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700">
              <span className="text-[10px] text-stone-500 dark:text-stone-400 block uppercase font-bold">Engine version</span>
              <span className="text-black dark:text-white font-mono font-bold">{engineVersion}</span>
            </div>
            <div className="p-2.5 bg-stone-50 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700">
              <span className="text-[10px] text-stone-500 dark:text-stone-400 block uppercase font-bold">Category</span>
              <span className="text-black dark:text-white truncate block font-mono font-bold">{category}</span>
            </div>
            <div className="p-2.5 bg-stone-50 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700">
              <span className="text-[10px] text-stone-500 dark:text-stone-400 block uppercase font-bold">Risk score</span>
              <span className="text-black dark:text-white font-mono font-bold">{riskScore} / 100</span>
            </div>
            <div className="p-2.5 bg-stone-50 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700">
              <span className="text-[10px] text-stone-500 dark:text-stone-400 block uppercase font-bold">Rules triggered</span>
              <span className="text-black dark:text-white font-mono font-bold">{findings.length}</span>
            </div>
          </div>

          <div>
            <span className="text-xs font-bold uppercase tracking-wide text-stone-700 dark:text-stone-300 block mb-2">
              Triggered rule identifiers:
            </span>
            {findings.length === 0 ? (
              <p className="text-stone-500 dark:text-stone-400 italic">No rules triggered.</p>
            ) : (
              <div className="space-y-1.5">
                {findings.map((f, i) => (
                  <div
                    key={i}
                    className="p-2 bg-stone-50 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700 flex items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span className="font-mono font-bold text-black dark:text-stone-200">{f.rule_id}</span>
                      <span className="text-stone-500 dark:text-stone-400 text-xs truncate">({f.name})</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 border border-stone-400 dark:border-stone-600 font-mono uppercase bg-white dark:bg-[#101012] text-black dark:text-stone-200">
                      {f.severity}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

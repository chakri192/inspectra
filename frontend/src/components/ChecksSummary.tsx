import React from 'react';
import { Layers } from 'lucide-react';
import { ChecksStatus } from '../types/api';

interface ChecksSummaryProps {
  checks: ChecksStatus;
}

export const ChecksSummary: React.FC<ChecksSummaryProps> = ({ checks }) => {
  const formatStatus = (status?: string) => {
    switch (status) {
      case 'completed':
        return {
          label: 'Completed',
          class: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-600 dark:border-emerald-800',
        };
      case 'failed':
        return {
          label: 'Failed / Unavailable',
          class: 'bg-red-100 text-red-800 dark:bg-rose-950/70 dark:text-rose-300 border-red-600 dark:border-rose-800',
        };
      case 'skipped':
        return {
          label: 'Skipped',
          class: 'bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 border-amber-600 dark:border-amber-800',
        };
      case 'not_configured':
        return {
          label: 'Not configured',
          class: 'bg-stone-100 text-stone-600 dark:bg-stone-800 dark:text-stone-400 border-stone-300 dark:border-stone-700',
        };
      case 'not_applicable':
      default:
        return {
          label: 'Not applicable',
          class: 'bg-stone-100 text-stone-500 dark:bg-stone-800 dark:text-stone-400 border-stone-300 dark:border-stone-700',
        };
    }
  };

  const checkItems = [
    {
      id: 'text_analysis',
      title: 'Message patterns',
      description: 'Urgency, authority claims, secrecy, and credential requests',
      status: checks.text_analysis,
    },
    {
      id: 'url_structure',
      title: 'URL structure',
      description: 'Domain inspection, homoglyphs, IP host format, and executable paths',
      status: checks.url_structure,
    },
    {
      id: 'app_permission_analysis',
      title: 'App permissions',
      description: 'Combinations of sensitive privileges (Accessibility, SMS) and purpose mismatches',
      status: checks.app_permission_analysis || 'not_applicable',
    },
    {
      id: 'reputation',
      title: 'External reputation',
      description: 'Threat intelligence lookup feeds (configured via environment)',
      status: checks.reputation,
    },
    {
      id: 'ai_semantic_analysis',
      title: 'LLaMA semantic analysis',
      description: 'Local Ollama semantic social engineering evaluation',
      status: checks.ai_semantic_analysis || 'not_configured',
    },
  ];

  return (
    <div className="p-5 sm:p-6 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[4px_4px_0px_#000] space-y-4 transition-colors">
      <div className="flex items-center justify-between pb-3 border-b-2 border-black dark:border-[#27272A]">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2.2]" />
          <h3 className="text-sm font-bold uppercase tracking-wide text-black dark:text-white">
            Completed checks
          </h3>
        </div>
        <span className="text-xs text-stone-500 dark:text-stone-400">
          Check status audit
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        {checkItems.map((item) => {
          const statusMeta = formatStatus(item.status);

          return (
            <div
              key={item.id}
              className="p-3 bg-stone-50 dark:bg-[#18181B] border border-stone-300 dark:border-stone-700 flex flex-col justify-between space-y-1.5"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-1">
                  <h4 className="text-xs font-bold text-black dark:text-white">{item.title}</h4>
                  <span className={`text-[10px] px-2 py-0.5 border font-semibold ${statusMeta.class}`}>
                    {statusMeta.label}
                  </span>
                </div>
                <p className="text-xs text-stone-600 dark:text-stone-400 leading-snug">{item.description}</p>
              </div>

              {item.status === 'failed' && (
                <div className="text-[11px] text-red-700 dark:text-rose-300 bg-red-50 dark:bg-rose-950/40 p-1.5 border border-red-300 dark:border-rose-800">
                  Check unavailable. Failed checks are never converted to safe verdicts.
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

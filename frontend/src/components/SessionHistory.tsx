import React from 'react';
import { History, Trash2, ArrowRight } from 'lucide-react';
import { InputType, AnalyzeResponse, AppContext } from '../types/api';

export interface SessionHistoryItem {
  id: string;
  timestamp: string;
  inputType: InputType;
  snippet: string;
  result: AnalyzeResponse;
  rawInput: {
    message?: string;
    url?: string;
    appContent?: string;
    appContext?: AppContext;
  };
}

interface SessionHistoryProps {
  items: SessionHistoryItem[];
  selectedId: string | null;
  onSelect: (item: SessionHistoryItem) => void;
  onClear: () => void;
}

export const SessionHistory: React.FC<SessionHistoryProps> = ({
  items,
  selectedId,
  onSelect,
  onClear,
}) => {
  if (items.length === 0) return null;

  const getTypeLabel = (type: InputType) => {
    switch (type) {
      case 'message':
        return 'MSG';
      case 'url':
        return 'URL';
      case 'app_request':
        return 'APP';
      case 'qr_code':
        return 'QR';
    }
  };

  const getVerdictStyle = (verdict: string) => {
    switch (verdict) {
      case 'appears_safe':
        return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-400 dark:border-emerald-700';
      case 'suspicious':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/70 dark:text-rose-300 border-rose-400 dark:border-rose-700';
      default:
        return 'bg-amber-100 text-amber-900 dark:bg-amber-950/70 dark:text-amber-300 border-amber-400 dark:border-amber-700';
    }
  };

  const formatVerdict = (v: string) => {
    if (v === 'appears_safe') return 'Safe';
    if (v === 'suspicious') return 'Suspicious';
    return 'Unable';
  };

  return (
    <div className="p-3 sm:p-4 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[3px_3px_0px_#000] transition-colors">
      <div className="flex items-center justify-between gap-2 pb-2.5 mb-3 border-b border-stone-200 dark:border-stone-800">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2.2]" />
          <span className="text-xs font-bold uppercase tracking-wider text-black dark:text-white">
            Tab Session History
          </span>
          <span className="hidden sm:inline-block text-[11px] text-stone-500 dark:text-stone-400">
            (Last {items.length} in memory • zero persistence)
          </span>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-stone-600 dark:text-stone-400 hover:text-rose-600 dark:hover:text-rose-400 border border-stone-300 dark:border-stone-700 hover:border-rose-400 dark:hover:border-rose-600 bg-stone-50 dark:bg-[#1f1f24] transition-colors"
          title="Clear session history"
        >
          <Trash2 className="w-3 h-3 stroke-[2]" />
          <span>Clear history</span>
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {items.map((item) => {
          const isSelected = item.id === selectedId;
          const verdictClass = getVerdictStyle(item.result.verdict);

          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelect(item)}
              className={`group flex items-center gap-2 p-1.5 sm:px-2.5 sm:py-1.5 text-xs text-left border-2 transition-all ${
                isSelected
                  ? 'border-black dark:border-white bg-[#FFE600] text-black shadow-[2px_2px_0px_#000]'
                  : 'border-black dark:border-stone-700 bg-stone-50 dark:bg-[#1C1C20] text-black dark:text-stone-200 hover:bg-stone-100 dark:hover:bg-[#25252A] shadow-[1px_1px_0px_#000] active:translate-x-[1px] active:translate-y-[1px]'
              }`}
            >
              <span className={`px-1 py-0.5 text-[10px] font-bold border ${isSelected ? 'border-black bg-black text-white' : 'border-stone-400 dark:border-stone-600 bg-white dark:bg-[#121214] text-stone-800 dark:text-stone-300'}`}>
                {getTypeLabel(item.inputType)}
              </span>
              <span className="font-mono text-[11px] max-w-[130px] sm:max-w-[180px] truncate">
                {item.snippet}
              </span>
              <span className={`px-1.5 py-0.2 text-[10px] font-bold border ${verdictClass}`}>
                {formatVerdict(item.result.verdict)} ({item.result.risk_score})
              </span>
              <ArrowRight className={`w-3 h-3 ${isSelected ? 'text-black opacity-100' : 'text-stone-400 opacity-60 group-hover:opacity-100 group-hover:translate-x-0.5'} transition-transform`} />
            </button>
          );
        })}
      </div>
    </div>
  );
};

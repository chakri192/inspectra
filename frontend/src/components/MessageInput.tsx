import React from 'react';
import { Search, RotateCcw, AlertCircle } from 'lucide-react';

interface MessageInputProps {
  content: string;
  onChange: (val: string) => void;
  onAnalyze: () => void;
  onClear: () => void;
  isLoading: boolean;
  validationError?: string | null;
}

export const MessageInput: React.FC<MessageInputProps> = ({
  content,
  onChange,
  onAnalyze,
  onClear,
  isLoading,
  validationError,
}) => {
  const maxChars = 10000;
  const charsUsed = content.length;
  const isOverLimit = charsUsed > maxChars;

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      if (!isLoading && !isOverLimit && content.trim()) {
        onAnalyze();
      }
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label htmlFor="message-content" className="block text-xs font-bold text-stone-700 dark:text-stone-300 uppercase tracking-wide mb-1.5">
          Suspicious message text
        </label>
        <textarea
          id="message-content"
          value={content}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          rows={7}
          placeholder="Paste SMS, email, WhatsApp, or messaging text to analyze for phishing, urgency, impersonation, or OTP demands..."
          className={`w-full p-3.5 bg-white dark:bg-[#121214] border-2 font-sans text-sm text-black dark:text-stone-100 placeholder:text-stone-400 dark:placeholder:text-stone-600 focus:outline-none transition-all resize-y min-h-[160px] ${
            isOverLimit
              ? 'border-red-600 dark:border-red-500 bg-rose-50 dark:bg-rose-950/20 shadow-[2px_2px_0px_#DC2626]'
              : 'border-black dark:border-stone-700 shadow-[2px_2px_0px_#000] focus:shadow-[3px_3px_0px_#000] dark:focus:border-stone-400'
          }`}
        />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mt-2 text-xs">
          <span className="text-stone-500 dark:text-stone-400">
            Press <kbd className="px-1.5 py-0.5 bg-stone-100 dark:bg-[#1E1E22] border border-stone-300 dark:border-stone-700 font-mono text-[11px] text-stone-800 dark:text-stone-300">Ctrl+Enter</kbd> to analyze
          </span>
          <span
            className={`font-mono text-xs ${
              isOverLimit
                ? 'text-red-600 dark:text-red-400 font-bold'
                : 'text-stone-600 dark:text-stone-400'
            }`}
          >
            {charsUsed.toLocaleString()} / {maxChars.toLocaleString()} characters
          </span>
        </div>
      </div>

      {validationError && (
        <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 border-2 border-red-600 dark:border-red-500 text-xs font-medium">
          <AlertCircle className="w-4 h-4 flex-shrink-0 stroke-[2.2]" />
          <span>{validationError}</span>
        </div>
      )}

      <div className="flex items-center justify-end gap-3 pt-2">
        <button
          type="button"
          onClick={onClear}
          disabled={isLoading || !content}
          className="flex items-center gap-1.5 px-3.5 py-2 bg-white dark:bg-[#1E1E22] border-2 border-black dark:border-stone-600 text-xs font-semibold text-black dark:text-stone-200 shadow-[2px_2px_0px_#000] hover:bg-stone-100 dark:hover:bg-[#28282E] transition-all active:translate-x-[1px] active:translate-y-[1px] active:shadow-none disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <RotateCcw className="w-3.5 h-3.5 stroke-[2.2]" />
          <span>Clear</span>
        </button>

        <button
          type="button"
          onClick={onAnalyze}
          disabled={isLoading || isOverLimit || !content.trim()}
          className="flex items-center gap-2 px-6 py-2.5 bg-[#FFE600] hover:bg-[#FADC00] text-black border-2 border-black dark:border-[#FFE600] text-xs sm:text-sm font-bold shadow-[2px_2px_0px_#000] transition-all active:translate-x-[1px] active:translate-y-[1px] active:shadow-none disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {isLoading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-black border-t-transparent animate-spin" />
              <span>Analyzing...</span>
            </>
          ) : (
            <>
              <Search className="w-4 h-4 stroke-[2.5]" />
              <span>Analyze</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};

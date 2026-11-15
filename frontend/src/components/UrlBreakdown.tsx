import React, { useState } from 'react';
import { Globe, Copy, Check, ShieldCheck } from 'lucide-react';
import { UrlFinding } from '../types/api';
import { defangUrl } from '../utils/defang';

interface UrlBreakdownProps {
  urls: UrlFinding[];
}

export const UrlBreakdown: React.FC<UrlBreakdownProps> = ({ urls }) => {
  const [isDefanged, setIsDefanged] = useState(true);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (!urls || urls.length === 0) {
    return null;
  }

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="p-5 sm:p-6 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[4px_4px_0px_#000] space-y-4 transition-colors">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b-2 border-black dark:border-[#27272A]">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2.2]" />
          <h3 className="text-sm font-bold uppercase tracking-wide text-black dark:text-white">
            URL analysis
          </h3>
        </div>

        {/* Defang toggle switch */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setIsDefanged(!isDefanged)}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold border-2 transition-all ${
              isDefanged
                ? 'bg-[#FFE600] text-black border-black shadow-[1px_1px_0px_#000]'
                : 'bg-stone-100 dark:bg-[#25252A] text-stone-700 dark:text-stone-300 border-stone-300 dark:border-stone-700'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 stroke-[2.2]" />
            <span>Defang URLs: {isDefanged ? 'ON' : 'OFF'}</span>
          </button>
          <span className="text-xs text-stone-500 dark:text-stone-400 hidden sm:inline">
            {isDefanged ? '(hxxps, [.])' : '(raw text)'}
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {urls.map((urlItem, index) => {
          const isHighRisk = urlItem.risk_score >= 25;
          const displayUrl = isDefanged ? defangUrl(urlItem.raw_url) : urlItem.raw_url;
          const isCopied = copiedIndex === index;

          return (
            <div
              key={index}
              className="p-3.5 bg-stone-50 dark:bg-[#18181B] border-2 border-black dark:border-stone-700 space-y-3"
            >
              {/* URL Display (Strictly Non-Clickable Plain Text with Defanging) */}
              <div className="space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-semibold text-stone-600 dark:text-stone-400">
                    {urls.length > 1 ? `Link #${index + 1}` : 'Submitted link'}
                    {isDefanged && <span className="ml-1 text-emerald-600 dark:text-emerald-400 font-mono">[defanged]</span>}
                  </span>
                  <span
                    className={`px-2 py-0.5 text-[11px] font-semibold border ${
                      isHighRisk
                        ? 'bg-red-100 text-red-800 dark:bg-rose-950/70 dark:text-rose-300 border-red-600 dark:border-rose-800'
                        : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-600 dark:border-emerald-800'
                    }`}
                  >
                    Risk score: {urlItem.risk_score} / 100
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex-1 font-mono text-xs text-black dark:text-stone-200 break-all select-all bg-white dark:bg-[#101012] px-3 py-2 border border-stone-300 dark:border-stone-700">
                    {displayUrl}
                  </div>
                  <button
                    type="button"
                    onClick={() => handleCopy(displayUrl, index)}
                    title="Copy URL"
                    className="p-2 bg-white dark:bg-[#1E1E22] border-2 border-black dark:border-stone-600 text-black dark:text-stone-200 shadow-[1px_1px_0px_#000] hover:bg-stone-100 dark:hover:bg-[#28282E] flex-shrink-0"
                  >
                    {isCopied ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 stroke-[2.5]" />
                    ) : (
                      <Copy className="w-3.5 h-3.5 stroke-[2.2]" />
                    )}
                  </button>
                </div>
              </div>

              {/* Technical Attributes Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                <div className="p-2 bg-white dark:bg-[#121214] border border-stone-200 dark:border-stone-800">
                  <span className="text-[10px] text-stone-500 dark:text-stone-400 block font-semibold">ROOT DOMAIN</span>
                  <span className="text-black dark:text-white font-mono font-medium truncate block">
                    {urlItem.domain || 'N/A'}
                  </span>
                </div>

                <div className="p-2 bg-white dark:bg-[#121214] border border-stone-200 dark:border-stone-800">
                  <span className="text-[10px] text-stone-500 dark:text-stone-400 block font-semibold">HOST TYPE</span>
                  <span className="block font-medium text-black dark:text-white">
                    {urlItem.is_ip ? (
                      <span className="text-red-600 dark:text-rose-400 font-semibold">Raw IP host</span>
                    ) : (
                      'Named domain'
                    )}
                  </span>
                </div>

                <div className="p-2 bg-white dark:bg-[#121214] border border-stone-200 dark:border-stone-800">
                  <span className="text-[10px] text-stone-500 dark:text-stone-400 block font-semibold">TLD RISK</span>
                  <span className="block font-medium text-black dark:text-white">
                    {urlItem.has_suspicious_tld ? (
                      <span className="text-amber-600 dark:text-amber-400 font-semibold">High-risk TLD</span>
                    ) : (
                      'Standard'
                    )}
                  </span>
                </div>

                <div className="p-2 bg-white dark:bg-[#121214] border border-stone-200 dark:border-stone-800">
                  <span className="text-[10px] text-stone-500 dark:text-stone-400 block font-semibold">EXECUTABLE EXT</span>
                  <span className="block font-medium text-black dark:text-white">
                    {urlItem.has_executable_extension ? (
                      <span className="text-red-600 dark:text-rose-400 font-semibold">Executable / Package</span>
                    ) : (
                      'None'
                    )}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

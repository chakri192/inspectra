import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertCircle, RotateCcw, Copy, Check } from 'lucide-react';
import { Verdict, Finding, UrlFinding } from '../types/api';
import { RiskMeter } from './RiskMeter';
import { defangUrl } from '../utils/defang';

interface VerdictCardProps {
  verdict: Verdict;
  riskScore: number;
  category: string;
  summary: string;
  findings?: Finding[];
  urls?: UrlFinding[];
  onReset: () => void;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({
  verdict,
  riskScore,
  category,
  summary,
  findings = [],
  urls = [],
  onReset,
}) => {
  const [isReportCopied, setIsReportCopied] = useState(false);

  const formatCategory = (cat: string) => {
    const map: Record<string, string> = {
      phishing_and_deceptive_links: 'Phishing & deceptive links',
      digital_arrest_and_authority_impersonation: 'Digital-arrest & authority impersonation',
      suspicious_app_installation: 'Suspicious app installation & permissions',
      general_suspicious: 'General security threat pattern',
      insufficient_input: 'Insufficient content',
      benign: 'Benign content',
    };
    return map[cat] || cat.replace(/_/g, ' ');
  };

  const getVerdictDetails = () => {
    switch (verdict) {
      case 'appears_safe':
        return {
          title: 'Appears safe',
          badgeClass: 'bg-emerald-600 text-white dark:bg-emerald-500 dark:text-black border-2 border-black dark:border-emerald-400',
          icon: ShieldCheck,
          description: 'No meaningful suspicious indicators were detected by the rules engine.',
        };
      case 'suspicious':
        return {
          title: 'Suspicious',
          badgeClass: 'bg-red-600 text-white dark:bg-rose-600 dark:text-white border-2 border-black dark:border-rose-400',
          icon: ShieldAlert,
          description: 'Concerning security indicators or threat patterns were detected in the submission.',
        };
      case 'unable_to_assess':
      default:
        return {
          title: 'Unable to assess',
          badgeClass: 'bg-[#FFE600] text-black border-2 border-black dark:border-[#FFE600]',
          icon: AlertCircle,
          description: 'Input content was insufficient or essential checks could not complete.',
        };
    }
  };

  const handleCopyReport = () => {
    const defangedLinks =
      urls.length > 0
        ? urls.map((u) => `  * ${defangUrl(u.raw_url)} (Risk: ${u.risk_score}/100)`).join('\n')
        : '';

    const indicatorsList =
      findings.length > 0
        ? findings.map((f) => `  * [${f.severity.toUpperCase()}] ${f.name}`).join('\n')
        : '  * None detected';

    const reportLines = [
      '========================================',
      'CYBERSHIELD SECURITY ASSESSMENT REPORT',
      '========================================',
      `Verdict: ${verdict.toUpperCase().replace(/_/g, ' ')}`,
      `Risk Score: ${riskScore} / 100`,
      `Threat Category: ${formatCategory(category)}`,
      `Summary: ${summary}`,
      '',
      ...(defangedLinks ? ['Analyzed Links (Defanged):', defangedLinks, ''] : []),
      'Detected Indicators:',
      indicatorsList,
      '',
      'Limitation Notice:',
      'This assessment is heuristic and based on the submitted content and available checks.',
      'It does not guarantee safety or confirm malicious intent.',
      '========================================',
    ];

    navigator.clipboard.writeText(reportLines.join('\n'));
    setIsReportCopied(true);
    setTimeout(() => setIsReportCopied(false), 2000);
  };

  const details = getVerdictDetails();
  const IconComponent = details.icon;

  return (
    <div className="p-5 sm:p-6 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[4px_4px_0px_#000] space-y-5 transition-colors">
      {/* 1. Verdict & Action Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b-2 border-black dark:border-[#27272A]">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-[#FFE600] text-black border-2 border-black shadow-[2px_2px_0px_#000]">
            <IconComponent className="w-6 h-6 stroke-[2.2]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-stone-600 dark:text-stone-400 uppercase tracking-wide">
                Verdict:
              </span>
              <span
                className={`px-3 py-1 font-bold text-sm uppercase ${details.badgeClass}`}
                role="status"
              >
                {details.title}
              </span>
            </div>
            <p className="text-xs text-stone-600 dark:text-stone-400 mt-1">
              {details.description}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleCopyReport}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-[#1E1E22] hover:bg-stone-100 dark:hover:bg-[#28282E] text-black dark:text-stone-200 border-2 border-black dark:border-stone-600 text-xs font-semibold shadow-[2px_2px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all"
            title="Copy sanitized assessment summary"
          >
            {isReportCopied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 stroke-[2.5]" />
                <span>Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 stroke-[2.2]" />
                <span>Copy summary</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={onReset}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-[#1E1E22] hover:bg-stone-100 dark:hover:bg-[#28282E] text-black dark:text-stone-200 border-2 border-black dark:border-stone-600 text-xs font-semibold shadow-[2px_2px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all"
          >
            <RotateCcw className="w-3.5 h-3.5 stroke-[2.2]" />
            <span>Analyze another</span>
          </button>
        </div>
      </div>

      {/* 2. Risk Score & 3. Category */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="md:col-span-2">
          <RiskMeter score={riskScore} />
        </div>

        <div className="p-3.5 bg-stone-50 dark:bg-[#18181B] border-2 border-black dark:border-stone-700 flex flex-col justify-between">
          <div>
            <span className="text-xs font-bold text-stone-600 dark:text-stone-400 uppercase tracking-wide block mb-1">
              Content category
            </span>
            <div className="text-sm font-bold text-black dark:text-white mt-1">
              {formatCategory(category)}
            </div>
          </div>
          <span className="text-[11px] text-stone-500 dark:text-stone-400 mt-2 block">
            Determined by dominant rule pattern
          </span>
        </div>
      </div>

      {/* 4. Short Analysis Summary */}
      <div className="p-4 bg-stone-50 dark:bg-[#18181B] border-2 border-black dark:border-stone-700">
        <span className="text-xs font-bold text-stone-700 dark:text-stone-300 uppercase tracking-wide block mb-1">
          Analysis summary
        </span>
        <p className="text-sm text-stone-900 dark:text-stone-200 leading-relaxed font-medium">
          {summary}
        </p>
      </div>
    </div>
  );
};

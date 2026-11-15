import React, { useState } from 'react';
import { Search, RotateCcw, AlertCircle, Info, X } from 'lucide-react';
import { AppContext } from '../types/api';

interface AppRequestInputProps {
  content: string;
  context: AppContext;
  onChangeContent: (val: string) => void;
  onChangeContext: (context: AppContext) => void;
  onAnalyze: () => void;
  onClear: () => void;
  isLoading: boolean;
  validationError?: string | null;
}

const COMMON_PERMISSIONS = [
  { id: 'BIND_ACCESSIBILITY_SERVICE', label: 'Accessibility service', risk: 'critical' },
  { id: 'READ_SMS', label: 'Read SMS / OTPs', risk: 'high' },
  { id: 'RECEIVE_SMS', label: 'Receive SMS', risk: 'high' },
  { id: 'BIND_DEVICE_ADMIN', label: 'Device administrator', risk: 'high' },
  { id: 'BIND_NOTIFICATION_LISTENER_SERVICE', label: 'Notification listener', risk: 'high' },
  { id: 'SYSTEM_ALERT_WINDOW', label: 'Draw over other apps (overlay)', risk: 'medium' },
  { id: 'REQUEST_INSTALL_PACKAGES', label: 'Install unknown apps / sideload', risk: 'high' },
  { id: 'READ_CONTACTS', label: 'Read contacts', risk: 'medium' },
  { id: 'READ_CALL_LOG', label: 'Read call logs', risk: 'medium' },
];

export const AppRequestInput: React.FC<AppRequestInputProps> = ({
  content,
  context,
  onChangeContent,
  onChangeContext,
  onAnalyze,
  onClear,
  isLoading,
  validationError,
}) => {
  const [customPermInput, setCustomPermInput] = useState('');
  const maxChars = 10000;
  const charsUsed = content.length;
  const isOverLimit = charsUsed > maxChars;

  const togglePermission = (permId: string) => {
    const current = context.requested_permissions || [];
    const updated = current.includes(permId)
      ? current.filter((p) => p !== permId)
      : [...current, permId];
    onChangeContext({ ...context, requested_permissions: updated });
  };

  const addCustomPermission = () => {
    const trimmed = customPermInput.trim();
    if (!trimmed) return;
    const current = context.requested_permissions || [];
    if (!current.includes(trimmed)) {
      onChangeContext({ ...context, requested_permissions: [...current, trimmed] });
    }
    setCustomPermInput('');
  };

  const removePermission = (perm: string) => {
    const current = context.requested_permissions || [];
    onChangeContext({
      ...context,
      requested_permissions: current.filter((p) => p !== perm),
    });
  };

  return (
    <div className="space-y-4">
      {/* Functional Scope Notice */}
      <div className="p-3 bg-stone-100 dark:bg-[#1E1E22] border-2 border-black dark:border-stone-700 text-xs text-stone-700 dark:text-stone-300 flex items-start gap-2">
        <Info className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2] flex-shrink-0 mt-0.5" />
        <span>
          Evaluates the supplied installation text and requested permissions for risk indicators. Does not decompile or execute app code.
        </span>
      </div>

      {/* Main text area */}
      <div>
        <label htmlFor="app-content" className="block text-xs font-bold text-stone-700 dark:text-stone-300 uppercase tracking-wide mb-1.5">
          App installation request or description
        </label>
        <textarea
          id="app-content"
          value={content}
          onChange={(e) => onChangeContent(e.target.value)}
          disabled={isLoading}
          rows={4}
          placeholder="Paste message or instructions asking you to install an app, download an APK, or enable special access..."
          className={`w-full p-3.5 bg-white dark:bg-[#121214] border-2 font-sans text-sm text-black dark:text-stone-100 placeholder:text-stone-400 dark:placeholder:text-stone-600 focus:outline-none transition-all resize-y min-h-[110px] ${
            isOverLimit
              ? 'border-red-600 dark:border-red-500 bg-rose-50 dark:bg-rose-950/20 shadow-[2px_2px_0px_#DC2626]'
              : 'border-black dark:border-stone-700 shadow-[2px_2px_0px_#000] focus:shadow-[3px_3px_0px_#000] dark:focus:border-stone-400'
          }`}
        />
        <div className="flex justify-end text-xs font-mono text-stone-600 dark:text-stone-400 mt-1">
          {charsUsed.toLocaleString()} / {maxChars.toLocaleString()} characters
        </div>
      </div>

      {/* Contextual fields */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3.5 bg-stone-50 dark:bg-[#1A1A1E] border-2 border-black dark:border-stone-700">
        <div>
          <label htmlFor="claimed-purpose" className="block text-xs font-semibold text-stone-800 dark:text-stone-200 mb-1">
            Claimed app purpose (optional)
          </label>
          <input
            id="claimed-purpose"
            type="text"
            value={context.claimed_app_purpose || ''}
            onChange={(e) =>
              onChangeContext({ ...context, claimed_app_purpose: e.target.value || null })
            }
            disabled={isLoading}
            placeholder="e.g., Calculator, Battery Saver, PDF Reader"
            className="w-full px-3 py-2 bg-white dark:bg-[#121214] border-2 border-black dark:border-stone-600 text-xs text-black dark:text-stone-200 placeholder:text-stone-400 dark:placeholder:text-stone-600 focus:outline-none focus:border-black dark:focus:border-[#FFE600]"
          />
          <span className="text-[11px] text-stone-500 dark:text-stone-400 mt-0.5 block">
            Used to check for purpose vs privilege anomalies
          </span>
        </div>

        <div>
          <label htmlFor="installation-source" className="block text-xs font-semibold text-stone-800 dark:text-stone-200 mb-1">
            Installation source (optional)
          </label>
          <input
            id="installation-source"
            type="text"
            value={context.installation_source || ''}
            onChange={(e) =>
              onChangeContext({ ...context, installation_source: e.target.value || null })
            }
            disabled={isLoading}
            placeholder="e.g., Direct APK, Telegram channel, Google Play"
            className="w-full px-3 py-2 bg-white dark:bg-[#121214] border-2 border-black dark:border-stone-600 text-xs text-black dark:text-stone-200 placeholder:text-stone-400 dark:placeholder:text-stone-600 focus:outline-none focus:border-black dark:focus:border-[#FFE600]"
          />
          <span className="text-[11px] text-stone-500 dark:text-stone-400 mt-0.5 block">
            Evaluates distribution channel risks (sideloading)
          </span>
        </div>
      </div>

      {/* Permissions Selector */}
      <div className="p-3.5 bg-white dark:bg-[#1A1A1E] border-2 border-black dark:border-stone-700 space-y-3">
        <div className="flex items-center justify-between border-b border-stone-200 dark:border-stone-800 pb-2">
          <span className="text-xs font-bold uppercase tracking-wide text-stone-800 dark:text-stone-200">
            Select requested permissions
          </span>
          <span className="text-xs font-mono font-medium px-2 py-0.5 bg-stone-100 dark:bg-[#25252A] text-stone-700 dark:text-stone-300">
            {context.requested_permissions?.length || 0} selected
          </span>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {COMMON_PERMISSIONS.map((perm) => {
            const isSelected = context.requested_permissions?.includes(perm.id);
            return (
              <button
                key={perm.id}
                type="button"
                disabled={isLoading}
                onClick={() => togglePermission(perm.id)}
                className={`text-xs px-2.5 py-1 font-medium border-2 transition-all flex items-center gap-1.5 ${
                  isSelected
                    ? perm.risk === 'critical'
                      ? 'bg-red-600 text-white border-red-700'
                      : 'bg-[#FFE600] text-black border-black dark:border-[#FFE600] shadow-[1px_1px_0px_#000]'
                    : 'bg-stone-50 dark:bg-[#121214] text-stone-700 dark:text-stone-300 border-stone-300 dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-[#202024]'
                } active:translate-x-[1px] active:translate-y-[1px] active:shadow-none`}
              >
                <span>{perm.label}</span>
                <span className="text-[10px]">{isSelected ? '✓' : '+'}</span>
              </button>
            );
          })}
        </div>

        {/* Custom permission input */}
        <div className="flex items-center gap-2 pt-1">
          <input
            type="text"
            value={customPermInput}
            onChange={(e) => setCustomPermInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                addCustomPermission();
              }
            }}
            disabled={isLoading}
            placeholder="Add custom permission (e.g., android.permission.CAMERA)"
            className="flex-1 px-3 py-1.5 bg-stone-50 dark:bg-[#121214] border-2 border-stone-300 dark:border-stone-700 text-xs text-black dark:text-stone-200 placeholder:text-stone-400 dark:placeholder:text-stone-600 focus:outline-none"
          />
          <button
            type="button"
            onClick={addCustomPermission}
            disabled={isLoading || !customPermInput.trim()}
            className="px-3 py-1.5 bg-stone-200 dark:bg-[#25252A] text-black dark:text-stone-200 border-2 border-black dark:border-stone-600 text-xs font-semibold hover:bg-stone-300 dark:hover:bg-[#303038] disabled:opacity-40"
          >
            Add
          </button>
        </div>

        {/* Custom permissions list */}
        {context.requested_permissions && context.requested_permissions.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {context.requested_permissions
              .filter((p) => !COMMON_PERMISSIONS.some((cp) => cp.id === p))
              .map((p) => (
                <span
                  key={p}
                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-stone-100 dark:bg-[#25252A] border border-black dark:border-stone-600 text-xs font-mono text-black dark:text-stone-200"
                >
                  <span>{p}</span>
                  <button
                    type="button"
                    onClick={() => removePermission(p)}
                    className="hover:text-red-500"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
          </div>
        )}
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
          disabled={isLoading || (!content && !context.claimed_app_purpose && !context.installation_source && (!context.requested_permissions || context.requested_permissions.length === 0))}
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

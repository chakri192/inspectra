import React from 'react';
import { Shield, Moon, Sun } from 'lucide-react';

interface HeaderProps {
  isServiceOnline?: boolean;
  isDark: boolean;
  onToggleTheme: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  isDark,
  onToggleTheme,
}) => {
  return (
    <header className="border-b-2 border-black dark:border-[#27272A] bg-white dark:bg-[#141416] sticky top-0 z-40 transition-colors">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#FFE600] border-2 border-black shadow-[2px_2px_0px_#000]">
            <Shield className="w-5 h-5 text-black stroke-[2.2]" />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-bold tracking-tight text-black dark:text-white">
              Inspectra
            </h1>
            <p className="text-xs text-stone-600 dark:text-stone-400">
              Suspicious Content Analyzer
            </p>
          </div>
        </div>

        {/* Theme toggle control */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
            className="flex items-center gap-2 px-3 py-1.5 bg-white dark:bg-[#1E1E22] text-black dark:text-stone-200 border-2 border-black dark:border-stone-500 text-xs font-semibold shadow-[2px_2px_0px_#000] hover:bg-stone-100 dark:hover:bg-[#28282E] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all"
          >
            {isDark ? (
              <>
                <Sun className="w-3.5 h-3.5 text-[#FFE600] stroke-[2.2]" />
                <span>Light</span>
              </>
            ) : (
              <>
                <Moon className="w-3.5 h-3.5 text-stone-700 stroke-[2.2]" />
                <span>Dark</span>
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};

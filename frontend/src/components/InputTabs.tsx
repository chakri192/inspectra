import React from 'react';
import { MessageSquareText, Link2, Smartphone, QrCode } from 'lucide-react';
import { InputType } from '../types/api';

interface InputTabsProps {
  activeTab: InputType;
  onTabChange: (tab: InputType) => void;
  disabled?: boolean;
}

export const InputTabs: React.FC<InputTabsProps> = ({ activeTab, onTabChange, disabled = false }) => {
  const tabs = [
    {
      id: 'message' as InputType,
      label: 'Message',
      icon: MessageSquareText,
    },
    {
      id: 'url' as InputType,
      label: 'URL',
      icon: Link2,
    },
    {
      id: 'app_request' as InputType,
      label: 'App request',
      icon: Smartphone,
    },
    {
      id: 'qr_code' as InputType,
      label: 'QR code',
      icon: QrCode,
    },
  ];

  return (
    <div className="w-full mb-5">
      <div className="flex flex-wrap gap-2 border-b-2 border-black dark:border-[#27272A] pb-3" role="tablist" aria-label="Analysis input type">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              disabled={disabled}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 text-xs sm:text-sm font-semibold border-2 transition-all ${
                isActive
                  ? 'bg-[#FFE600] text-black border-black dark:border-[#FFE600] shadow-[2px_2px_0px_#000]'
                  : 'bg-white dark:bg-[#1A1A1E] text-stone-700 dark:text-stone-300 border-black dark:border-stone-700 hover:bg-stone-100 dark:hover:bg-[#25252A]'
              } ${disabled ? 'opacity-40 cursor-not-allowed' : 'active:translate-x-[1px] active:translate-y-[1px] active:shadow-none'}`}
            >
              <Icon className="w-4 h-4 stroke-[2.2]" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

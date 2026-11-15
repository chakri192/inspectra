import React from 'react';
import { InputType, AppContext } from '../types/api';

export interface SamplePreset {
  id: string;
  name: string;
  type: InputType;
  expectedVerdict: 'Safe' | 'Suspicious';
  content: string;
  context?: AppContext;
}

const SAMPLE_PRESETS: SamplePreset[] = [
  {
    id: 'phishing_urgent_otp',
    name: 'Urgent phishing SMS',
    type: 'message',
    expectedVerdict: 'Suspicious',
    content: 'URGENT: Your bank account will be suspended within 24 hours due to suspicious login attempts. Send your OTP immediately to cancel this action and verify your identity.',
  },
  {
    id: 'unofficial_sender_mobile_alert',
    name: 'Personal mobile bank SMS',
    type: 'message',
    expectedVerdict: 'Suspicious',
    content: '+91 9876543210: Dear customer, your bank account has been blocked due to suspicious activity. Send your OTP immediately to restore service.',
  },
  {
    id: 'customs_parcel_contraband_scam',
    name: 'FedEx customs seizure',
    type: 'message',
    expectedVerdict: 'Suspicious',
    content: 'Your FedEx courier parcel containing illegal contraband narcotics has been seized by customs clearance authorities at Mumbai airport. Call our customs verification cell immediately.',
  },
  {
    id: 'electricity_disconnection_threat',
    name: 'Power disconnection threat',
    type: 'message',
    expectedVerdict: 'Suspicious',
    content: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid electricity bill. Please call our power officer immediately at 9876543210 to avoid disconnection.',
  },
  {
    id: 'digital_arrest_scam',
    name: 'Digital-arrest extortion',
    type: 'message',
    expectedVerdict: 'Suspicious',
    content: 'This is Inspector Sharma from Central Bureau of Investigation CBI Cyber Crime Cell. A non-bailable arrest warrant has been registered against you for an illegal customs parcel. You are placed under digital arrest. Transfer the verification bail deposit immediately via bank transfer to the government escrow account. Keep this strictly confidential under Official Secrecy Act and do not disconnect this video call.',
  },
  {
    id: 'benign_work_message',
    name: 'Benign work message',
    type: 'message',
    expectedVerdict: 'Safe',
    content: 'Hi Alex, hope you are having a productive week! Just a reminder that our quarterly product review is scheduled for tomorrow at 2:00 PM in Conference Room 3. Please review the updated slides beforehand.',
  },
  {
    id: 'educational_negation_tip',
    name: 'Defensive security tip',
    type: 'message',
    expectedVerdict: 'Safe',
    content: 'Cybersecurity Awareness Tip: Never share your OTP, banking password, or debit card PIN with anyone. Official bank staff will never ask you to disclose verification codes.',
  },
  {
    id: 'deceptive_subdomain_url',
    name: 'Deceptive brand subdomain',
    type: 'url',
    expectedVerdict: 'Suspicious',
    content: 'https://paypal.com.account-verification-portal.xyz/secure/login',
  },
  {
    id: 'legitimate_long_url',
    name: 'Legitimate documentation URL',
    type: 'url',
    expectedVerdict: 'Safe',
    content: 'https://docs.python.org/3/library/urllib.parse.html?highlight=urlsplit#module-urllib.parse-deep-anchor-reference-documentation',
  },
  {
    id: 'banking_trojan_app',
    name: 'Banking trojan permissions',
    type: 'app_request',
    expectedVerdict: 'Suspicious',
    content: 'Please install this System Optimizer update from our direct link to enhance device battery and performance.',
    context: {
      claimed_app_purpose: 'Battery Optimizer',
      installation_source: 'Telegram Channel APK Download',
      requested_permissions: [
        'BIND_ACCESSIBILITY_SERVICE',
        'READ_SMS',
        'RECEIVE_SMS',
        'SYSTEM_ALERT_WINDOW',
      ],
    },
  },
  {
    id: 'calculator_mismatch_app',
    name: 'Calculator purpose mismatch',
    type: 'app_request',
    expectedVerdict: 'Suspicious',
    content: 'A simple scientific calculator app requesting system administration and SMS rights.',
    context: {
      claimed_app_purpose: 'Calculator',
      installation_source: 'Direct APK',
      requested_permissions: ['READ_SMS', 'BIND_DEVICE_ADMIN'],
    },
  },
];

interface SampleSelectorProps {
  currentTab: InputType;
  onSelectSample: (sample: SamplePreset) => void;
  disabled?: boolean;
}

export const SampleSelector: React.FC<SampleSelectorProps> = ({
  currentTab,
  onSelectSample,
  disabled = false,
}) => {
  const matchingSamples = SAMPLE_PRESETS.filter((s) => s.type === currentTab);

  if (matchingSamples.length === 0) {
    return null;
  }

  return (
    <div className="mb-5 flex flex-wrap items-center gap-2">
      <span className="text-xs font-semibold text-stone-600 dark:text-stone-400">
        Load sample:
      </span>
      <div className="flex flex-wrap gap-1.5">
        {matchingSamples.map((sample) => {
          const isSuspicious = sample.expectedVerdict === 'Suspicious';

          return (
            <button
              key={sample.id}
              type="button"
              disabled={disabled}
              onClick={() => onSelectSample(sample)}
              className={`text-xs px-2.5 py-1 font-medium border-2 border-black dark:border-stone-700 bg-white dark:bg-[#1A1A1E] text-black dark:text-stone-200 hover:bg-stone-100 dark:hover:bg-[#25252A] shadow-[1px_1px_0px_#000] flex items-center gap-1.5 transition-all ${
                disabled
                  ? 'opacity-40 cursor-not-allowed'
                  : 'active:translate-x-[1px] active:translate-y-[1px] active:shadow-none'
              }`}
            >
              <span>{sample.name}</span>
              <span
                className={`text-[10px] font-semibold px-1 py-0.2 border ${
                  isSuspicious
                    ? 'bg-rose-100 text-rose-800 dark:bg-rose-950/70 dark:text-rose-300 border-rose-400 dark:border-rose-800'
                    : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-400 dark:border-emerald-800'
                }`}
              >
                {sample.expectedVerdict}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

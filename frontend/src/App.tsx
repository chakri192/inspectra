import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { InputTabs } from './components/InputTabs';
import { SampleSelector, SamplePreset } from './components/SampleSelector';
import { MessageInput } from './components/MessageInput';
import { UrlInput } from './components/UrlInput';
import { AppRequestInput } from './components/AppRequestInput';
import { QrCodeInput } from './components/QrCodeInput';
import { VerdictCard } from './components/VerdictCard';
import { IndicatorsList } from './components/IndicatorsList';
import { UrlBreakdown } from './components/UrlBreakdown';
import { ChecksSummary } from './components/ChecksSummary';
import { LimitationsNotice } from './components/LimitationsNotice';
import { TechnicalDetails } from './components/TechnicalDetails';
import { SessionHistory, SessionHistoryItem } from './components/SessionHistory';
import { InputType, AppContext, AnalyzeResponse } from './types/api';
import { analyzeContent, checkHealth, ApiError } from './services/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<InputType>('message');
  const [messageContent, setMessageContent] = useState('');
  const [urlContent, setUrlContent] = useState('');
  const [appContent, setAppContent] = useState('');
  const [appContext, setAppContext] = useState<AppContext>({
    claimed_app_purpose: null,
    installation_source: null,
    requested_permissions: [],
  });

  const [isLoading, setIsLoading] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [isBackendHealthy, setIsBackendHealthy] = useState(true);

  // In-memory tab session history (max 5 items, zero persistence)
  const [sessionHistory, setSessionHistory] = useState<SessionHistoryItem[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);

  // Dark mode state: default to dark
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem('inspectra_theme') || localStorage.getItem('cybershield_theme');
    if (saved) return saved === 'dark';
    return true;
  });

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('inspectra_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('inspectra_theme', 'light');
    }
  }, [isDark]);

  const toggleTheme = () => setIsDark((prev) => !prev);

  // Periodic health check
  useEffect(() => {
    let isMounted = true;
    const verifyHealth = async () => {
      try {
        const health = await checkHealth();
        if (isMounted) setIsBackendHealthy(health.status === 'healthy');
      } catch {
        if (isMounted) setIsBackendHealthy(false);
      }
    };

    verifyHealth();
    const interval = setInterval(verifyHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleTabChange = (tab: InputType) => {
    setActiveTab(tab);
    setValidationError(null);
    setApiError(null);
  };

  const handleSelectSample = (sample: SamplePreset) => {
    setActiveTab(sample.type);
    setValidationError(null);
    setApiError(null);
    setResult(null);
    setSelectedHistoryId(null);

    if (sample.type === 'message') {
      setMessageContent(sample.content);
    } else if (sample.type === 'url') {
      setUrlContent(sample.content);
    } else if (sample.type === 'app_request') {
      setAppContent(sample.content);
      if (sample.context) {
        setAppContext(sample.context);
      }
    }
  };

  const handleClearCurrent = () => {
    setValidationError(null);
    setApiError(null);
    setResult(null);
    setSelectedHistoryId(null);

    if (activeTab === 'message') {
      setMessageContent('');
    } else if (activeTab === 'url') {
      setUrlContent('');
    } else if (activeTab === 'app_request') {
      setAppContent('');
      setAppContext({
        claimed_app_purpose: null,
        installation_source: null,
        requested_permissions: [],
      });
    }
  };

  const getCurrentContent = () => {
    if (activeTab === 'message') return messageContent;
    if (activeTab === 'url') return urlContent;
    return appContent;
  };

  const handleAnalyze = async () => {
    const rawContent = getCurrentContent();
    const trimmed = rawContent.trim();

    if (!trimmed) {
      setValidationError('Please enter or paste content to analyze.');
      return;
    }

    if (trimmed.length > 10000) {
      setValidationError('Input exceeds the maximum length of 10,000 characters.');
      return;
    }

    setValidationError(null);
    setApiError(null);
    setIsLoading(true);

    try {
      const response = await analyzeContent({
        input_type: activeTab,
        content: rawContent,
        context: activeTab === 'app_request' ? appContext : undefined,
      });
      setResult(response);
      setIsBackendHealthy(true);

      const snippet = trimmed.length > 36 ? trimmed.slice(0, 36) + '…' : trimmed;
      const historyId = String(Date.now());
      setSelectedHistoryId(historyId);
      setSessionHistory((prev) => [
        {
          id: historyId,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          inputType: activeTab,
          snippet,
          result: response,
          rawInput: {
            message: activeTab === 'message' ? rawContent : undefined,
            url: activeTab === 'url' ? rawContent : undefined,
            appContent: activeTab === 'app_request' ? rawContent : undefined,
            appContext: activeTab === 'app_request' ? appContext : undefined,
          },
        },
        ...prev,
      ].slice(0, 5));
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setApiError(err.message);
      } else {
        setApiError('Unable to connect to the analysis service. Please check your connection and try again.');
      }
      setIsBackendHealthy(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyzeDecodedUrl = async (decodedContent: string) => {
    const trimmed = decodedContent.trim();
    if (!trimmed) return;

    setValidationError(null);
    setApiError(null);
    setIsLoading(true);

    const isUrl = trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.includes('://') || trimmed.includes('.');
    const targetType: InputType = isUrl ? 'url' : 'message';

    try {
      const response = await analyzeContent({
        input_type: targetType,
        content: trimmed,
      });
      setResult(response);
      setIsBackendHealthy(true);

      const snippet = trimmed.length > 36 ? trimmed.slice(0, 36) + '…' : trimmed;
      const historyId = String(Date.now());
      setSelectedHistoryId(historyId);
      setSessionHistory((prev) => [
        {
          id: historyId,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          inputType: targetType,
          snippet,
          result: response,
          rawInput: {
            message: targetType === 'message' ? trimmed : undefined,
            url: targetType === 'url' ? trimmed : undefined,
          },
        },
        ...prev,
      ].slice(0, 5));
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setApiError(err.message);
      } else {
        setApiError('Unable to complete analysis of decoded QR payload.');
      }
      setIsBackendHealthy(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectHistoryItem = (item: SessionHistoryItem) => {
    setSelectedHistoryId(item.id);
    setActiveTab(item.inputType);
    setResult(item.result);
    setValidationError(null);
    setApiError(null);

    if (item.rawInput.message !== undefined) setMessageContent(item.rawInput.message);
    if (item.rawInput.url !== undefined) setUrlContent(item.rawInput.url);
    if (item.rawInput.appContent !== undefined) setAppContent(item.rawInput.appContent);
    if (item.rawInput.appContext) setAppContext(item.rawInput.appContext);
  };

  const handleClearHistory = () => {
    setSessionHistory([]);
    setSelectedHistoryId(null);
  };

  const handleResetAnalysis = () => {
    setResult(null);
    setSelectedHistoryId(null);
    setValidationError(null);
    setApiError(null);
  };

  return (
    <div className="min-h-screen bg-[#F4F0E8] dark:bg-[#0C0C0E] text-[#0C0C0C] dark:text-[#F3F4F6] flex flex-col font-sans transition-colors">
      <Header
        isServiceOnline={isBackendHealthy}
        isDark={isDark}
        onToggleTheme={toggleTheme}
      />

      <main className="flex-1 max-w-4xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8 space-y-6">
        {/* Tab Session History (when items exist) */}
        {sessionHistory.length > 0 && (
          <SessionHistory
            items={sessionHistory}
            selectedId={selectedHistoryId}
            onSelect={handleSelectHistoryItem}
            onClear={handleClearHistory}
          />
        )}

        {/* Main Input Form Card */}
        {!result && (
          <div className="p-5 sm:p-7 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[4px_4px_0px_#000] transition-colors">
            {/* Context Header */}
            <div className="mb-5 pb-4 border-b-2 border-black dark:border-[#27272A]">
              <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-black dark:text-white">
                Check suspicious content
              </h2>
              <p className="text-xs sm:text-sm text-stone-600 dark:text-stone-400 mt-1">
                Submit suspicious messages, URLs, or mobile app requests to evaluate potential security risks and threat indicators.
              </p>
            </div>

            {/* Input Mode Tabs */}
            <InputTabs
              activeTab={activeTab}
              onTabChange={handleTabChange}
              disabled={isLoading}
            />

            {/* Sample presets */}
            <SampleSelector
              currentTab={activeTab}
              onSelectSample={handleSelectSample}
              disabled={isLoading}
            />

            {/* Mode-specific input fields */}
            {activeTab === 'message' && (
              <MessageInput
                content={messageContent}
                onChange={setMessageContent}
                onAnalyze={handleAnalyze}
                onClear={handleClearCurrent}
                isLoading={isLoading}
                validationError={validationError}
              />
            )}

            {activeTab === 'url' && (
              <UrlInput
                content={urlContent}
                onChange={setUrlContent}
                onAnalyze={handleAnalyze}
                onClear={handleClearCurrent}
                isLoading={isLoading}
                validationError={validationError}
              />
            )}

            {activeTab === 'app_request' && (
              <AppRequestInput
                content={appContent}
                context={appContext}
                onChangeContent={setAppContent}
                onChangeContext={setAppContext}
                onAnalyze={handleAnalyze}
                onClear={handleClearCurrent}
                isLoading={isLoading}
                validationError={validationError}
              />
            )}

            {activeTab === 'qr_code' && (
              <QrCodeInput
                onAnalyzeDecodedUrl={handleAnalyzeDecodedUrl}
                isLoading={isLoading}
              />
            )}

            {/* Clean API Error Banner */}
            {apiError && (
              <div className="mt-4 p-3.5 bg-red-50 dark:bg-rose-950/40 text-red-700 dark:text-rose-300 border-2 border-red-600 dark:border-rose-800 text-xs font-medium">
                {apiError}
              </div>
            )}
          </div>
        )}

        {/* Results Interface */}
        {result && (
          <div className="space-y-5">
            {/* 1. Verdict, 2. Risk Score, 3. Category, 4. Summary */}
            <VerdictCard
              verdict={result.verdict}
              riskScore={result.risk_score}
              category={result.category}
              summary={result.summary}
              findings={result.findings}
              urls={result.urls}
              onReset={handleResetAnalysis}
            />

            {/* 5. Detected Indicators & 6. Highlighted Evidence */}
            <IndicatorsList findings={result.findings} />

            {/* URL Structural Breakdown if URLs were detected/submitted */}
            {result.urls && result.urls.length > 0 && (
              <UrlBreakdown urls={result.urls} />
            )}

            {/* 7. Completed, Unavailable, and Skipped Checks */}
            <ChecksSummary checks={result.checks} />

            {/* Technical rule diagnostics (Collapsible) */}
            <TechnicalDetails
              findings={result.findings}
              engineVersion={result.engine_version}
              category={result.category}
              riskScore={result.risk_score}
            />

            {/* 8. Mandatory Assessment Limitation */}
            <LimitationsNotice limitations={result.limitations} />
          </div>
        )}
      </main>

      <footer className="border-t-2 border-black dark:border-[#27272A] bg-white dark:bg-[#141416] py-4 text-center text-xs text-stone-600 dark:text-stone-400 transition-colors">
        <p>Inspectra — Content security analysis tool. Evaluates submitted text against explainable heuristic rules.</p>
      </footer>
    </div>
  );
};

export default App;

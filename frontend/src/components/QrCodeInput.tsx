import React, { useState, useEffect, useRef } from 'react';
import { Upload, AlertCircle, CheckCircle, Search, RotateCcw, Shield } from 'lucide-react';
import jsQR from 'jsqr';
import QRCode from 'qrcode';

interface QrCodeInputProps {
  onAnalyzeDecodedUrl: (url: string) => void;
  isLoading: boolean;
}

interface TestQrPreset {
  id: string;
  name: string;
  url: string;
  threatType: 'Phishing' | 'Malware' | 'Safe';
}

const TEST_QR_PRESETS: TestQrPreset[] = [
  {
    id: 'chase_subdomain_qr',
    name: 'Banking lure QR',
    url: 'https://chase.com.security-verification-portal.xyz/login',
    threatType: 'Phishing',
  },
  {
    id: 'malware_apk_qr',
    name: 'Direct APK QR',
    url: 'https://system-update.org/android-patch.apk',
    threatType: 'Malware',
  },
  {
    id: 'homoglyph_qr',
    name: 'Homoglyph domain QR',
    url: 'https://p\u0430ypal.com/signin',
    threatType: 'Phishing',
  },
  {
    id: 'safe_wiki_qr',
    name: 'Wikipedia link QR',
    url: 'https://en.wikipedia.org/wiki/QR_code',
    threatType: 'Safe',
  },
];

export const QrCodeInput: React.FC<QrCodeInputProps> = ({
  onAnalyzeDecodedUrl,
  isLoading,
}) => {
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [decodedData, setDecodedData] = useState<string | null>(null);
  const [decodingError, setDecodingError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Global clipboard paste listener
  useEffect(() => {
    const handlePaste = (e: ClipboardEvent) => {
      const items = e.clipboardData?.items;
      if (!items) return;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type.startsWith('image/')) {
          const file = items[i].getAsFile();
          if (file) {
            processImageFile(file);
            break;
          }
        }
      }
    };

    window.addEventListener('paste', handlePaste);
    return () => window.removeEventListener('paste', handlePaste);
  }, []);

  const decodeQrFromImage = (imageElement: HTMLImageElement) => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) {
      setDecodingError('Unable to initialize canvas decoder.');
      return;
    }

    canvas.width = imageElement.naturalWidth || imageElement.width;
    canvas.height = imageElement.naturalHeight || imageElement.height;
    ctx.drawImage(imageElement, 0, 0, canvas.width, canvas.height);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);

    if (code && code.data) {
      setDecodedData(code.data.trim());
      setDecodingError(null);
    } else {
      setDecodedData(null);
      setDecodingError('No valid QR code was detected in the submitted image.');
    }
  };

  const processImageFile = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setDecodingError('Please select a valid image file (PNG, JPG, WebP).');
      return;
    }

    setDecodingError(null);
    setDecodedData(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target?.result as string;
      setImagePreview(dataUrl);

      const img = new Image();
      img.onload = () => decodeQrFromImage(img);
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processImageFile(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processImageFile(file);
  };

  const handleGenerateTestQr = async (preset: TestQrPreset) => {
    try {
      setDecodingError(null);
      const qrDataUrl = await QRCode.toDataURL(preset.url, {
        width: 300,
        margin: 2,
        color: { dark: '#000000', light: '#FFFFFF' },
      });

      setImagePreview(qrDataUrl);
      const img = new Image();
      img.onload = () => decodeQrFromImage(img);
      img.src = qrDataUrl;
    } catch {
      setDecodingError('Failed to generate test QR code.');
    }
  };

  const handleReset = () => {
    setImagePreview(null);
    setDecodedData(null);
    setDecodingError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="space-y-4">
      {/* Functional Scope Notice */}
      <div className="p-3 bg-stone-100 dark:bg-[#1E1E22] border-2 border-black dark:border-stone-700 text-xs text-stone-700 dark:text-stone-300 flex items-center gap-2">
        <Shield className="w-4 h-4 text-stone-700 dark:text-stone-300 stroke-[2] flex-shrink-0" />
        <span>
          QR codes are decoded in browser memory. Extracted links are analyzed structurally and are never visited.
        </span>
      </div>

      {/* Test presets */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-stone-600 dark:text-stone-400">
          Load sample QR:
        </span>
        <div className="flex flex-wrap gap-1.5">
          {TEST_QR_PRESETS.map((preset) => {
            const isSuspicious = preset.threatType !== 'Safe';
            return (
              <button
                key={preset.id}
                type="button"
                disabled={isLoading}
                onClick={() => handleGenerateTestQr(preset)}
                className="text-xs px-2.5 py-1 font-medium border-2 border-black dark:border-stone-700 bg-white dark:bg-[#1A1A1E] text-black dark:text-stone-200 hover:bg-stone-100 dark:hover:bg-[#25252A] shadow-[1px_1px_0px_#000] flex items-center gap-1.5 transition-all active:translate-x-[1px] active:translate-y-[1px] active:shadow-none"
              >
                <span>{preset.name}</span>
                <span
                  className={`text-[10px] font-semibold px-1 py-0.2 border ${
                    isSuspicious
                      ? 'bg-rose-100 text-rose-800 dark:bg-rose-950/70 dark:text-rose-300 border-rose-400 dark:border-rose-800'
                      : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-400 dark:border-emerald-800'
                  }`}
                >
                  {preset.threatType}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Drag & Drop Upload Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`p-6 border-2 border-dashed cursor-pointer transition-all text-center flex flex-col items-center justify-center gap-2.5 ${
          isDragging
            ? 'border-black dark:border-[#FFE600] bg-yellow-50 dark:bg-yellow-950/20'
            : 'border-black dark:border-stone-700 bg-stone-50 dark:bg-[#161619] hover:bg-stone-100 dark:hover:bg-[#1E1E22]'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="p-2.5 bg-[#FFE600] text-black border-2 border-black shadow-[2px_2px_0px_#000]">
          <Upload className="w-5 h-5 stroke-[2.2]" />
        </div>

        <div className="space-y-0.5">
          <p className="text-xs sm:text-sm font-bold text-black dark:text-stone-100">
            Click to upload an image or drag and drop
          </p>
          <p className="text-xs text-stone-600 dark:text-stone-400">
            Supports PNG, JPG, WebP • Or paste screenshot with <kbd className="px-1.5 py-0.5 bg-stone-100 dark:bg-[#25252A] border border-stone-300 dark:border-stone-700 font-mono text-[11px] text-stone-800 dark:text-stone-300">Ctrl+V</kbd>
          </p>
        </div>
      </div>

      {/* Decoding Error Alert */}
      {decodingError && (
        <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 border-2 border-red-600 dark:border-red-500 text-xs font-medium">
          <AlertCircle className="w-4 h-4 flex-shrink-0 stroke-[2.2]" />
          <span>{decodingError}</span>
        </div>
      )}

      {/* Decoded QR Code Result Box */}
      {decodedData && (
        <div className="p-4 bg-white dark:bg-[#161619] border-2 border-black dark:border-stone-700 shadow-[2px_2px_0px_#000] space-y-3">
          <div className="flex items-center justify-between border-b border-stone-200 dark:border-stone-800 pb-2">
            <div className="flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-emerald-600 dark:text-emerald-400 stroke-[2.2]" />
              <h4 className="text-xs font-bold text-black dark:text-stone-200 uppercase tracking-wide">
                Decoded QR code content
              </h4>
            </div>
            <button
              type="button"
              onClick={handleReset}
              className="text-xs text-stone-600 dark:text-stone-400 hover:text-black dark:hover:text-white flex items-center gap-1"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>

          <div className="flex flex-col sm:flex-row items-start gap-3">
            {imagePreview && (
              <div className="w-20 h-20 p-1 bg-white border-2 border-black flex-shrink-0 shadow-[1px_1px_0px_#000]">
                <img
                  src={imagePreview}
                  alt="Decoded QR preview"
                  className="w-full h-full object-contain"
                />
              </div>
            )}

            <div className="flex-1 min-w-0 space-y-2">
              <div className="p-2.5 bg-stone-50 dark:bg-[#101012] border border-stone-300 dark:border-stone-700 font-mono text-xs text-black dark:text-stone-200 break-all select-all">
                {decodedData}
              </div>
              <p className="text-[11px] text-stone-500 dark:text-stone-400">
                Extracted content is displayed as non-clickable plain text.
              </p>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="button"
              onClick={() => onAnalyzeDecodedUrl(decodedData)}
              disabled={isLoading}
              className="flex items-center gap-2 px-5 py-2 bg-[#FFE600] hover:bg-[#FADC00] text-black border-2 border-black dark:border-[#FFE600] text-xs sm:text-sm font-bold shadow-[2px_2px_0px_#000] transition-all active:translate-x-[1px] active:translate-y-[1px] active:shadow-none disabled:opacity-40"
            >
              <Search className="w-4 h-4 stroke-[2.5]" />
              <span>Analyze decoded content</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

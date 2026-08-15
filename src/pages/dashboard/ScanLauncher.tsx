import React, { useState } from 'react';
import { Play, Coins, Globe, RefreshCw, ArrowRight, AlertTriangle } from 'lucide-react';

type Pack = 'single' | 'pack5' | 'pack20';

interface ScanLauncherProps {
  credits: number;
  isPerformingAction: boolean;
  onInitiateScan: (url: string, authHeader?: string) => void;
  onPurchaseCredits: (packName: Pack) => void;
}

export default function ScanLauncher({ credits, isPerformingAction, onInitiateScan, onPurchaseCredits }: ScanLauncherProps) {
  const [scanUrl, setScanUrl] = useState('');
  const [authHeader, setAuthHeader] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [errorText, setErrorText] = useState('');
  const [buyPack, setBuyPack] = useState<Pack>('pack5');
  const [isBuying, setIsBuying] = useState(false);

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorText('');
    const urlStr = scanUrl.trim();
    if (!urlStr) return;

    if (credits < 1) {
      setErrorText('Insufficient balances available. Please top-up credits to run a scan.');
      return;
    }

    onInitiateScan(urlStr, authHeader.trim() || undefined);
    setScanUrl('');
    setAuthHeader('');
  };

  const handleBuyCredits = async () => {
    setIsBuying(true);
    // Mimic the full stripe checkout redirect loop
    setTimeout(() => {
      onPurchaseCredits(buyPack);
      setIsBuying(false);
    }, 1200);
  };

  return (
    <div className="lg:col-span-7 space-y-8">

      {/* Quick Scan Launcher */}
      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
        <div className="flex items-center space-x-2.5 mb-4">
          <div className="p-1.5 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e]">
            <Play className="w-4 h-4" />
          </div>
          <h2 className="text-sm font-bold font-mono text-white">Trigger Penetration Test</h2>
        </div>
        <p className="text-[#a1a1aa] text-xs font-mono mb-6">
          Enter any public staging, production or application URL. Seclayer runs modern black-box scans checking HTTP headers security, Technology signatures leakage, directories exposures, SSL certificates validity, and cookie flags.
        </p>

        <form onSubmit={handleScanSubmit} className="space-y-4">
          <div>
            <label className="text-[11px] font-mono uppercase tracking-wider text-[#52525b] ml-1 block mb-2">Target URL</label>
            <div className="flex bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors">
              <div className="flex items-center text-[#52525b] pl-3 pr-1.5 font-mono text-xs">
                <Globe className="w-4 h-4 text-[#52525b] mr-1.5" />
                <span>https://</span>
              </div>
              <input
                type="text"
                className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
                placeholder="test-shop-staging.mydomain.io"
                value={scanUrl}
                onChange={(e) => setScanUrl(e.target.value)}
                disabled={isPerformingAction}
                id="target-url-input"
              />
            </div>
          </div>

          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="text-[11px] font-mono text-[#52525b] hover:text-white uppercase tracking-wider flex items-center space-x-1 transition-colors"
            >
              <span>{showAdvanced ? '- Hide Advanced Options' : '+ Show Advanced Options (Authenticated Scans)'}</span>
            </button>

            {showAdvanced && (
              <div className="mt-3 p-3 bg-black/40 border border-[#27272a] rounded space-y-3">
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1">Authentication (optional)</label>
                  <p className="text-[10px] font-mono text-[#a1a1aa] mb-2">Applied to every request — root, crawl, probes and templates. Use a Bearer/Basic token, or an explicit header like <span className="text-[#22c55e]">Cookie: session=…</span> or <span className="text-[#22c55e]">X-API-Key: …</span>.</p>
                  <input
                    type="text"
                    className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors"
                    placeholder="Bearer eyJhbGci…   |   Cookie: session=…   |   X-API-Key: …"
                    value={authHeader}
                    onChange={(e) => setAuthHeader(e.target.value)}
                    disabled={isPerformingAction}
                    id="auth-header-input"
                  />
                </div>
              </div>
            )}
          </div>

          {errorText && (
            <div className="bg-[#f87171]/10 border border-[#f87171]/20 text-[#f87171] text-xs p-3 rounded flex items-center space-x-2 font-mono">
              <AlertTriangle className="w-4 h-4 text-[#f87171] shrink-0" />
              <span>{errorText}</span>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <span className="text-[10px] font-mono text-[#52525b]">
              Cost per scan: <strong className="text-[#22c55e]">1 credit</strong>
            </span>
            <button
              type="submit"
              disabled={isPerformingAction || !scanUrl.trim()}
              className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center space-x-2 shrink-0 cursor-pointer"
              id="trigger-scan-btn"
            >
              <span>Execute audit</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </form>
      </div>

      {/* Price Pack Booster (Stripe sandbox — intentionally mock) */}
      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
        <div className="flex items-center space-x-2.5 mb-4">
          <div className="p-1.5 bg-black border border-[#27272a] rounded text-[#22c55e]">
            <Coins className="w-4 h-4" />
          </div>
          <h2 className="text-sm font-bold font-mono text-white">Purchase Credits (Stripe Sandbox)</h2>
        </div>
        <p className="text-[#a1a1aa] text-xs font-mono mb-6">
          Need more scan capacity? To top up scan credits, choose a credit volume package below. We've set up a preconfigured Stripe test integration that performs instant top-ups dynamically.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
          {[
            { id: 'single', name: '1 Scan Credit', price: '$29', label: '$29/Scan' },
            { id: 'pack5', name: '5-Scan Pack', price: '$99', label: 'Save 30%' },
            { id: 'pack20', name: '20-Scan Pack', price: '$299', label: 'Save 50%' }
          ].map((pack) => (
            <div
              key={pack.id}
              onClick={() => setBuyPack(pack.id as any)}
              className={`p-4 rounded border text-center cursor-pointer transition-all ${
                buyPack === pack.id
                  ? 'border-[#22c55e] bg-[#22c55e]/5'
                  : 'border-[#27272a] hover:border-[#3f3f46] bg-black'
              }`}
            >
              <span className="text-[10px] font-mono text-[#52525b] block uppercase mb-1">{pack.name}</span>
              <strong className="text-lg font-mono text-white block">{pack.price}</strong>
              <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded inline-block mt-1 ${
                buyPack === pack.id ? 'bg-[#22c55e]/20 text-[#22c55e]' : 'bg-[#18181b] text-[#52525b]'
              }`}>{pack.label}</span>
            </div>
          ))}
        </div>

        <button
          onClick={handleBuyCredits}
          disabled={isBuying || isPerformingAction}
          className="w-full py-3 bg-[#18181b] hover:bg-[#27272a] border border-[#27272a] text-white hover:text-[#22c55e] text-xs font-mono font-bold uppercase tracking-widest rounded transition-all flex items-center justify-center space-x-2 cursor-pointer"
          id="buy-credits-btn"
        >
          {isBuying ? (
            <>
              <RefreshCw className="w-4 h-4 text-[#22c55e] animate-spin" />
              <span>Redirecting to stripe checkout...</span>
            </>
          ) : (
            <>
              <span>Acquire {buyPack === 'single' ? '1 scan credit' : buyPack === 'pack5' ? '5 credits pack' : '20 credits pack'}</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </div>

    </div>
  );
}

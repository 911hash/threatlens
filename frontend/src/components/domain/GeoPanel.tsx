import React from 'react';
import {
  MapPin,
  Server,
  Radio,
  ExternalLink,
  ShieldAlert,
  HelpCircle,
  Database,
} from 'lucide-react';
import type { GeoLocation } from '../../types/threat';
import { Badge } from '../primitives/Badge';
import { IndicatorChip } from './IndicatorChip';
import { CopyButton } from '../primitives/CopyButton';
import { useDefang } from '../../design/DefangContext';

export interface GeoPanelProps {
  geolocation?: GeoLocation | null;
  ip: string;
  hopIndex?: number;
  onPivot?: (geo: any, ip?: string) => void;
  className?: string;
}

export function getFlagEmoji(countryCode?: string): string {
  if (!countryCode || countryCode.length !== 2 || countryCode === 'LOCAL') return '🌐';
  try {
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  } catch {
    return '🌐';
  }
}

export const getCountryFlag = getFlagEmoji;

export const GeoPanel: React.FC<GeoPanelProps> = ({
  geolocation,
  ip,
  hopIndex,
  onPivot,
  className = '',
}) => {
  const { copyIndicator } = useDefang();

  const isUnknown = !geolocation || geolocation.is_unknown;
  const flag = getFlagEmoji(geolocation?.country_code);

  const handleCopyIp = (e: React.MouseEvent) => {
    const isLive = e.altKey || e.metaKey;
    copyIndicator(ip, { live: isLive });
  };

  const handlePivot = () => {
    if (onPivot) {
      const targetGeo = geolocation || {
        ip,
        is_unknown: true,
        country: 'unknown',
        region: 'unknown',
        city: 'unknown',
        is_vpn: false,
        is_proxy: false,
        is_tor: false,
        is_datacenter: false,
        cached: false,
      };
      onPivot(targetGeo, ip);
    }
  };

  return (
    <div
      className={`p-4 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-panel)] transition-all hover:border-[var(--border-strong)] space-y-3 ${className}`}
    >
      {/* Header Row: Hop indicator, IP chip, risk badges, pivot trigger */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
        <div className="flex items-center gap-2 flex-wrap">
          {hopIndex !== undefined && (
            <Badge variant="neutral" size="xs" className="font-mono">
              {hopIndex === 0 ? 'Hop 0 (Origin)' : `Hop ${hopIndex}`}
            </Badge>
          )}

          {/* Defanged IP indicator using IndicatorChip primitive */}
          <IndicatorChip indicator={ip} type="ip" size="xs" showCopy={true} />

          {/* Risk Badges */}
          {geolocation?.is_tor && (
            <Badge variant="critical" size="xs" icon={<ShieldAlert className="w-3 h-3" />}>
              Tor Exit
            </Badge>
          )}
          {geolocation?.is_vpn && (
            <Badge variant="warning" size="xs">
              VPN
            </Badge>
          )}
          {geolocation?.is_proxy && !geolocation?.is_vpn && !geolocation?.is_tor && (
            <Badge variant="warning" size="xs">
              Proxy
            </Badge>
          )}
          {geolocation?.is_datacenter && (
            <Badge variant="warning" size="xs" icon={<Database className="w-3 h-3" />}>
              Datacenter
            </Badge>
          )}
          {geolocation?.country_code === 'LOCAL' && (
            <Badge variant="neutral" size="xs">
              Private / LAN
            </Badge>
          )}
          {!geolocation?.is_tor &&
            !geolocation?.is_vpn &&
            !geolocation?.is_proxy &&
            !geolocation?.is_datacenter &&
            !isUnknown &&
            geolocation?.country_code !== 'LOCAL' && (
              <Badge variant="low" size="xs">
                Direct Relay
              </Badge>
            )}

          {isUnknown && (
            <Badge variant="neutral" size="xs" icon={<HelpCircle className="w-3 h-3" />}>
              Unknown Telemetry
            </Badge>
          )}

          {geolocation?.cached && (
            <Badge variant="neutral" size="xs" className="opacity-75">
              Cached 24h
            </Badge>
          )}
        </div>

        {/* Pivot Action Button */}
        {onPivot && (
          <button
            type="button"
            onClick={handlePivot}
            className="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-inset)] border border-[var(--border-subtle)] transition-colors cursor-pointer"
            title="Inspect full IP geolocation details in Drawer"
          >
            <span>Pivot IP</span>
            <ExternalLink className="w-3 h-3 opacity-70" />
          </button>
        )}
      </div>

      {/* Body: Location, Network infrastructure details */}
      {isUnknown ? (
        <div className="p-3 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] text-xs text-[var(--text-secondary)] flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <HelpCircle className="w-4 h-4 text-[var(--text-tertiary)] shrink-0" />
            <span>
              Telemetry unavailable or deferred under strict privacy mode. No active external lookup performed for this relay.
            </span>
          </div>
          <CopyButton
            value={ip}
            onCopy={handleCopyIp}
            tooltip="Copy Defanged IP"
            size="xs"
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 pt-1 text-xs font-mono">
          {/* Location details */}
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
            <div className="text-[10px] uppercase font-bold text-[var(--text-tertiary)] flex items-center gap-1">
              <MapPin className="w-3 h-3 text-cyan-400" />
              <span>Geographic Location</span>
            </div>
            <div className="flex items-center gap-1.5 text-[var(--text-primary)] font-sans font-medium text-xs">
              <span className="text-base select-none leading-none">{flag}</span>
              <span className="truncate">
                {geolocation.country}
                {geolocation.city && geolocation.city !== 'unknown' && `, ${geolocation.city}`}
              </span>
            </div>
            <div className="text-[10px] text-[var(--text-tertiary)]">
              {geolocation.lat != null && geolocation.lon != null
                ? `${geolocation.lat.toFixed(2)}°, ${geolocation.lon.toFixed(2)}°`
                : '—'}
            </div>
          </div>

          {/* ASN & ISP details */}
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1">
            <div className="text-[10px] uppercase font-bold text-[var(--text-tertiary)] flex items-center gap-1">
              <Server className="w-3 h-3 text-purple-400" />
              <span>Autonomous System (ASN)</span>
            </div>
            <div className="text-[var(--text-primary)] truncate font-semibold">
              {geolocation.asn || 'AS Unknown'}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] truncate">
              {geolocation.org || geolocation.isp || 'Unspecified Provider'}
            </div>
          </div>

          {/* Carrier & ISP routing */}
          <div className="p-2.5 rounded-lg bg-[var(--bg-inset)] border border-[var(--border-subtle)] space-y-1 sm:col-span-2 lg:col-span-1">
            <div className="text-[10px] uppercase font-bold text-[var(--text-tertiary)] flex items-center gap-1">
              <Radio className="w-3 h-3 text-emerald-400" />
              <span>Internet Service Provider</span>
            </div>
            <div className="text-[var(--text-primary)] truncate font-semibold font-sans">
              {geolocation.isp || 'Private / Local Network'}
            </div>
            <div className="text-[10px] text-[var(--text-secondary)] flex items-center gap-2">
              <span>TZ: {geolocation.timezone || 'UTC'}</span>
              <span>·</span>
              <span className={geolocation.cached ? 'text-amber-400' : 'text-emerald-400'}>
                {geolocation.cached ? 'Local Cache' : 'Live Enrich'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

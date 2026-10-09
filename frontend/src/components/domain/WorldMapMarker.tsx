import React from 'react';

export interface WorldMapMarkerProps {
  lat?: number | null;
  lon?: number | null;
  country?: string;
  city?: string;
  ip?: string;
  className?: string;
}

export const WorldMapMarker: React.FC<WorldMapMarkerProps> = ({
  lat,
  lon,
  country,
  city,
  ip,
  className = '',
}) => {
  const hasCoordinates =
    lat != null &&
    lon != null &&
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    !isNaN(lat) &&
    !isNaN(lon) &&
    (lat !== 0 || lon !== 0);

  // Equirectangular projection (width 800, height 400)
  // X: lon from -180 to +180 -> 0 to 800
  // Y: lat from +90 to -90 -> 0 to 400
  const markerX = hasCoordinates ? Math.max(12, Math.min(788, ((lon! + 180) / 360) * 800)) : 400;
  const markerY = hasCoordinates ? Math.max(12, Math.min(388, ((90 - lat!) / 180) * 400)) : 200;

  const accessibleLabel = hasCoordinates
    ? `World map marker located at latitude ${lat!.toFixed(2)}, longitude ${lon!.toFixed(2)} in ${city ? `${city}, ` : ''
    }${country || 'unknown'}`
    : `World map - Location unavailable for ${country || 'unknown destination'}`;

  return (
    <div
      tabIndex={0}
      role="region"
      aria-label={accessibleLabel}
      className={`relative w-full max-w-full overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] focus:outline-none focus:ring-2 focus:ring-cyan-500/60 transition-all ${className}`}
    >
      <svg
        viewBox="0 0 800 400"
        className="w-full h-auto block select-none pointer-events-none"
        preserveAspectRatio="xMidYMid meet"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--bg-panel)" stopOpacity="0.8" />
            <stop offset="100%" stopColor="var(--bg-inset)" stopOpacity="1" />
          </radialGradient>
          <filter id="markerGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="3" />
          </filter>
        </defs>

        {/* Map Background */}
        <rect width="800" height="400" fill="url(#mapGlow)" />

        {/* Grid lines (Equirectangular) */}
        <g stroke="var(--border-subtle)" strokeWidth="0.5" strokeDasharray="3 3" opacity="0.6">
          {/* Latitudes */}
          <line x1="0" y1="100" x2="800" y2="100" /> {/* 45 N */}
          <line x1="0" y1="200" x2="800" y2="200" strokeWidth="1" stroke="var(--border-strong)" strokeDasharray="none" /> {/* Equator */}
          <line x1="0" y1="300" x2="800" y2="300" /> {/* 45 S */}

          {/* Longitudes */}
          <line x1="200" y1="0" x2="200" y2="400" /> {/* 90 W */}
          <line x1="400" y1="0" x2="400" y2="400" strokeWidth="1" stroke="var(--border-strong)" strokeDasharray="none" /> {/* Prime Meridian */}
          <line x1="600" y1="0" x2="600" y2="400" /> {/* 90 E */}
        </g>

        {/* Simplified Continents Silhouette Paths */}
        <g fill="currentColor" className="text-[var(--text-tertiary)] opacity-20">
          {/* North America & Greenland */}
          <path d="M 120 40 L 160 30 L 220 35 L 230 65 L 180 75 L 195 100 L 240 95 L 255 125 L 235 155 L 210 180 L 180 200 L 170 220 L 190 230 L 180 250 L 160 215 L 140 185 L 125 150 L 110 120 L 80 80 L 100 55 Z" />
          <path d="M 270 30 L 330 25 L 340 60 L 300 85 L 265 65 Z" /> {/* Greenland */}

          {/* South America */}
          <path d="M 195 240 L 230 235 L 275 255 L 310 280 L 300 320 L 270 365 L 250 380 L 235 340 L 220 290 L 190 255 Z" />

          {/* Europe & Mediterranean */}
          <path d="M 370 70 L 410 60 L 430 80 L 415 110 L 435 130 L 405 145 L 375 140 L 360 110 L 355 85 Z" />
          <path d="M 410 40 L 435 35 L 440 65 L 420 80 L 400 65 Z" /> {/* Scandinavia */}
          <path d="M 365 75 L 380 70 L 385 95 L 370 100 Z" /> {/* British Isles */}

          {/* Africa */}
          <path d="M 375 150 L 430 145 L 475 170 L 495 210 L 465 260 L 450 310 L 420 330 L 400 290 L 365 220 L 355 180 Z" />
          <path d="M 480 280 L 495 275 L 490 310 L 475 315 Z" /> {/* Madagascar */}

          {/* Eurasia / Asia */}
          <path d="M 440 70 L 510 50 L 610 55 L 720 70 L 740 105 L 700 130 L 670 120 L 685 160 L 640 180 L 620 210 L 580 215 L 560 185 L 520 190 L 485 165 L 450 135 L 450 95 Z" />
          <path d="M 530 190 L 575 185 L 565 240 L 535 225 Z" /> {/* Indian Subcontinent */}
          <path d="M 465 160 L 510 160 L 500 210 L 465 195 Z" /> {/* Arabian Peninsula */}
          <path d="M 700 115 L 725 110 L 730 150 L 710 160 Z" /> {/* Japan */}

          {/* Southeast Asia Islands */}
          <path d="M 630 220 L 670 225 L 680 250 L 635 245 Z" />
          <path d="M 680 230 L 720 235 L 715 255 L 685 250 Z" />

          {/* Australia & New Zealand */}
          <path d="M 650 270 L 725 260 L 750 300 L 730 335 L 675 345 L 640 310 Z" />
          <path d="M 760 330 L 780 325 L 775 360 L 755 355 Z" />

          {/* Antarctica */}
          <path d="M 80 385 L 240 375 L 400 380 L 580 375 L 740 385 L 800 395 L 0 395 Z" />
        </g>

        {/* Pinpoint Location Marker */}
        {hasCoordinates && (
          <g transform={`translate(${markerX}, ${markerY})`} className="pointer-events-auto">
            {/* Pulsing ripple waves */}
            <circle
              r="22"
              className="fill-cyan-500/10 stroke-cyan-400/40 animate-ping"
              style={{ animationDuration: '2.5s' }}
            />
            <circle
              r="14"
              className="fill-cyan-500/20 stroke-cyan-400/60"
            />

            {/* Glowing radar target crosshairs */}
            <line x1="-12" y1="0" x2="-5" y2="0" stroke="#06B6D4" strokeWidth="1.5" />
            <line x1="5" y1="0" x2="12" y2="0" stroke="#06B6D4" strokeWidth="1.5" />
            <line x1="0" y1="-12" x2="0" y2="-5" stroke="#06B6D4" strokeWidth="1.5" />
            <line x1="0" y1="5" x2="0" y2="12" stroke="#06B6D4" strokeWidth="1.5" />

            {/* Core pinpoint dot */}
            <circle
              r="4.5"
              fill="#06B6D4"
              stroke="#FFFFFF"
              strokeWidth="2"
              filter="url(#markerGlow)"
            />
            <circle
              r="2"
              fill="#FFFFFF"
            />
          </g>
        )}
      </svg>

      {/* Floating Info Pill overlay */}
      <div className="absolute bottom-2 left-2 right-2 flex items-center justify-between pointer-events-none text-[10px] font-mono">
        <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-[var(--bg-panel)]/90 backdrop-blur-xs border border-[var(--border-subtle)] text-[var(--text-secondary)] shadow-xs">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${hasCoordinates ? 'bg-cyan-400 animate-pulse' : 'bg-gray-400'}`} />
          <span>
            {hasCoordinates
              ? `${lat!.toFixed(2)}°, ${lon!.toFixed(2)}°`
              : 'Location unavailable'}
          </span>
          {city && hasCoordinates && <span className="text-[var(--text-tertiary)]">· {city}</span>}
          {country && <span className="font-semibold text-[var(--text-primary)]">({country})</span>}
        </div>

        {ip && (
          <div className="hidden sm:flex items-center px-2 py-1 rounded bg-[var(--bg-panel)]/90 backdrop-blur-xs border border-[var(--border-subtle)] text-[var(--text-tertiary)]">
            IP: {ip}
          </div>
        )}
      </div>
    </div>
  );
};

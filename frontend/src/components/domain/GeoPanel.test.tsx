import React from 'react';
import { describe, it, expect } from 'vitest';
import { renderToString } from 'react-dom/server';
import { GeoPanel } from './GeoPanel';
import { DefangProvider } from '../../design/DefangContext';
import type { GeoLocation } from '../../types/threat';

describe('GeoPanel Null Guards', () => {
  it('renders GeoPanel with lat=null, lon=null without crashing and displays "—"', () => {
    const geoData: GeoLocation = {
      ip: '192.168.1.1',
      country: 'Private Network',
      country_code: 'LOCAL',
      region: 'Internal',
      city: 'Local',
      lat: null,
      lon: null,
      timezone: 'UTC',
      isp: 'Internal LAN',
      asn: 'RFC1918',
      org: 'Local Network',
      is_vpn: false,
      is_proxy: false,
      is_tor: false,
      is_datacenter: false,
      is_unknown: false,
      cached: true,
    };

    let html = '';
    expect(() => {
      html = renderToString(
        <DefangProvider>
          <GeoPanel geolocation={geoData} ip="192.168.1.1" />
        </DefangProvider>
      );
    }).not.toThrow();

    expect(html).toContain('—');
    expect(html).not.toContain('NaN');
  });
});

import { useEffect } from 'react';
import { useDefang } from '../../design/DefangContext';
import { useToast } from '../primitives/Toast';

export function CopyWarningBridge(): null {
  const { onLiveCopy } = useDefang();
  const { warning } = useToast();

  useEffect(() => {
    return onLiveCopy(() => {
      warning('Copied LIVE indicator (Caution: active weaponized target)', 'Live Indicator Copied');
    });
  }, [onLiveCopy, warning]);

  return null;
}

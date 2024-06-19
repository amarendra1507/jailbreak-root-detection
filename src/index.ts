import { registerPlugin } from '@capacitor/core';

import type { JailbreakRootDetectionPlugin } from './definitions';

const JailbreakRootDetection = registerPlugin<JailbreakRootDetectionPlugin>(
  'JailbreakRootDetection',
  {
    web: () => import('./web').then(m => new m.JailbreakRootDetectionWeb()),
  },
);

export * from './definitions';
export { JailbreakRootDetection };

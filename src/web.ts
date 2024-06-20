import { WebPlugin } from '@capacitor/core';

import type { JailbreakRootDetectionPlugin } from './definitions';

export class JailbreakRootDetectionWeb
  extends WebPlugin
  implements JailbreakRootDetectionPlugin
{
  async echo(options: { value: string }): Promise<{value: string}> {
    console.log('ECHO', "isJailbroken", options);
    return options;
  }

  async jailbroken(options: {value: string}) : Promise<{value: string}> {
    console.log('ECHO', "isJailbroken", options);
    return options;
  }

}

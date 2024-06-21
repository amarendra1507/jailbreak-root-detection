export interface JailbreakRootDetectionPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
  jailbroken(options: { verificationKey: string, decryptionKey: string }): Promise<{ isJailbroken: boolean }>;
}

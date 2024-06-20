export interface JailbreakRootDetectionPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
  jailbroken(options: { value: string }): Promise<{ value: string }>;
}

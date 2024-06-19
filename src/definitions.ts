export interface JailbreakRootDetectionPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
}

// The current time, in one place so pages do not call Date.now() inside a component.
export function currentTimeMs(): number {
  return Date.now();
}

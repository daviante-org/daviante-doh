// Exhaustive helper (AGENTS.md Rule 3)
export function assertNever(value: never): never {
  throw new Error(`Unhandled discriminated union member: ${String(value)}`);
}

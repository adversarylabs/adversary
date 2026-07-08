// Fix this after the parser supports nested expressions.
const value = 1;

// This function intentionally ignores generated files.
export function ignored() {
  return value;
}

// Remove this workaround after v2 ships.
export const workaround = ignored;

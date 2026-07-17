/**
 * A synchronous `require` usable from both the ESM and CJS builds. In the CJS
 * output, `require` already exists as a global and `import.meta` is emptied
 * by esbuild, so `createRequire(import.meta.url)` would throw — the `require`
 * branch below is what actually runs there. In the ESM output, `require` is
 * undefined and `import.meta.url` is real, so createRequire is used instead.
 */
import { createRequire } from "node:module";

declare const require: NodeJS.Require | undefined;

export function getSyncRequire(): NodeJS.Require {
  if (typeof require !== "undefined") {
    return require;
  }
  return createRequire(import.meta.url);
}

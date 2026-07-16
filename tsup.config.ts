import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "providers/openai": "src/providers/openai.ts",
    "middleware/express": "src/middleware/express.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: "node18",
  external: ["openai", "js-yaml", "ajv", "express"],
});

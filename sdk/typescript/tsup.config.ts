import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: "es2022",
  minify: false,
  // Keep bundle small. zod is a peer dep (not bundled).
  external: ["zod"],
});

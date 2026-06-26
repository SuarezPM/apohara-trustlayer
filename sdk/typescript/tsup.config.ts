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
  // The wasm/ folder ships in the npm tarball but tsup must NOT
  // bundle it; instead the published `dist/` keeps an explicit copy
  // of `tl_wasm_bg.wasm` next to `index.js` / `index.cjs` (added by
  // the `build:copy` npm script).
  external: ["../wasm/tl_wasm.js"],
  // Preserve ES module syntax for the wasm loader — don't try to
  // commonJS-ify it.
  loader: { ".js": "js" },
});

import { defineConfig, type Plugin } from 'vite';

// @oqs/liboqs-js loads each algorithm's WASM with `await import(modulePath)`,
// where `modulePath` is a runtime ternary (Deno vs. browser). Rollup can't
// statically analyze a dynamic import whose argument is a variable, so it leaves
// the call untouched and never emits the target `dist/*.min.js` modules — they
// resolve fine under Node (real files on disk) but 404 in a production browser
// build. This plugin rewrites that one call so the import argument is the static
// `.min.js` path literal, which Rollup CAN analyze: it then bundles each WASM
// module as an async chunk and rewrites the URL with the correct base path.
// Only the algorithm source modules this demo actually imports. Rewriting just
// these keeps Rollup from eagerly parsing the WASM for every algorithm the
// library's barrel re-exports (mceliece, snova, …) before tree-shaking drops them.
const USED_ALGORITHM_MODULES = [
  'efrodokem-640-aes.js',
  'efrodokem-976-aes.js',
  'efrodokem-1344-aes.js',
  'ml-kem-768.js',
];

function liboqsStaticWasmImport(): Plugin {
  return {
    name: 'liboqs-static-wasm-import',
    enforce: 'pre',
    transform(code, id) {
      if (!id.includes('@oqs/liboqs-js') || !id.includes('/algorithms/')) return null;
      if (!USED_ALGORITHM_MODULES.some((f) => id.includes(`/${f}`))) return null;
      if (!code.includes('await import(modulePath)')) return null;
      const match = code.match(/`(\.\.\/[^`]*?\.min\.js)`/);
      if (!match) return null;
      const rewritten = code.replace(
        'await import(modulePath)',
        'await import(`' + match[1] + '`)',
      );
      if (rewritten === code) return null;
      return { code: rewritten, map: null };
    },
  };
}

export default defineConfig({
  base: '/crypto-lab-frodo-vault/',
  plugins: [liboqsStaticWasmImport()],
  // Skip esbuild prebundling for liboqs so the plugin above applies to the raw
  // ESM consistently in dev and build.
  optimizeDeps: {
    exclude: ['@oqs/liboqs-js'],
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});

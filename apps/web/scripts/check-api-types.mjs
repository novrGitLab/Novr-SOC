// Generate (--write) or verify (default) the TypeScript types derived from the published OpenAPI documents:
//   packages/contracts/openapi/novrsoc-api.v1.json        -> src/foundation/api/schema.gen.ts     (HTTP API)
//   packages/contracts/openapi/novrsoc-contracts.v1.json  -> src/foundation/api/contracts.gen.ts  (shared contracts)
// Exit 1 when a committed file differs from what the documents generate (contract drift).
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import openapiTS, { astToString } from 'openapi-typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(root, '..', '..');
const BANNER = '// GENERATED from packages/contracts/openapi/%s by scripts/check-api-types.mjs. Do not edit.\n// Regenerate: npm run api:types (after scripts/contracts/export.py).\n\n';
const PAIRS = [
    ['novrsoc-api.v1.json', 'src/foundation/api/schema.gen.ts'],
    ['novrsoc-contracts.v1.json', 'src/foundation/api/contracts.gen.ts'],
];

const write = process.argv.includes('--write');
let drift = 0;
for (const [doc, out] of PAIRS) {
    const src = join(repo, 'packages', 'contracts', 'openapi', doc);
    const ast = await openapiTS(pathToFileURL(src));
    const text = BANNER.replace('%s', doc) + astToString(ast);
    const target = join(root, out);
    if (write) { writeFileSync(target, text); console.log(`wrote ${out}`); continue; }
    if (!existsSync(target) || readFileSync(target, 'utf8') !== text) { console.error(`DRIFT: ${out} does not match ${doc}`); drift++; }
    else console.log(`ok: ${out} matches ${doc}`);
}
process.exit(drift ? 1 : 0);

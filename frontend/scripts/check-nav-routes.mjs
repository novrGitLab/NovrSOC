// Fails (exit 1) if any sidebar href in src/config/nav.ts has no matching page under src/app.
//
//   npm run check:nav
//
// nav.ts is transpiled with the project's own TypeScript and evaluated, so computed hrefs (the
// CNII sector list) are checked as rendered, not scraped with a regex. A route matches when each
// path segment resolves to a directory of the same name or a dynamic [param] directory, and the
// final directory contains page.tsx / page.ts / page.jsx / page.js.
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const appDir = join(root, 'src', 'app');

// Transpile into node_modules/.cache so `lucide-react` resolves from the project's node_modules.
// nav.ts imports the VMS section list (config/vmsSections.ts), so that is transpiled alongside it.
const cacheDir = join(root, 'node_modules', '.cache', 'nav-check');
mkdirSync(cacheDir, { recursive: true });
function transpile(name) {
    const source = join(root, 'src', 'config', `${name}.ts`);
    const out = ts.transpileModule(readFileSync(source, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, verbatimModuleSyntax: false },
        fileName: source,
    });
    const file = join(cacheDir, `${name}.mjs`);
    writeFileSync(file, out.outputText.replace(/from '\.\/vmsSections'/g, "from './vmsSections.mjs'"));
    return file;
}
transpile('vmsSections');
const compiled = transpile('nav');

const { ADMIN_NAV, CLIENT_NAV } = await import(pathToFileURL(compiled).href);
const { VMS_SECTIONS } = await import(pathToFileURL(join(cacheDir, 'vmsSections.mjs')).href);

const PAGE_FILES = ['page.tsx', 'page.ts', 'page.jsx', 'page.js'];
const isDir = (p) => existsSync(p) && statSync(p).isDirectory();

function resolveRoute(href) {
    const segments = href.split('?')[0].split('#')[0].split('/').filter(Boolean);
    let dirs = [appDir];
    for (const seg of segments) {
        const next = [];
        for (const d of dirs) {
            if (isDir(join(d, seg))) next.push(join(d, seg));
            for (const entry of readdirSync(d)) {
                const full = join(d, entry);
                if (/^\[[^\]]+\]$/.test(entry) && isDir(full)) next.push(full);
                // Route groups like (marketing) don't add a URL segment.
                if (/^\(.+\)$/.test(entry) && isDir(full) && isDir(join(full, seg))) next.push(join(full, seg));
            }
        }
        dirs = next;
        if (dirs.length === 0) return null;
    }
    for (const d of dirs) for (const f of PAGE_FILES) if (existsSync(join(d, f))) return join(d, f);
    return null;
}

const items = [...ADMIN_NAV, ...CLIENT_NAV].flatMap((s) => s.items);
if (items.length === 0) {
    console.error('check-nav-routes: no nav items found in src/config/nav.ts');
    process.exit(1);
}

const ids = new Map();
const missing = [];
for (const item of items) {
    if (ids.has(item.id)) missing.push(`${item.id}: duplicate id (also used by "${ids.get(item.id)}")`);
    ids.set(item.id, item.label);
    if (!resolveRoute(item.href)) missing.push(`${item.id}: ${item.href} has no page under src/app`);
}

// Every VMS section page (the tabs in app/admin/vms/layout.tsx) must exist too.
const vmsPages = VMS_SECTIONS.flatMap((s) => s.pages);
for (const p of vmsPages) if (!resolveRoute(p.href)) missing.push(`vms page "${p.label}": ${p.href} has no page under src/app`);

if (missing.length > 0) {
    console.error(`check-nav-routes: ${missing.length} problem(s):`);
    for (const m of missing) console.error(`  - ${m}`);
    process.exit(1);
}
console.log(`check-nav-routes: all ${items.length} nav hrefs and ${vmsPages.length} VMS section pages resolve to a page.`);

#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const sourceFiles = [
    path.join(projectRoot, 'express-rest-api', 'src', 'app.ts'),
    path.join(projectRoot, 'express-rest-api', 'src', 'routes', 'index.ts'),
];
const docsFile = path.join(projectRoot, 'express-rest-api', 'docs', 'API_REFERENCE.md');

const endpointPattern = /\bapp\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]/g;
const documentedEndpointPattern = /\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_\-\/.{}:]*)/g;

const excludedEndpoints = new Set([
    'GET /api/error',
    'GET /api/crash',
]);

const normalizeEndpoint = (method, routePath) => {
    const normalizedPath = routePath.length > 1 && routePath.endsWith('/') ? routePath.slice(0, -1) : routePath;
    return `${method.toUpperCase()} ${normalizedPath}`;
};

const collectImplementedEndpoints = () => {
    const implemented = new Set();

    for (const file of sourceFiles) {
        const content = readFileSync(file, 'utf8');
        const matches = content.matchAll(endpointPattern);

        for (const match of matches) {
            const endpoint = normalizeEndpoint(match[1], match[2]);
            if (!excludedEndpoints.has(endpoint)) {
                implemented.add(endpoint);
            }
        }
    }

    return implemented;
};

const collectDocumentedEndpoints = () => {
    const docsContent = readFileSync(docsFile, 'utf8');
    const documented = new Set();
    const matches = docsContent.matchAll(documentedEndpointPattern);

    for (const match of matches) {
        documented.add(normalizeEndpoint(match[1], match[2]));
    }

    return documented;
};

const printList = (title, values) => {
    console.log(`\n${title}`);
    for (const value of values) {
        console.log(`  - ${value}`);
    }
};

const implementedEndpoints = collectImplementedEndpoints();
const documentedEndpoints = collectDocumentedEndpoints();

const missingInDocs = [...implementedEndpoints]
    .filter((endpoint) => !documentedEndpoints.has(endpoint))
    .sort();

const staleInDocs = [...documentedEndpoints]
    .filter((endpoint) => !implementedEndpoints.has(endpoint))
    .sort();

console.log('API doc coverage check');
console.log(`Implemented endpoints: ${implementedEndpoints.size}`);
console.log(`Documented endpoints: ${documentedEndpoints.size}`);

if (missingInDocs.length === 0 && staleInDocs.length === 0) {
    console.log('\nNo endpoint coverage gaps found.');
    process.exit(0);
}

if (missingInDocs.length > 0) {
    printList('Missing in docs:', missingInDocs);
}

if (staleInDocs.length > 0) {
    printList('Possibly stale in docs:', staleInDocs);
}

process.exit(1);

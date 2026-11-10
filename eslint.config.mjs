import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

const domains = ['identity', 'organizations', 'resources', 'audit'];

const deepDomainImport = (message) => ({
  group: ['**/domains/*/**'],
  message,
});

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  globalIgnores(['.next/**', 'out/**', 'build/**', 'next-env.d.ts', 'coverage/**']),

  // Boundary rule: outside a domain, import only from '@/domains/<x>' (its index).
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/domains/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            deepDomainImport(
              "Import a domain only through its public index, e.g. '@/domains/identity'. Deep paths are private.",
            ),
          ],
        },
      ],
    },
  },

  // Inside a domain: reach other domains only through their index.
  // Own internals are imported with relative paths.
  ...domains.map((own) => ({
    files: [`src/domains/${own}/**/*.{ts,tsx}`],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            deepDomainImport(
              "A domain imports another domain only through its index ('@/domains/<x>'). Use relative paths inside your own domain.",
            ),
            {
              group: ['@/experiences/**', '**/experiences/**'],
              message: 'Domains must not depend on experiences.',
            },
          ],
        },
      ],
    },
  })),
  // Files at a domain's root: a relative '../<other>/<file>' is a deep import too.
  {
    files: ['src/domains/*/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            deepDomainImport("Import another domain only through its index ('@/domains/<x>')."),
            {
              group: ['../*/**'],
              message: "Import another domain only through its index ('@/domains/<x>').",
            },
            {
              group: ['@/experiences/**', '**/experiences/**'],
              message: 'Domains must not depend on experiences.',
            },
          ],
        },
      ],
    },
  },
]);

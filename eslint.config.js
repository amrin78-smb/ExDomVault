import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist',
      '**/.wrangler',
      '**/node_modules',
      '**/coverage',
      'worker',
      'apps/web/worker-configuration.d.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ['apps/web/src/**/*.{ts,tsx}'],
    languageOptions: { globals: globals.browser },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
  {
    files: ['**/*.config.{js,ts}'],
    languageOptions: { globals: globals.node },
  },
  {
    // Tests assert on rows they just inserted; non-null assertions are clearer than guards there.
    files: ['**/*.test.{ts,tsx}'],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },
  {
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': 'error',
    },
  },
);

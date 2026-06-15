import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // eslint-plugin-react-hooks v7 promoted the experimental React Compiler
      // rules into "recommended" as errors. They flag idiomatic, working
      // patterns we use throughout (the latest-ref pattern, reading a ref to
      // derive a render value). We have not adopted the React Compiler, so
      // these are advisory here: keep them visible as warnings rather than
      // failing the lint on a dependency bump. Revisit when adopting the
      // compiler. react-refresh is a dev-only fast-refresh hint, also advisory.
      'react-hooks/refs': 'warn',
      'react-hooks/purity': 'warn',
      'react-refresh/only-export-components': 'warn',
    },
  },
])

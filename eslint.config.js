// ESLint flat config for the React + TypeScript UI. Formatting is Prettier's job (`npm run format`).

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import prettier from "eslint-config-prettier";
import globals from "globals";

export default tseslint.config(
  // src/components/ui and src/hooks/use-mobile.ts are shadcn/ui output, kept as generated.
  {
    ignores: ["dist", "node_modules", "src-tauri", "target", "crates", "src/components/ui", "src/hooks/use-mobile.ts"],
  },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended, reactHooks.configs.flat.recommended, prettier],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
  },
);

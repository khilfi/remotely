/// <reference types="node" />
// UX-06: no requirement ID (VM-23, AP-04, SS-09...) reaches the screen. Every string literal, template and piece of JSX
// text in src/**/*.tsx and src/lib/*.ts is checked; comments may keep their IDs, and so may tests. The files are read
// with TypeScript's own parser, so an apostrophe in JSX text or a // inside a string can't fool the check. Run with
// `npm test`.

import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/** The prefixes of the PRD's and the plans' requirement IDs (CLAUDE.md). */
const REQUIREMENT_ID = /\b(?:VM|SS|BX|AP|MO|FD|QL|CT|CV|UX)-\d{2}\b/;

const SRC = fileURLToPath(new URL("..", import.meta.url));

/** Each requirement ID in the text a file shows: its strings, templates and JSX text, never its comments. */
function idsInSource(text: string, fileName: string): { line: number; text: string }[] {
  const kind = fileName.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);
  const found: { line: number; text: string }[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node) ||
      ts.isJsxText(node)
    ) {
      // Module names are not shown.
      if (
        !ts.isImportDeclaration(node.parent) &&
        !ts.isExportDeclaration(node.parent) &&
        REQUIREMENT_ID.test(node.text)
      ) {
        const { line } = source.getLineAndCharacterOfPosition(node.getStart(source));
        found.push({ line: line + 1, text: node.text.trim().slice(0, 100) });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

/** The UI's own files: every .tsx under src (shadcn's generated components aside) and src/lib's modules. */
function uiFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) {
        if (relative(SRC, path).replace(/\\/g, "/") !== "components/ui") walk(path);
      } else if (name.endsWith(".tsx")) out.push(path);
    }
  };
  walk(SRC);
  const lib = join(SRC, "lib");
  for (const name of readdirSync(lib)) {
    if (name.endsWith(".ts") && !name.endsWith(".test.ts")) out.push(join(lib, name));
  }
  return out;
}

test("the check finds an ID in a string or JSX text, and not in a comment", () => {
  const code = [
    "// AP-04: a comment may name it",
    "/* VM-23 here too */",
    'const ok = "Protected";',
    "const a = <p>Don't touch {/* SS-09 */} this</p>;",
    'const bad = "Do not touch (AP-04)";',
    "const tpl = `a ${ok} (VM-21)`;",
    "const jsx = <p>Only its public half (SS-09).</p>;",
    'const url = "https://example.com/a//b"; // QL-01',
  ].join("\n");
  assert.deepEqual(
    idsInSource(code, "fixture.tsx").map((f) => f.line),
    [5, 6, 7],
  );
});

test("no requirement ID shows in the UI", () => {
  const files = uiFiles();
  assert.ok(files.length > 100, "the UI's files are found");
  const found = files.flatMap((file) =>
    idsInSource(readFileSync(file, "utf8"), file).map(
      (f) => `${relative(SRC, file).replace(/\\/g, "/")}:${f.line}: ${f.text}`,
    ),
  );
  assert.deepEqual(found, [], "move the ID into a comment, or drop it from the text");
});

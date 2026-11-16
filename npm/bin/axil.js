#!/usr/bin/env node
import { spawn } from "node:child_process";
import { fstatSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { normalizeCliArgs, runCli } from "../dist/index.js";

function detachedFdMode(fd) {
  try {
    return fstatSync(fd).isFile() ? "inherit" : "ignore";
  } catch {
    return "ignore";
  }
}

const rawArgs = process.argv.slice(2);

let foreground = false;
let help = false;
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a === "-K" || a === "-k" || a === "-C" || a === "-p" || a === "-s" || a === "-B" || a === "-m") {
    i++;
    continue;
  }
  if (a.startsWith("-") && a.length > 1 && !a.startsWith("--")) {
    for (let j = 1; j < a.length; j++) {
      const ch = a[j];
      if (ch === "d") foreground = true;
      if (ch === "?") help = true;
      if ("KkCpsBm".includes(ch)) {
        if (j === a.length - 1) i++;
        break;
      }
    }
  }
}

const resolvedArgs = normalizeCliArgs(rawArgs);

if (!foreground && !help) {
  const selfPath = fileURLToPath(import.meta.url);
  const stdio = ["ignore", detachedFdMode(1), detachedFdMode(2)];
  const child = spawn(process.execPath, [selfPath, "-d", ...resolvedArgs], {
    detached: true,
    stdio,
    env: process.env,
  });
  child.unref();
  process.exit(0);
}

const rc = runCli(resolvedArgs);
process.exit(rc);

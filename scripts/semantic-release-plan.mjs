#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  let configPath = ".releaserc";
  let output = "";
  let retryTag = "";
  let sourceSha = "";
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--output") {
      output = argv[index + 1] ?? "";
      index += 1;
    } else if (argument === "--config") {
      configPath = argv[index + 1] ?? "";
      index += 1;
    } else if (argument === "--retry-tag") {
      retryTag = argv[index + 1] ?? "";
      index += 1;
    } else if (argument === "--source-sha") {
      sourceSha = argv[index + 1] ?? "";
      index += 1;
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  if (!output) fail("--output is required");
  if (!configPath) fail("--config must not be empty");
  if (!/^[0-9a-f]{40}$/.test(sourceSha)) {
    fail("--source-sha must be an exact lowercase commit SHA");
  }
  if (retryTag && !/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(retryTag)) {
    fail("--retry-tag must be an exact stable semantic version tag");
  }
  return { configPath: resolve(configPath), output: resolve(output), retryTag, sourceSha };
}

function findSemanticReleaseModules(cwd) {
  const nodeModules = join(cwd, "node_modules");
  return {
    semanticRelease: join(nodeModules, "semantic-release", "index.js"),
    commitAnalyzer: join(nodeModules, "@semantic-release", "commit-analyzer", "index.js"),
    releaseNotesGenerator: join(
      nodeModules,
      "@semantic-release",
      "release-notes-generator",
      "index.js",
    ),
  };
}

function readConfiguration(configPath) {
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  const expectedNames = [
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
  ];
  if (JSON.stringify(config.branches) !== JSON.stringify(["main"])) {
    fail("semantic-release branches must be the exact main singleton");
  }
  if (config.tagFormat !== "v${version}") {
    fail("semantic-release tagFormat must be v${version}");
  }
  if (!Array.isArray(config.plugins) || config.plugins.length !== expectedNames.length) {
    fail("semantic-release planner must contain exactly two read-only plugins");
  }
  const options = config.plugins.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2 || entry[0] !== expectedNames[index]) {
      fail("semantic-release planner plugin order or shape is invalid");
    }
    if (!entry[1] || typeof entry[1] !== "object" || Array.isArray(entry[1])) {
      fail("semantic-release planner plugin options are invalid");
    }
    return entry[1];
  });
  return { config, options };
}

const { configPath, output, retryTag, sourceSha } = parseArguments(process.argv.slice(2));
const cwd = process.cwd();
if (process.env.GITHUB_REPOSITORY !== "lightning-it/container-ee-wunder-ansible-ubi9") {
  fail("GITHUB_REPOSITORY is outside the exact planner scope");
}
const { config, options } = readConfiguration(configPath);
const modules = findSemanticReleaseModules(cwd);
const isolatedRoot = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), "semantic-plan-"));
const isolatedRepository = join(isolatedRoot, "repository.git");
const isolatedWorkspace = join(isolatedRoot, "workspace");
const canonicalRepositoryUrl =
  "https://github.com/lightning-it/container-ee-wunder-ansible-ubi9.git";

try {
  const checkedOutSha = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd,
    encoding: "utf8",
  }).trim();
  if (checkedOutSha !== sourceSha) fail("checked-out commit does not match --source-sha");
  execFileSync(
    "git",
    ["clone", "--bare", "--no-local", cwd, isolatedRepository],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  execFileSync(
    "git",
    ["--git-dir", isolatedRepository, "update-ref", "refs/heads/main", sourceSha],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  execFileSync(
    "git",
    ["clone", "--no-local", isolatedRepository, isolatedWorkspace],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  execFileSync("git", ["checkout", "--force", "main"], {
    cwd: isolatedWorkspace,
    stdio: ["ignore", "ignore", "inherit"],
  });
  execFileSync(
    "git",
    [
      "config",
      `url.${pathToFileURL(isolatedRepository).href}.insteadOf`,
      canonicalRepositoryUrl,
    ],
    { cwd: isolatedWorkspace, stdio: ["ignore", "ignore", "inherit"] },
  );
  execFileSync(
    "git",
    ["--git-dir", isolatedRepository, "symbolic-ref", "HEAD", "refs/heads/main"],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  const isolatedHead = execFileSync(
    "git",
    ["--git-dir", isolatedRepository, "rev-parse", "HEAD"],
    { encoding: "utf8" },
  ).trim();
  if (isolatedHead !== sourceSha) fail("isolated repository HEAD does not match --source-sha");
  const sourceTimestamp = execFileSync(
    "git",
    ["show", "-s", "--format=%ct", sourceSha],
    { cwd: isolatedWorkspace, encoding: "utf8" },
  ).trim();
  if (!/^[1-9][0-9]*$/.test(sourceTimestamp)) {
    fail("source commit did not yield a deterministic timestamp");
  }
  const releaseDate = new Date(Number(sourceTimestamp) * 1000)
    .toISOString()
    .slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(releaseDate)) {
    fail("source commit did not yield a deterministic UTC release date");
  }
  if (retryTag) {
    const exactTag = execFileSync("git", ["tag", "--points-at", "HEAD"], {
      cwd: isolatedWorkspace,
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean)
      .filter((tag) => tag === retryTag);
    if (exactTag.length === 1) {
      execFileSync(
        "git",
        ["--git-dir", isolatedRepository, "tag", "--delete", retryTag],
        { stdio: ["ignore", "ignore", "inherit"] },
      );
      execFileSync("git", ["tag", "--delete", retryTag], {
        cwd: isolatedWorkspace,
        stdio: ["ignore", "ignore", "inherit"],
      });
    } else if (exactTag.length > 1) {
      fail("retry tag is ambiguous in the isolated repository");
    }
  }

  const semanticRelease = (await import(pathToFileURL(modules.semanticRelease))).default;
  const commitAnalyzerModule = await import(pathToFileURL(modules.commitAnalyzer));
  const releaseNotesGeneratorModule = await import(
    pathToFileURL(modules.releaseNotesGenerator)
  );
  const commitAnalyzer = { analyzeCommits: commitAnalyzerModule.analyzeCommits };
  const releaseNotesGenerator = {
    generateNotes: releaseNotesGeneratorModule.generateNotes,
  };
  const result = await semanticRelease(
    {
      branches: config.branches,
      ci: false,
      dryRun: true,
      repositoryUrl: canonicalRepositoryUrl,
      tagFormat: config.tagFormat,
      plugins: [
        [commitAnalyzer, options[0]],
        [releaseNotesGenerator, options[1]],
      ],
    },
    {
      cwd: isolatedWorkspace,
      env: {
        ...process.env,
        GH_TOKEN: "",
        GITHUB_TOKEN: "",
      },
      stderr: process.stderr,
      stdout: process.stderr,
    },
  );

  let plan = { release: false };
  if (result !== false && result !== null && result !== undefined) {
    const next = result.nextRelease;
    if (
      !next ||
      typeof next.version !== "string" ||
      typeof next.gitTag !== "string" ||
      next.gitHead !== sourceSha
    ) {
      fail("semantic-release did not return a complete nextRelease plan");
    }
    if (next.gitTag !== `v${next.version}`) {
      fail("semantic-release returned a tag that does not match its version");
    }
    if (!/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(next.gitTag)) {
      fail("semantic-release returned a non-stable tag");
    }
    if (typeof next.notes !== "string" || next.notes.length === 0) {
      fail("semantic-release returned empty release notes");
    }
    const datedHeading = /^(#{1,2} [^\n]+) \(\d{4}-\d{2}-\d{2}\)$/m;
    if (!datedHeading.test(next.notes)) {
      fail("semantic-release notes do not contain the expected dated heading");
    }
    const notes = next.notes.replace(datedHeading, `$1 (${releaseDate})`);
    const canonical = JSON.stringify({
      gitHead: next.gitHead,
      gitTag: next.gitTag,
      notes,
      releaseDate,
      version: next.version,
    });
    plan = {
      release: true,
      version: next.version,
      gitHead: next.gitHead,
      gitTag: next.gitTag,
      notes,
      releaseDate,
      planSha256: createHash("sha256").update(canonical).digest("hex"),
    };
  }
  if (retryTag && (!plan.release || plan.gitTag !== retryTag)) {
    fail("the isolated retry plan does not reproduce the exact resumable draft tag");
  }
  writeFileSync(output, `${JSON.stringify(plan)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
} finally {
  rmSync(isolatedRoot, { force: true, recursive: true });
}

const exec = require("@actions/exec");
const cache = require("@actions/cache");
const core = require("@actions/core");
const tc = require("@actions/tool-cache");
const { readFileSync } = require("fs");
const os = require("os");
const path = require("path");
const { create } = require("@actions/artifact"); // измененный импорт

const EXIT_CODE_LEAKS_DETECTED = 2;

async function Install(version) {
  const pathToInstall = path.join(os.tmpdir(), `gitleaks-${version}`);
  core.info(
    `Version to install: ${version} (target directory: ${pathToInstall})`
  );
  const cacheKey = `gitleaks-cache-${version}-${process.platform}-${process.arch}`;
  let restoredFromCache = undefined;

  try {
    restoredFromCache = await cache.restoreCache([pathToInstall], cacheKey); // восстанавливаем кэш
  } catch (error) {
    core.warning(`Cache restore failed: ${error}`);
  }

  if (restoredFromCache !== undefined) {
    core.info(`✅ Gitleaks restored from cache`);
  } else {
    const gitleaksReleaseURL = downloadURL(
      process.platform,
      process.arch,
      version
    );
    core.info(`⬇️ Downloading gitleaks from ${gitleaksReleaseURL}`);
    let downloadPath = "";
    try {
      downloadPath = await tc.downloadTool(
        gitleaksReleaseURL,
        path.join(os.tmpdir(), `gitleaks.tmp`)
      );
    } catch (error) {
      core.error(
        `❌ Could not install gitleaks from ${gitleaksReleaseURL}, error: ${error}`
      );
      throw error;
    }

    if (gitleaksReleaseURL.endsWith(".zip")) {
      await tc.extractZip(downloadPath, pathToInstall);
    } else if (gitleaksReleaseURL.endsWith(".tar.gz")) {
      await tc.extractTar(downloadPath, pathToInstall);
    } else {
      core.error(`❌ Unsupported archive format: ${gitleaksReleaseURL}`);
      throw new Error("Unsupported archive format");
    }

    try {
      await cache.saveCache([pathToInstall], cacheKey); // сохраняем кэш
    } catch (error) {
      core.warning(`Cache save failed: ${error}`);
    }
  }

  core.addPath(pathToInstall);
}

function downloadURL(platform, arch, version) {
  const baseURL = "https://github.com/zricethezav/gitleaks/releases/download";
  if (platform == "win32") {
    platform = "windows";
  }
  return `${baseURL}/v${version}/gitleaks_${version}_${platform}_${arch}.tar.gz`;
}

async function Latest(octokit) {
  const latest = await octokit.rest.repos.getLatestRelease({
    owner: "zricethezav",
    repo: "gitleaks",
  });

  return latest.data.tag_name.replace(/^v/, "");
}

async function Scan(gitleaksEnableUploadArtifact, scanInfo, eventType) {
  let args = [
    "detect",
    "--redact",
    "-v",
    "--exit-code=2",
    "--report-format=sarif",
    "--report-path=results.sarif",
    "--log-level=debug",
  ];

  if (eventType == "push") {
    if (scanInfo.baseRef == scanInfo.headRef) {
      args.push(`--log-opts=-1`);
    } else {
      args.push(
        `--log-opts=--no-merges --first-parent ${scanInfo.baseRef}^..${scanInfo.headRef}`
      );
    }
  } else if (eventType == "pull_request") {
    args.push(
      `--log-opts=--no-merges --first-parent ${scanInfo.baseRef}^..${scanInfo.headRef}`
    );
  }

  core.info(`🔍 gitleaks cmd: gitleaks ${args.join(" ")}`);
  let exitCode = await exec.exec("gitleaks", args, {
    ignoreReturnCode: true,
    delay: 60 * 1000,
  });
  core.setOutput("exit-code", exitCode);

  if (gitleaksEnableUploadArtifact == true) {
    const artifactClient = create(); // создание клиента артефактов
    const artifactName = "gitleaks-results.sarif";
    const options = {
      continueOnError: true,
    };

    await artifactClient.uploadArtifact(
      artifactName,
      ["results.sarif"],
      process.env.HOME,
      options
    );
  }

  return exitCode;
}

async function ScanPullRequest(
  gitleaksEnableUploadArtifact,
  octokit,
  eventJSON,
  eventType
) {
  const fullName = eventJSON.repository.full_name;
  const [owner, repo] = fullName.split("/");

  if (!process.env.GITHUB_TOKEN) {
    core.error(
      "🛑 GITHUB_TOKEN is now required to scan pull requests. You can use the automatically created token as shown in the README. For more info, see https://github.com/gitleaks/gitleaks-action#-announcement."
    );
    process.exit(1);
  }

  let commits = await octokit.request(
    "GET /repos/{owner}/{repo}/pulls/{pull_number}/commits",
    {
      owner: owner,
      repo: repo,
      pull_number: eventJSON.number,
    }
  );

  let scanInfo = {
    baseRef: commits.data[0].sha,
    headRef: commits.data[commits.data.length - 1].sha,
  };

  const exitCode = await Scan(
    gitleaksEnableUploadArtifact,
    scanInfo,
    eventType
  );

  if (process.env.GITLEAKS_ENABLE_COMMENTS == "false") {
    core.info("💬 Skipping comments");
    return exitCode;
  }

  if (exitCode == EXIT_CODE_LEAKS_DETECTED) {
    const sarif = JSON.parse(readFileSync("results.sarif", "utf8"));

    for (let i = 0; i < sarif.runs[0].results.length; i++) {
      let results = sarif.runs[0].results[i];
      const commit_sha = results.partialFingerprints.commitSha;
      const fingerprint =
        commit_sha +
        ":" +
        results.locations[0].physicalLocation.artifactLocation.uri +
        ":" +
        results.ruleId +
        ":" +
        results.locations[0].physicalLocation.region.startLine;

      let proposedComment = {
        owner: owner,
        repo: repo,
        pull_number: eventJSON.number,
        body: `🛑 **Gitleaks** has detected a secret with rule-id \`${results.ruleId}\` in commit ${commit_sha}.
If this secret is a _true_ positive, please rotate the secret ASAP.

If this secret is a _false_ positive, you can add the fingerprint below to your \`.gitleaksignore\` file and commit the change to this branch.

\`\`\`
echo ${fingerprint} >> .gitleaksignore
\`\`\`
`,
        commit_id: commit_sha,
        path: results.locations[0].physicalLocation.artifactLocation.uri,
        side: "RIGHT",
        line: results.locations[0].physicalLocation.region.startLine,
      };

      if (process.env.GITLEAKS_NOTIFY_USER_LIST) {
        proposedComment.body += `\n\ncc ${process.env.GITLEAKS_NOTIFY_USER_LIST}`;
      }

      let comments = await octokit.request(
        "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments",
        {
          owner: owner,
          repo: repo,
          pull_number: eventJSON.number,
        }
      );

      let skip = false;
      comments.data.forEach((comment) => {
        if (
          comment.body == proposedComment.body &&
          comment.path == proposedComment.path &&
          comment.original_line == proposedComment.line
        ) {
          skip = true;
          return;
        }
      });

      if (skip == true) {
        continue;
      }

      try {
        await octokit.rest.pulls.createReviewComment(proposedComment);
      } catch (error) {
        core.warning(`⚠️ Failed to write PR comment: ${error}`);
      }
    }
  }

  return exitCode;
}

module.exports.Scan = Scan;
module.exports.Latest = Latest;
module.exports.Install = Install;
module.exports.ScanPullRequest = ScanPullRequest;
module.exports.EXIT_CODE_LEAKS

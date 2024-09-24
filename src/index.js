const { Octokit } = require("@octokit/rest");
const { readFileSync } = require("fs");
const core = require("@actions/core");
const summary = require("./summary.js");
const gitleaks = require("./gitleaks.js");

let gitleaksEnableSummary = true;
if (
  process.env.GITLEAKS_ENABLE_SUMMARY == "false" ||
  process.env.GITLEAKS_ENABLE_SUMMARY == 0
) {
  core.debug("Disabling GitHub Actions Summary.");
  gitleaksEnableSummary = false;
}

let gitleaksEnableUploadArtifact = true;
if (
  process.env.GITLEAKS_ENABLE_UPLOAD_ARTIFACT == "false" ||
  process.env.GITLEAKS_ENABLE_UPLOAD_ARTIFACT == 0
) {
  core.debug("Disabling uploading of results.sarif artifact.");
  gitleaksEnableUploadArtifact = false;
}

// Event JSON example: https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#webhook-payload-example-32
let eventJSON = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));

// Examples of event types: "workflow_dispatch", "push", "pull_request", etc
const eventType = process.env.GITHUB_EVENT_NAME;
const supportedEvents = [
  "push",
  "pull_request",
  "workflow_dispatch",
  "schedule",
];

if (!supportedEvents.includes(eventType)) {
  core.error(`ERROR: The [${eventType}] event is not yet supported`);
  process.exit(1);
}

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN,
  baseUrl: process.env.GITHUB_API_URL,
});

start();

async function start() {

  let exitCode = 0;

  let gitleaksVersion = process.env.GITLEAKS_VERSION || "8.16.1";
  if (gitleaksVersion === "latest") {
    gitleaksVersion = await gitleaks.Latest(octokit);
  }
  core.info("gitleaks version: " + gitleaksVersion);
  let gitleaksPath = await gitleaks.Install(gitleaksVersion);

  // default scanInfo
  let scanInfo = {
    gitleaksPath: gitleaksPath,
  };

  // determine how to run gitleaks based on event type
  core.info("event type: " + eventType);
  if (eventType === "push") {
    // check if eventsJSON.commits is empty, if it is send a info message
    // saying we don't have to run gitleaks
    if (eventJSON.commits.length === 0) {
      core.info("No commits to scan");
      process.exit(0);
    }
    scanInfo = {
      baseRef: eventJSON.commits[0].id,
      headRef: eventJSON.commits[eventJSON.commits.length - 1].id,
    };
    exitCode = await gitleaks.Scan(
      gitleaksEnableUploadArtifact,
      scanInfo,
      eventType
    );
  } else if (eventType === "workflow_dispatch" || eventType === "schedule") {
    exitCode = await gitleaks.Scan(
      gitleaksEnableUploadArtifact,
      scanInfo,
      eventType
    );
  } else if (eventType === "pull_request") {
    exitCode = await gitleaks.ScanPullRequest(
      gitleaksEnableUploadArtifact,
      octokit,
      eventJSON,
      eventType
    );
  }

  // after gitleaks scan, update the job summary
  if (gitleaksEnableSummary == true) {
    await summary.Write(exitCode, eventJSON);
  }

  if (exitCode == 0) {
    core.info("✅ No leaks detected");
  } else if (exitCode == gitleaks.EXIT_CODE_LEAKS_DETECTED) {
    core.warning("🛑 Leaks detected, see job summary for details");
    process.exit(1);
  } else {
    core.error(`ERROR: Unexpected exit code [${exitCode}]`);
    process.exit(exitCode);
  }
}

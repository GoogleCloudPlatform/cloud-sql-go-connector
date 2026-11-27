// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

/**
 * Picks a unique job matching `expectedJobName`, disambiguating multiple
 * matches via active `in_progress` status or `runner_name`.
 *
 * @param {Array<object>} jobs
 * @param {string} expectedJobName
 * @param {string} runnerName
 * @return {object|null}
 */
function pickByName(jobs, expectedJobName, runnerName) {
  const matches = jobs.filter((job) => job.name === expectedJobName);
  if (matches.length === 1) {
    return matches[0];
  }
  if (matches.length > 1) {
    const inProgress = matches.filter((job) => job.status === 'in_progress');
    if (inProgress.length === 1) {
      return inProgress[0];
    }
    if (runnerName) {
      const byRunner = matches.filter((job) => job.runner_name === runnerName);
      if (byRunner.length === 1) {
        return byRunner[0];
      }
    }
  }
  return null;
}

/**
 * Picks a unique job matching `runnerName`, disambiguating reused runner names
 * via active `in_progress` status.
 *
 * @param {Array<object>} jobs
 * @param {string} runnerName
 * @return {object|null}
 */
function pickByRunner(jobs, runnerName) {
  const matches = jobs.filter((job) => job.runner_name === runnerName);
  if (matches.length === 1) {
    return matches[0];
  }
  if (matches.length > 1) {
    const inProgress = matches.filter((job) => job.status === 'in_progress');
    if (inProgress.length === 1) {
      return inProgress[0];
    }
  }
  return null;
}

/**
 * Resolves the GitHub Actions job `html_url` for the currently executing job
 * attempt, falling back to the workflow run URL if lookup fails or is ambiguous.
 *
 * @param {{github: object, context: object, core: object, env: object}} params
 * @return {Promise<string>}
 */
async function resolveJobUrl({ github, context, core, env }) {
  const serverUrl = env.SERVER_URL || 'https://github.com';
  const fallbackUrl =
    env.FALLBACK_URL ||
    `${serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;

  const runId = Number.parseInt(env.RUN_ID || String(context.runId || ''), 10);
  const attemptNumber = Number.parseInt(env.RUN_ATTEMPT || '1', 10);
  if (!Number.isInteger(runId) || runId <= 0 || !Number.isInteger(attemptNumber) || attemptNumber <= 0) {
    core.warning(
      `Invalid run_id (${env.RUN_ID}) or attempt_number (${env.RUN_ATTEMPT}); falling back to ${fallbackUrl}`,
    );
    return fallbackUrl;
  }

  let jobs;
  try {
    const response = await github.paginate(
      github.rest.actions.listJobsForWorkflowRunAttempt,
      {
        owner: context.repo.owner,
        repo: context.repo.repo,
        run_id: runId,
        attempt_number: attemptNumber,
        per_page: 100,
      },
    );
    jobs = Array.isArray(response) ? response : response?.jobs || [];
  } catch (err) {
    core.warning(
      `Failed to list workflow run jobs (${err?.message || err}); falling back to ${fallbackUrl}`,
    );
    return fallbackUrl;
  }

  const expectedJobName = (env.EXPECTED_JOB_NAME || '').trim();
  const runnerName = (env.RUNNER_NAME || '').trim();

  let matched = null;
  if (expectedJobName) {
    matched = pickByName(jobs, expectedJobName, runnerName);
    if (!matched && runnerName) {
      core.warning(
        `Could not uniquely match job by name "${expectedJobName}"; falling back to runner_name "${runnerName}"`,
      );
      matched = pickByRunner(jobs, runnerName);
    }
  } else if (runnerName) {
    matched = pickByRunner(jobs, runnerName);
  }

  if (matched?.html_url) {
    core.info(`Resolved job URL: ${matched.html_url} (job=${matched.name}, id=${matched.id})`);
    return matched.html_url;
  }

  core.warning(
    `Could not uniquely resolve job html_url (expectedJobName=${expectedJobName}, runnerName=${runnerName}, jobCount=${jobs.length}); falling back to ${fallbackUrl}`,
  );
  return fallbackUrl;
}

module.exports = resolveJobUrl;

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

const assert = require('node:assert/strict');
const test = require('node:test');

const resolveJobUrl = require('./resolve-job-url.js');

const SAMPLE_JOBS = [
  {
    id: 138634719639,
    name: 'integration tests (macos-latest)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619412',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634719639',
  },
  {
    id: 138634720285,
    name: 'integration tests (windows-latest)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619066',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720285',
  },
  {
    id: 138634720332,
    name: 'integration tests (ubuntu-latest)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619413',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720332',
  },
  {
    id: 138634720417,
    name: 'unit tests (386, 1.27)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619772',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720417',
  },
  {
    id: 138634720624,
    name: 'unit tests (1.26)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619808',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720624',
  },
  {
    id: 138634720791,
    name: 'unit tests (1.27)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619855',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720791',
  },
  {
    id: 138634720944,
    name: 'unit tests (386, 1.26)',
    status: 'in_progress',
    runner_name: 'GitHub Actions 1073619942',
    html_url: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720944',
  },
];

function makeMocks(jobsOrError) {
  const warnings = [];
  const infos = [];
  let paginateArgs = null;
  const github = {
    rest: {
      actions: {
        listJobsForWorkflowRunAttempt: Symbol('listJobsForWorkflowRunAttempt'),
      },
    },
    paginate: async (endpoint, params) => {
      paginateArgs = { endpoint, params };
      if (jobsOrError instanceof Error) {
        throw jobsOrError;
      }
      return jobsOrError;
    },
  };
  const core = {
    warning: (msg) => warnings.push(msg),
    info: (msg) => infos.push(msg),
  };
  const context = {
    repo: { owner: 'GoogleCloudPlatform', repo: 'cloud-sql-go-connector' },
    runId: 45447365557,
  };
  return { github, core, context, warnings, infos, getPaginateArgs: () => paginateArgs };
}

test('resolves exact integration and unit matrix job URLs', async () => {
  const cases = [
    ['integration tests (windows-latest)', 'GitHub Actions 1073619066', '138634720285'],
    ['integration tests (ubuntu-latest)', 'GitHub Actions 1073619413', '138634720332'],
    ['integration tests (macos-latest)', 'GitHub Actions 1073619412', '138634719639'],
    ['unit tests (1.26)', 'GitHub Actions 1073619808', '138634720624'],
    ['unit tests (386, 1.27)', 'GitHub Actions 1073619772', '138634720417'],
  ];

  for (const [expectedName, runnerName, expectedId] of cases) {
    const { github, core, context, warnings, getPaginateArgs } = makeMocks(SAMPLE_JOBS);
    const url = await resolveJobUrl({
      github,
      context,
      core,
      env: {
        EXPECTED_JOB_NAME: expectedName,
        RUNNER_NAME: runnerName,
        RUN_ID: '45447365557',
        RUN_ATTEMPT: '2',
        FALLBACK_URL: 'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557',
      },
    });
    assert.equal(
      url,
      `https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/${expectedId}`,
    );
    assert.deepEqual(warnings, []);
    assert.deepEqual(getPaginateArgs().params, {
      owner: 'GoogleCloudPlatform',
      repo: 'cloud-sql-go-connector',
      run_id: 45447365557,
      attempt_number: 2,
      per_page: 100,
    });
  }
});

test('warns and falls back to runner_name when expectedJobName does not match', async () => {
  const { github, core, context, warnings } = makeMocks(SAMPLE_JOBS);
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'renamed job (ubuntu-latest)',
      RUNNER_NAME: 'GitHub Actions 1073619413',
      RUN_ID: '45447365557',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(
    url,
    'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720332',
  );
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /falling back to runner_name/);
});

test('disambiguates reused runner_name via in_progress status', async () => {
  const { github, core, context, warnings } = makeMocks([
    {
      id: 1,
      name: 'job A',
      status: 'completed',
      runner_name: 'self-hosted-1',
      html_url: 'https://example.com/job/1',
    },
    {
      id: 2,
      name: 'job B',
      status: 'in_progress',
      runner_name: 'self-hosted-1',
      html_url: 'https://example.com/job/2',
    },
  ]);
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'other name',
      RUNNER_NAME: 'self-hosted-1',
      RUN_ID: '45447365557',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(url, 'https://example.com/job/2');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /falling back to runner_name/);
});

test('disambiguates duplicate job names via runner_name', async () => {
  const { github, core, context, warnings } = makeMocks([
    {
      id: 1,
      name: 'dup',
      status: 'in_progress',
      runner_name: 'r1',
      html_url: 'https://example.com/job/1',
    },
    {
      id: 2,
      name: 'dup',
      status: 'in_progress',
      runner_name: 'r2',
      html_url: 'https://example.com/job/2',
    },
  ]);
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'dup',
      RUNNER_NAME: 'r2',
      RUN_ID: '45447365557',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(url, 'https://example.com/job/2');
  assert.deepEqual(warnings, []);
});

test('falls back to workflow run URL on API error', async () => {
  const { github, core, context, warnings } = makeMocks(new Error('rate limit exceeded'));
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'integration tests (ubuntu-latest)',
      RUNNER_NAME: 'GitHub Actions 1073619413',
      RUN_ID: '45447365557',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(url, 'https://example.com/fallback');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /rate limit exceeded/);
});

test('falls back to workflow run URL when ambiguous or not found', async () => {
  const { github, core, context, warnings } = makeMocks([
    {
      id: 1,
      name: 'dup',
      status: 'in_progress',
      runner_name: 'r1',
      html_url: 'https://example.com/job/1',
    },
    {
      id: 2,
      name: 'dup',
      status: 'in_progress',
      runner_name: 'r2',
      html_url: 'https://example.com/job/2',
    },
  ]);
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'dup',
      RUNNER_NAME: 'r3',
      RUN_ID: '45447365557',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(url, 'https://example.com/fallback');
  assert.equal(warnings.length, 2);
});

test('falls back cleanly on invalid run ID or attempt', async () => {
  const { github, core, context, warnings } = makeMocks(SAMPLE_JOBS);
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'unit tests (1.26)',
      RUNNER_NAME: 'r1',
      RUN_ID: 'not-a-number',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(url, 'https://example.com/fallback');
  assert.equal(warnings.length, 1);
});

test('supports object { jobs: [...] } response shape defensively', async () => {
  const { github, core, context, warnings } = makeMocks({ jobs: SAMPLE_JOBS });
  const url = await resolveJobUrl({
    github,
    context,
    core,
    env: {
      EXPECTED_JOB_NAME: 'unit tests (1.26)',
      RUNNER_NAME: 'GitHub Actions 1073619808',
      RUN_ID: '45447365557',
      RUN_ATTEMPT: '1',
      FALLBACK_URL: 'https://example.com/fallback',
    },
  });
  assert.equal(
    url,
    'https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/runs/45447365557/job/138634720624',
  );
  assert.deepEqual(warnings, []);
});

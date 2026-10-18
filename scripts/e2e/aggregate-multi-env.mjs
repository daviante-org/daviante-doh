#!/usr/bin/env node
/**
 * Multi-Environment Black-Box API & Protocol Matrix Aggregator for daviante-doh
 *
 * Combines per-environment telemetry from:
 *   - ./test-evidence/container/live-api-metrics.json
 *   - ./test-evidence/kubernetes/live-api-metrics.json
 *   - ./test-evidence/openshift/live-api-metrics.json
 *
 * Generates:
 *   - ./test-evidence/multi-env-matrix.md   (Unified 3-Environment GitHub Step Summary Matrix)
 *   - ./test-evidence/live-api-results.md   (Copy of unified matrix for backwards-compatible CI consumers)
 *   - ./test-evidence/multi-env-metrics.json (Combined machine-readable multi-platform telemetry)
 */

import fs from 'node:fs';
import path from 'node:path';

const ROOT_DIR = path.resolve(process.env.DOH_EVIDENCE_ROOT || 'test-evidence');

const ENV_TARGETS = [
  {
    id: 'container',
    shortLabel: 'Container (Podman/Docker)',
    dir: path.join(ROOT_DIR, 'container'),
  },
  {
    id: 'kubernetes',
    shortLabel: 'Kubernetes (MetalLB LB + Ingress)',
    dir: path.join(ROOT_DIR, 'kubernetes'),
  },
  {
    id: 'openshift',
    shortLabel: 'OpenShift (Route CRD + HAProxy Router)',
    dir: path.join(ROOT_DIR, 'openshift'),
  },
];

function readJsonIfExists(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return null;
  }
}

const loadedEnvs = [];
for (const envSpec of ENV_TARGETS) {
  const metricsPath = path.join(envSpec.dir, 'live-api-metrics.json');
  const clusterPath = path.join(envSpec.dir, 'cluster-telemetry.json');
  const mdPath = path.join(envSpec.dir, 'live-api-results.md');

  const metrics = readJsonIfExists(metricsPath);
  if (!metrics) continue;

  const clusterTelemetry = readJsonIfExists(clusterPath);
  const rawMarkdown = fs.existsSync(mdPath)
    ? fs.readFileSync(mdPath, 'utf8')
    : '';

  loadedEnvs.push({
    ...envSpec,
    metrics,
    clusterTelemetry,
    rawMarkdown,
  });
}

if (loadedEnvs.length === 0) {
  console.error(
    `Error: No per-environment live-api-metrics.json files found under ${ROOT_DIR}`
  );
  process.exit(1);
}

const totalEnvironments = loadedEnvs.length;
const totalTestsExecuted = loadedEnvs.reduce(
  (acc, e) => acc + (e.metrics.summary?.totalTests || 0),
  0
);
const totalPassed = loadedEnvs.reduce(
  (acc, e) => acc + (e.metrics.summary?.passedTests || 0),
  0
);
const totalFailed = totalTestsExecuted - totalPassed;
const overallPassRatePct = Number(
  ((totalPassed / Math.max(totalTestsExecuted, 1)) * 100).toFixed(2)
);

// 1. Build Environment Executive Comparison Rows
const envComparisonRows = loadedEnvs.map((e) => {
  const m = e.metrics;
  const envInfo = m.environment || {};
  const lat = m.summary?.latency || { meanMs: 0, p50Ms: 0, p95Ms: 0, maxMs: 0 };
  const caches = m.cacheTelemetry || m.cacheBenchmarks || [];
  const avgSpeedup =
    caches.length > 0
      ? `${(caches.reduce((s, c) => s + (c.speedupFactor || 0), 0) / caches.length).toFixed(1)}x`
      : 'N/A';
  const fl = m.floodTelemetry || {};
  const floodStr = fl.concurrency
    ? `${fl.http200Count} OK / ${fl.http429Count} 429 (${fl.droppedConnections} drops)`
    : 'N/A';
  const podDist = e.clusterTelemetry?.podDistribution || 'Single-Container (1/1)';

  return {
    id: e.id,
    shortLabel: e.shortLabel,
    name: envInfo.name || e.shortLabel,
    replicas: envInfo.replicaCount || 1,
    loadBalancerMode: envInfo.loadBalancerMode || m.target?.endpoint || 'Direct',
    securityContext: envInfo.securityContext || 'Non-root UID 10001:0',
    passedTests: m.summary.passedTests,
    totalTests: m.summary.totalTests,
    failedTests: m.summary.failedTests,
    passRatePct: m.summary.passRatePct,
    meanMs: lat.meanMs,
    p50Ms: lat.p50Ms,
    p95Ms: lat.p95Ms,
    maxMs: lat.maxMs,
    avgCacheSpeedup: avgSpeedup,
    floodSummary: floodStr,
    podDistribution: podDist,
    verdict: m.summary.failedTests === 0 ? 'PASS' : 'FAIL',
  };
});

// 2. Build Category Comparison Matrix across loaded environments
const allCategoryNames = [
  ...new Set(
    loadedEnvs.flatMap((e) =>
      (e.metrics.categoryMetrics || []).map((c) => c.category)
    )
  ),
];

const categoryComparisonMatrix = allCategoryNames.map((catName) => {
  const perEnv = {};
  let cases = 0;
  for (const e of loadedEnvs) {
    const c = (e.metrics.categoryMetrics || []).find(
      (item) => item.category === catName
    );
    if (c) {
      cases = c.total;
      perEnv[e.id] = {
        passed: c.passed,
        total: c.total,
        meanMs: c.meanMs,
        p50Ms: c.p50Ms,
        p95Ms: c.p95Ms,
        maxMs: c.maxMs,
        verdict: c.verdict,
      };
    }
  }
  return {
    category: catName,
    cases,
    environments: perEnv,
  };
});

// 3. Build DNS Record Type Cross-Environment Matrix
const firstEnvRecords =
  loadedEnvs[0].metrics.recordTypeMatrix ||
  loadedEnvs[0].metrics.recordMatrixMetrics ||
  [];

const recordTypeComparisonMatrix = firstEnvRecords.map((rec) => {
  const perEnv = {};
  let allPass = true;
  for (const e of loadedEnvs) {
    const list =
      e.metrics.recordTypeMatrix || e.metrics.recordMatrixMetrics || [];
    const found = list.find((r) => r.recordType === rec.recordType);
    if (found) {
      if (!found.pass) allPass = false;
      perEnv[e.id] = {
        getStatus: found.getStatus,
        getLatencyMs: found.getLatencyMs,
        postStatus: found.postStatus,
        postLatencyMs: found.postLatencyMs,
        rcode: found.rcode,
        ancount: found.ancount,
        pass: found.pass,
      };
    }
  }
  return {
    recordType: rec.recordType,
    qtype: rec.qtype,
    domain: rec.domain,
    sampleAnswer: rec.sampleAnswer,
    environments: perEnv,
    verdict: allPass ? 'PASS' : 'FAIL',
  };
});

// 4. Write ./test-evidence/multi-env-metrics.json
const multiEnvJson = {
  schemaVersion: '1.0',
  generatedAt: new Date().toISOString(),
  summary: {
    totalEnvironments,
    totalTestsExecuted,
    totalPassed,
    totalFailed,
    overallPassRatePct,
    verdict: totalFailed === 0 ? 'ALL_PASS' : 'FAILED',
  },
  environmentMatrix: envComparisonRows,
  categoryComparisonMatrix,
  recordTypeComparisonMatrix,
  environments: Object.fromEntries(
    loadedEnvs.map((e) => [
      e.id,
      {
        clusterTelemetry: e.clusterTelemetry,
        metrics: e.metrics,
      },
    ])
  ),
};

fs.mkdirSync(ROOT_DIR, { recursive: true });
fs.writeFileSync(
  path.join(ROOT_DIR, 'multi-env-metrics.json'),
  JSON.stringify(multiEnvJson, null, 2),
  'utf8'
);

// 5. Render Unified Multi-Environment Markdown Report
const envTableRowsMd = envComparisonRows
  .map(
    (r) =>
      `| **${r.shortLabel}** | ${r.replicas} | \`${r.loadBalancerMode}\` | \`${r.securityContext}\` | **${r.passedTests}/${r.totalTests}** (${r.passRatePct}%) | \`${r.meanMs.toFixed(2)} ms\` / \`${r.p50Ms.toFixed(2)} ms\` / \`${r.p95Ms.toFixed(2)} ms\` | **${r.avgCacheSpeedup}** | \`${r.floodSummary}\` | \`${r.podDistribution}\` | **${r.verdict}** |`
  )
  .join('\n');

const catHeadersMd = loadedEnvs
  .map((e) => `${e.shortLabel} (\`p50\` / \`p95\` / Verdict)`)
  .join(' | ');
const catAlignMd = loadedEnvs.map(() => ':---:').join(' | ');
const catRowsMd = categoryComparisonMatrix
  .map((c) => {
    const cols = loadedEnvs
      .map((e) => {
        const ce = c.environments[e.id];
        if (!ce) return 'N/A';
        return `\`${ce.p50Ms.toFixed(2)} ms\` / \`${ce.p95Ms.toFixed(2)} ms\` (**${ce.passed}/${ce.total} ${ce.verdict}**)`;
      })
      .join(' | ');
    return `| ${c.category} | ${c.cases} | ${cols} |`;
  })
  .join('\n');

const rrHeadersMd = loadedEnvs
  .map((e) => `${e.shortLabel} (\`GET\` / \`POST\`)`)
  .join(' | ');
const rrAlignMd = loadedEnvs.map(() => ':---:').join(' | ');
const rrRowsMd = recordTypeComparisonMatrix
  .map((r) => {
    const cols = loadedEnvs
      .map((e) => {
        const re = r.environments[e.id];
        if (!re) return 'N/A';
        return `**${re.getStatus}** (\`${re.getLatencyMs.toFixed(2)}ms\`) / **${re.postStatus}** (\`${re.postLatencyMs.toFixed(2)}ms\`)`;
      })
      .join(' | ');
    return `| \`${r.recordType}\` (${r.qtype}) | \`${r.domain}\` | ${cols} | \`${r.sampleAnswer.replace(/\|/g, '\\|')}\` | **${r.verdict}** |`;
  })
  .join('\n');

const detailsSectionsMd = loadedEnvs
  .map(
    (e) => `<details>
<summary><strong>📄 Expand Full 73-Case Evidence Report — ${e.shortLabel} (${e.metrics.summary.passedTests}/${e.metrics.summary.totalTests} PASSED)</strong></summary>

${e.rawMarkdown}

</details>`
  )
  .join('\n\n');

const unifiedMd = `# Multi-Environment Black-Box API & Protocol Matrix (\`daviante-doh\`)

- **Environments Verified:** **${totalEnvironments}** (${loadedEnvs.map((e) => `\`${e.shortLabel}\``).join(', ')})
- **Total Live Protocol Tests Executed:** **${totalPassed}/${totalTestsExecuted} PASSED (${overallPassRatePct}% Pass Rate, ${totalFailed} FAILED)**
- **Generated Timestamp:** \`${multiEnvJson.generatedAt}\`

---

## 1. Executive 3-Environment Comparison Matrix (Container vs. Kubernetes LB vs. OpenShift Router)

| Platform Environment | Replicas | Load Balancer & Routing Topology | Security Context | Pass Rate | Latency (\`mean\` / \`p50\` / \`p95\`) | Cache Hit Speedup | 500-Request Flood Telemetry | Multi-Replica Traffic Distribution | Verdict |
| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :--- | :--- | :---: |
${envTableRowsMd}

---

## 2. Category Latency Matrix Across Environments

| Test Category | Cases / Env | ${catHeadersMd} |
| :--- | :---: | ${catAlignMd} |
${catRowsMd}

---

## 3. DNS Record Type Matrix Across Environments (HTTP/2 \`GET\` vs. \`POST\`)

| Record Type | Query Domain | ${rrHeadersMd} | Decoded Wire Answer Sample | Verdict |
| :--- | :--- | ${rrAlignMd} | :--- | :---: |
${rrRowsMd}

---

## 4. Per-Environment Detailed Evidence Logs (73 Cases Each)

${detailsSectionsMd}
`;

fs.writeFileSync(path.join(ROOT_DIR, 'multi-env-matrix.md'), unifiedMd, 'utf8');
fs.writeFileSync(path.join(ROOT_DIR, 'live-api-results.md'), unifiedMd, 'utf8');

console.log(
  `==> Wrote Unified Multi-Environment Matrix (${totalPassed}/${totalTestsExecuted} PASSED across ${totalEnvironments} environments):`
);
console.log(`  - ${path.join(ROOT_DIR, 'multi-env-matrix.md')}`);
console.log(`  - ${path.join(ROOT_DIR, 'multi-env-metrics.json')}`);

if (totalFailed > 0) {
  process.exitCode = 1;
}

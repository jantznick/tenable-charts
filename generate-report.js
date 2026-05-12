import 'dotenv/config';
import puppeteer from 'puppeteer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Read and parse the JSON file
function loadFindings(jsonPath) {
  try {
    const data = fs.readFileSync(jsonPath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error instanceof SyntaxError) {
      // Try to provide more helpful error information
      const data = fs.readFileSync(jsonPath, 'utf8');
      const position = error.message.match(/position (\d+)/);
      if (position) {
        const pos = parseInt(position[1]);
        const start = Math.max(0, pos - 100);
        const end = Math.min(data.length, pos + 100);
        const snippet = data.substring(start, end);
        const lineNumber = data.substring(0, pos).split('\n').length;
        console.error(`\nJSON Parse Error at line ${lineNumber}, position ${pos}:`);
        console.error(`Context: ...${snippet}...`);
      }
    }
    throw error;
  }
}

const DEFAULT_TENABLE_BASE_URL = 'https://cloud.tenable.com';
// WAS v2: https://developer.tenable.com/reference/was-v2-vulns-search
const WAS_VULNS_SEARCH_PATH = '/was/v2/vulnerabilities/search';
const WAS_MAX_PAGE_LIMIT = 200;

function parseCliArgs(argv) {
  const args = argv.slice(2);
  const options = {
    mode: 'file',
    jsonPath: null,
    outputDir: null,
    saveJsonPath: null,
    company: null,
    configPath: 'tenable-presets.json',
    sinceDays: null
  };

  // Backward compatible usage:
  // node generate-report.js <jsonFile> <outputDirectory>
  if (args.length === 2 && !args[0].startsWith('--') && !args[1].startsWith('--')) {
    return {
      ...options,
      mode: 'file',
      jsonPath: args[0],
      outputDir: args[1]
    };
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json') {
      options.mode = 'file';
      options.jsonPath = args[i + 1];
      i++;
    } else if (arg === '--output') {
      options.outputDir = args[i + 1];
      i++;
    } else if (arg === '--save-json') {
      options.saveJsonPath = args[i + 1];
      i++;
    } else if (arg === '--since-days') {
      const parsed = Number.parseInt(args[i + 1], 10);
      if (!Number.isNaN(parsed) && parsed >= 0) {
        options.sinceDays = parsed;
      }
      i++;
    } else if (arg === '--company') {
      options.mode = 'was';
      options.company = args[i + 1];
      i++;
    } else if (arg === '--config') {
      options.configPath = args[i + 1];
      i++;
    }
  }

  return options;
}

function loadCompanyUuidMap(configPath) {
  const cfgPath = path.isAbsolute(configPath) ? configPath : path.join(__dirname, configPath);
  if (!fs.existsSync(cfgPath)) {
    throw new Error(`Company config not found: ${cfgPath}`);
  }
  const raw = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Company config must be a JSON object: { "Company A": "<uuid>", ... }');
  }
  return raw;
}

function resolveCompanyUuid(companyMap, companyName) {
  if (companyMap[companyName] != null) {
    return String(companyMap[companyName]).trim();
  }
  const lower = companyName.toLowerCase();
  for (const [k, v] of Object.entries(companyMap)) {
    if (k.toLowerCase() === lower) {
      return String(v).trim();
    }
  }
  const keys = Object.keys(companyMap);
  throw new Error(
    `Company "${companyName}" not found in config. Available: ${keys.length ? keys.join(', ') : '(none)'}`
  );
}

function isoDaysAgo(days) {
  const d = days != null && !Number.isNaN(days) ? days : 30;
  return new Date(Date.now() - d * 24 * 60 * 60 * 1000).toISOString();
}

/**
 * Build POST body for WAS vulnerabilities search (field/operator/value filters).
 * Field names/operators must match your tenant — list via GET /was/v2/vulnerabilities/filters.
 * Override defaults with TENABLE_WAS_* env vars or TENABLE_WAS_SEARCH_BODY_JSON for a full body.
 */
function buildWasVulnerabilitySearchBody(companyTagUuid, cliSinceDays) {
  const custom = process.env.TENABLE_WAS_SEARCH_BODY_JSON;
  if (custom && custom.trim().startsWith('{')) {
    return JSON.parse(custom);
  }

  const tagField = process.env.TENABLE_WAS_TAG_FIELD || 'tag';
  const tagOp = process.env.TENABLE_WAS_TAG_OPERATOR || 'eq';
  const dateField = process.env.TENABLE_WAS_DATE_FIELD || 'created_at';
  const dateOp = process.env.TENABLE_WAS_DATE_OPERATOR || 'gte';
  const sevField = process.env.TENABLE_WAS_SEVERITY_FIELD || 'severity';
  const sevOp = process.env.TENABLE_WAS_SEVERITY_OPERATOR || 'neq';
  const sevInfo = process.env.TENABLE_WAS_SEVERITY_INFO_VALUE || 'info';

  const envSinceDays =
    process.env.TENABLE_WAS_SINCE_DAYS != null && process.env.TENABLE_WAS_SINCE_DAYS !== ''
      ? Number.parseInt(process.env.TENABLE_WAS_SINCE_DAYS, 10)
      : null;

  let days = 30;
  if (cliSinceDays != null && !Number.isNaN(cliSinceDays) && cliSinceDays >= 0) {
    days = cliSinceDays;
  } else if (Number.isFinite(envSinceDays) && envSinceDays >= 0) {
    days = envSinceDays;
  }

  const andFilters = [
    { field: tagField, operator: tagOp, value: companyTagUuid },
    { field: dateField, operator: dateOp, value: isoDaysAgo(days) },
    { field: sevField, operator: sevOp, value: sevInfo }
  ];

  const extra = process.env.TENABLE_WAS_EXTRA_FILTERS_JSON;
  if (extra && extra.trim().startsWith('[')) {
    const parsed = JSON.parse(extra);
    if (Array.isArray(parsed)) {
      andFilters.push(...parsed);
    }
  }

  return { AND: andFilters };
}

function wasSeverityToNumeric(item) {
  if (typeof item.severity === 'number' && item.severity >= 0 && item.severity <= 4) {
    return item.severity;
  }
  const s = item.severity ?? item.severity_level ?? item.risk;
  if (typeof s === 'number' && s >= 0 && s <= 4) {
    return s;
  }
  const map = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const key = s != null ? String(s).toLowerCase() : '';
  if (map[key] !== undefined) {
    return map[key];
  }
  return 2;
}

function wasVulnerabilityToFinding(item, companyName, companyUuid) {
  const uri = item.uri || '';
  let host = 'Unknown';
  try {
    host = new URL(uri).hostname || uri;
  } catch {
    host = uri || 'Unknown';
  }

  const sev = wasSeverityToNumeric(item);
  const created = item.created_at || item.detected_at;
  const age =
    created != null
      ? Math.max(0, Math.floor((Date.now() - new Date(created).getTime()) / (24 * 60 * 60 * 1000)))
      : 0;

  return {
    finding_id: item.vuln_id || item.id,
    id: item.vuln_id || item.id,
    asset_name: host,
    severity: sev,
    risk_modified: 'NONE',
    state: 'NEW',
    first_observed: created,
    last_seen: created,
    age_in_days: age,
    output: item.details?.output ?? '',
    definition: {
      name: item.plugin_name || item.name || `WAS plugin ${item.plugin_id ?? ''}`.trim(),
      family: 'Web Application Scanning',
      severity: sev,
      references: [],
      cvss3:
        item.cvss3 != null
          ? item.cvss3
          : item.cvss_base_score != null
            ? { base_score: Number(item.cvss_base_score) }
            : {}
    },
    asset: {
      id: item.scan_id,
      name: host,
      tags: [
        { category: 'Company', value: companyName },
        { category: 'CompanyTagUuid', value: companyUuid }
      ]
    }
  };
}

async function tenableRequest(baseUrl, requestPath, accessKey, secretKey, options = {}) {
  const url = `${baseUrl}${requestPath}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      'X-ApiKeys': `accessKey=${accessKey}; secretKey=${secretKey}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `Tenable API request failed (${response.status} ${response.statusText}) at ${requestPath}: ${body}`
    );
  }

  return response.json();
}

async function fetchWasVulnerabilitySearchPage(baseUrl, accessKey, secretKey, body, limit, offset) {
  const qs = new URLSearchParams({
    limit: String(limit),
    offset: String(offset)
  });
  const pathWithQuery = `${WAS_VULNS_SEARCH_PATH}?${qs.toString()}`;
  return tenableRequest(baseUrl, pathWithQuery, accessKey, secretKey, {
    method: 'POST',
    body: JSON.stringify(body)
  });
}

async function loadFindingsFromWasSearch(options) {
  const accessKey = process.env.TENABLE_ACCESS_KEY;
  const secretKey = process.env.TENABLE_SECRET_KEY;
  const baseUrl = process.env.TENABLE_BASE_URL || DEFAULT_TENABLE_BASE_URL;

  if (!accessKey || !secretKey) {
    throw new Error(
      'Missing Tenable credentials. Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env (see .env.example) or the environment.'
    );
  }

  const companyMap = loadCompanyUuidMap(options.configPath);
  const companyUuid = resolveCompanyUuid(companyMap, options.company);
  const searchBody = buildWasVulnerabilitySearchBody(companyUuid, options.sinceDays);

  const limit = Math.min(
    WAS_MAX_PAGE_LIMIT,
    Math.max(
      1,
      Number.parseInt(process.env.TENABLE_WAS_PAGE_LIMIT || String(WAS_MAX_PAGE_LIMIT), 10) || WAS_MAX_PAGE_LIMIT
    )
  );

  console.log(`POST ${baseUrl}${WAS_VULNS_SEARCH_PATH} (paginated, limit=${limit})`);
  console.log('Request body:', JSON.stringify(searchBody, null, 2));

  const allItems = [];
  let offset = 0;
  let total = null;

  for (;;) {
    const page = await fetchWasVulnerabilitySearchPage(
      baseUrl,
      accessKey,
      secretKey,
      searchBody,
      limit,
      offset
    );
    const items = Array.isArray(page.items) ? page.items : [];
    if (page.pagination && typeof page.pagination.total === 'number') {
      total = page.pagination.total;
    }
    allItems.push(...items);
    console.log(
      `Fetched WAS vulnerabilities: offset=${offset}, pageSize=${items.length}, totalSoFar=${allItems.length}` +
        (total != null ? `, reportedTotal=${total}` : '')
    );

    if (items.length === 0) {
      break;
    }
    if (total != null && allItems.length >= total) {
      break;
    }
    if (items.length < limit) {
      break;
    }
    offset += limit;
  }

  const findings = allItems.map((item) =>
    wasVulnerabilityToFinding(item, options.company, companyUuid)
  );

  if (options.saveJsonPath) {
    const savePath = path.isAbsolute(options.saveJsonPath)
      ? options.saveJsonPath
      : path.join(__dirname, options.saveJsonPath);
    fs.writeFileSync(savePath, JSON.stringify(findings, null, 2));
    console.log(`Saved mapped findings to: ${savePath}`);
  }

  return findings;
}

// Process findings data for charts
function processData(findings) {
  const data = {
    severityCounts: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 },
    familyCounts: {},
    stateCounts: {},
    assetCounts: {},
    vprScores: [],
    ageInDays: [],
    cvss3Scores: [],
    topVulnerabilities: {},
    owasp2021: {},
    owasp2017: {},
    cweCounts: {},
    riskModifiedCounts: {},
    wascCounts: {},
    complianceFrameworks: {
      hipaa: 0,
      pci_dss: 0,
      iso: 0,
      nist: 0,
      disa_stig: 0
    },
    cvssSeverityCounts: { None: 0, Low: 0, Medium: 0, High: 0, Critical: 0 },
    assetSeverityBreakdown: {},
    assetExposure: { Public: 0, Private: 0 },
    assetSourceCounts: {},
    externalExposureCounts: {},
    assetVprScores: {},
    criticalHighByAsset: {},
    findingsByMonth: {}
  };

  // OWASP 2021 mapping
  const owasp2021Map = {
    'A1': 'A01:2021 - Broken Access Control',
    'A2': 'A02:2021 - Cryptographic Failures',
    'A3': 'A03:2021 - Injection',
    'A4': 'A04:2021 - Insecure Design',
    'A5': 'A05:2021 - Security Misconfiguration',
    'A6': 'A06:2021 - Vulnerable Components',
    'A7': 'A07:2021 - Auth Failures',
    'A8': 'A08:2021 - Software/Data Integrity',
    'A9': 'A09:2021 - Logging/Monitoring Failures',
    'A10': 'A10:2021 - SSRF'
  };

  // OWASP 2017 mapping
  const owasp2017Map = {
    'A1': 'A1:2017 - Injection',
    'A2': 'A2:2017 - Broken Authentication',
    'A3': 'A3:2017 - Sensitive Data Exposure',
    'A4': 'A4:2017 - XXE',
    'A5': 'A5:2017 - Broken Access Control',
    'A6': 'A6:2017 - Security Misconfiguration',
    'A7': 'A7:2017 - XSS',
    'A8': 'A8:2017 - Insecure Deserialization',
    'A9': 'A9:2017 - Known Vulnerabilities',
    'A10': 'A10:2017 - Insufficient Logging'
  };

  findings.forEach(finding => {
    // Severity distribution
    const severity = finding.severity || 0;
    data.severityCounts[severity] = (data.severityCounts[severity] || 0) + 1;

    // Family distribution
    const family = finding.definition?.family || 'Unknown';
    data.familyCounts[family] = (data.familyCounts[family] || 0) + 1;

    // State distribution
    const state = finding.state || 'Unknown';
    data.stateCounts[state] = (data.stateCounts[state] || 0) + 1;

    // Asset distribution
    const assetName = finding.asset_name || 'Unknown';
    data.assetCounts[assetName] = (data.assetCounts[assetName] || 0) + 1;

    // VPR scores
    if (finding.vpr) {
      data.vprScores.push(finding.vpr);
    }

    // Age in days
    if (finding.age_in_days !== undefined) {
      data.ageInDays.push(finding.age_in_days);
    }

    // CVSS3 scores and severity
    if (finding.definition?.cvss3?.base_score !== undefined) {
      const score = finding.definition.cvss3.base_score;
      data.cvss3Scores.push(score);
      
      // Categorize CVSS severity
      if (score === 0) data.cvssSeverityCounts.None++;
      else if (score < 4.0) data.cvssSeverityCounts.Low++;
      else if (score < 7.0) data.cvssSeverityCounts.Medium++;
      else if (score < 9.0) data.cvssSeverityCounts.High++;
      else data.cvssSeverityCounts.Critical++;
    }

    // Top vulnerabilities by name
    const vulnName = finding.definition?.name || 'Unknown';
    data.topVulnerabilities[vulnName] = (data.topVulnerabilities[vulnName] || 0) + 1;

    // Risk modification status
    const riskModified = finding.risk_modified || 'NONE';
    data.riskModifiedCounts[riskModified] = (data.riskModifiedCounts[riskModified] || 0) + 1;

    // Process references
    if (finding.definition?.references) {
      finding.definition.references.forEach(ref => {
        // OWASP 2021
        if (ref.type === 'owasp_2021' && ref.ids && ref.ids.length > 0) {
          ref.ids.forEach(id => {
            const label = owasp2021Map[id] || `A${id}:2021`;
            data.owasp2021[label] = (data.owasp2021[label] || 0) + 1;
          });
        }

        // OWASP 2017
        if (ref.type === 'owasp_2017' && ref.ids && ref.ids.length > 0) {
          ref.ids.forEach(id => {
            const label = owasp2017Map[id] || `A${id}:2017`;
            data.owasp2017[label] = (data.owasp2017[label] || 0) + 1;
          });
        }

        // CWE
        if (ref.type === 'cwe' && ref.ids && ref.ids.length > 0) {
          ref.ids.forEach(id => {
            const cweId = `CWE-${id}`;
            data.cweCounts[cweId] = (data.cweCounts[cweId] || 0) + 1;
          });
        }

        // WASC
        if (ref.type === 'wasc' && ref.ids && ref.ids.length > 0) {
          ref.ids.forEach(id => {
            data.wascCounts[id] = (data.wascCounts[id] || 0) + 1;
          });
        }

        // Compliance frameworks
        if (ref.type === 'hipaa' && ref.ids && ref.ids.length > 0) {
          data.complianceFrameworks.hipaa++;
        }
        if (ref.type === 'pci_dss' && ref.ids && ref.ids.length > 0) {
          data.complianceFrameworks.pci_dss++;
        }
        if (ref.type === 'iso' && ref.ids && ref.ids.length > 0) {
          data.complianceFrameworks.iso++;
        }
        if (ref.type === 'nist' && ref.ids && ref.ids.length > 0) {
          data.complianceFrameworks.nist++;
        }
        if (ref.type === 'disa_stig' && ref.ids && ref.ids.length > 0) {
          data.complianceFrameworks.disa_stig++;
        }
      });
    }

    // High-level asset reporting (reusing assetName and severity from above)
    // Asset severity breakdown
    if (!data.assetSeverityBreakdown[assetName]) {
      data.assetSeverityBreakdown[assetName] = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
    }
    data.assetSeverityBreakdown[assetName][severity]++;

    // Critical/High by asset
    if (severity >= 3) {
      data.criticalHighByAsset[assetName] = (data.criticalHighByAsset[assetName] || 0) + 1;
    }

    // Asset VPR scores (for average calculation)
    if (finding.vpr) {
      if (!data.assetVprScores[assetName]) {
        data.assetVprScores[assetName] = [];
      }
      data.assetVprScores[assetName].push(finding.vpr);
    }

    // Asset exposure (Public vs Private)
    if (finding.asset?.tags) {
      const publicTag = finding.asset.tags.find(t => t.category === 'Public');
      if (publicTag) {
        if (publicTag.value === 'TRUE') {
          data.assetExposure.Public++;
        } else {
          data.assetExposure.Private++;
        }
      }

      // Asset source
      const sourceTag = finding.asset.tags.find(t => t.category === 'Asset Source');
      if (sourceTag && sourceTag.value) {
        data.assetSourceCounts[sourceTag.value] = (data.assetSourceCounts[sourceTag.value] || 0) + 1;
      }

      // External exposure
      const externalTag = finding.asset.tags.find(t => t.category === 'External Exposure');
      if (externalTag) {
        const exposure = externalTag.value === 'TRUE' ? 'Exposed' : 'Internal';
        data.externalExposureCounts[exposure] = (data.externalExposureCounts[exposure] || 0) + 1;
      }
    }

    // Findings by month
    if (finding.first_observed) {
      const date = new Date(finding.first_observed);
      const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
      data.findingsByMonth[monthKey] = (data.findingsByMonth[monthKey] || 0) + 1;
    }
  });

  return data;
}

/**
 * @param {object} [layout]
 * @param {number} [layout.chartContainerHeightPx] - fixed plot area height (use for horizontal bars so few categories do not leave a tall empty canvas)
 * @param {boolean} [layout.omitTitle] - when true, chart PNG has no title bar (title lives on the slide / elsewhere)
 */
function generateChartHTML(title, chartConfig, width = 1400, height = 1200, layout = {}) {
  const omitTitle = Boolean(layout.omitTitle);
  const chartContainerPx =
    layout.chartContainerHeightPx != null && Number.isFinite(layout.chartContainerHeightPx)
      ? Math.max(120, Math.floor(layout.chartContainerHeightPx))
      : Math.floor(height * 0.6);
  const wrapperPadding = omitTitle ? '10px 14px 14px' : '12px 16px 16px';
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.2.0/dist/chartjs-plugin-datalabels.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        html {
            height: fit-content;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: white;
            padding: 12px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: flex-start;
            min-height: 0;
            margin: 0 auto;
        }
        .chart-wrapper {
            background: white;
            padding: ${wrapperPadding};
            width: ${width}px;
            max-width: ${width}px;
            box-sizing: border-box;
        }
        .chart-title {
            font-size: 2.2em;
            font-weight: 600;
            color: #333;
            margin-bottom: 20px;
            text-align: center;
            padding-bottom: 12px;
            border-bottom: 3px solid #667eea;
        }
        .chart-container {
            position: relative;
            height: ${chartContainerPx}px;
            width: 100%;
            margin-bottom: 0;
        }
        canvas {
            max-width: 100%;
            max-height: 100%;
        }
    </style>
</head>
<body>
    <div class="chart-wrapper">
        ${omitTitle ? '' : `<div class="chart-title">${title}</div>`}
        <div class="chart-container">
            <canvas id="chart"></canvas>
        </div>
    </div>
    <script>
        Chart.register(ChartDataLabels);
        const config = ${JSON.stringify(chartConfig, null, 8)};
        new Chart(document.getElementById('chart'), config);
    </script>
</body>
</html>`;
}

/**
 * Pixel budget for horizontal bar chart: full hostnames (no ellipsis), no left clip.
 * leftPad is Chart.js layout padding; outer width must leave room for bars + value axis + datalabels.
 */
function buildTopAssetsChartLayout(topAssets) {
  const labels = topAssets.map((a) => a[0]);
  const counts = topAssets.map((a) => a[1]);
  const maxLabelLen = labels.reduce((m, s) => Math.max(m, String(s).length), 0);
  const maxCount = counts.length ? Math.max(...counts) : 0;
  const rightPad = Math.max(48, Math.round(16 + String(maxCount).length * 16));
  const wrapperCssHorizontal = 36;
  const outerW = Math.min(
    2000,
    Math.max(820, Math.round(520 + maxLabelLen * 10.8 + rightPad + wrapperCssHorizontal))
  );

  return { labels, counts, rightPad, outerW };
}

function buildTopAssetsChartConfig(layout) {
  const { labels, counts, rightPad } = layout;

  return {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Vulnerability Count',
          data: counts,
          backgroundColor: 'rgba(240, 147, 251, 0.8)',
          borderColor: 'rgba(240, 147, 251, 1)',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      clip: false,
      animation: {
        duration: 0
      },
      plugins: {
        legend: {
          display: false
        },
        datalabels: {
          anchor: 'end',
          align: 'end',
          color: '#333',
          clip: false,
          font: {
            weight: 'bold',
            size: 18
          },
          padding: 6,
          offset: 2
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: {
            stepSize: 1,
            maxRotation: 0,
            minRotation: 0,
            font: {
              size: 16,
              weight: 'bold'
            },
            padding: 10
          },
          title: {
            display: true,
            font: {
              size: 18,
              weight: 'bold'
            },
            padding: 12
          }
        },
        y: {
          ticks: {
            autoSkip: false,
            font: {
              size: 16,
              weight: 'bold'
            },
            padding: 4
          }
        }
      },
      layout: {
        padding: {
          top: 12,
          bottom: 18,
          left: 8,
          right: rightPad
        }
      }
    }
  };
}

// Prepare chart export (top assets / chart 6 only)
function prepareCharts(processedData) {
  const topAssets = Object.entries(processedData.assetCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const barRows = Math.min(topAssets.length, 10);
  const layout = buildTopAssetsChartLayout(topAssets);

  return [
    {
      filename: '06-top-10-assets.png',
      title: 'Top 10 Assets by Vulnerability Count',
      html: generateChartHTML(
        'Top 10 Assets by Vulnerability Count',
        buildTopAssetsChartConfig(layout),
        layout.outerW,
        1000,
        {
          chartContainerHeightPx: Math.max(200, 64 + barRows * 46),
          omitTitle: true
        }
      )
    }
  ];
}

// Generate screenshot of a single chart
async function generateChartImage(browser, chart, outputDir) {
  const tempHtmlPath = path.join(__dirname, `temp-${chart.filename.replace('.png', '.html')}`);
  const outputPath = path.join(outputDir, chart.filename);

  try {
    // Write HTML to temp file
    fs.writeFileSync(tempHtmlPath, chart.html);

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 2400 });

    await page.goto(`file://${tempHtmlPath}`, {
      waitUntil: 'networkidle0'
    });

    // Wait for charts to render
    await new Promise(resolve => setTimeout(resolve, 2000));

    const selector = '.chart-wrapper';
    const handle = await page.$(selector);
    if (!handle) {
      throw new Error(`Screenshot target not found: ${selector} (${chart.filename})`);
    }
    await handle.screenshot({
      path: outputPath,
      type: 'png'
    });

    await page.close();
    console.log(`✓ Generated: ${chart.filename}`);
  } finally {
    // Clean up temp file
    if (fs.existsSync(tempHtmlPath)) {
      fs.unlinkSync(tempHtmlPath);
    }
  }
}

// Main function
async function generateReport(options) {
  let findings;
  if (options.mode === 'was') {
    findings = await loadFindingsFromWasSearch(options);
  } else {
    console.log('Loading findings from:', options.jsonPath);
    findings = loadFindings(options.jsonPath);
  }
  
  console.log(`Processing ${findings.length} findings...`);
  const processedData = processData(findings);
  
  // Create output directory if it doesn't exist
  const outputDir = options.outputDir;
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
    console.log(`Created output directory: ${outputDir}`);
  }
  
  console.log('Preparing charts...');
  const charts = prepareCharts(processedData);
  
  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  try {
    console.log(`Generating ${charts.length} chart images...\n`);
    
    // Generate each chart
    for (const chart of charts) {
      await generateChartImage(browser, chart, outputDir);
    }
    
    console.log(`\n✓ Successfully generated ${charts.length} PNG files in: ${outputDir}`);
  } finally {
    await browser.close();
  }
}

// Run if called directly
const cliOptions = parseCliArgs(process.argv);

if (
  !cliOptions.outputDir ||
  (cliOptions.mode === 'file' && !cliOptions.jsonPath) ||
  (cliOptions.mode === 'was' && !cliOptions.company)
) {
  console.error('Usage (file mode):  node generate-report.js <jsonFile> <outputDirectory>');
  console.error(
    'Usage (WAS mode):    node generate-report.js --output <dir> --company <name> [--config tenable-presets.json] [--since-days 30] [--save-json <path>]'
  );
  console.error(
    'WAS API: POST https://cloud.tenable.com/was/v2/vulnerabilities/search — see https://developer.tenable.com/reference/was-v2-vulns-search'
  );
  console.error('Credentials: copy .env.example to .env and set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY.');
  console.error('Companies:   JSON map of company name -> tag UUID in tenable-presets.json (see tenable-presets.example.json).');
  console.error('Example (WAS):  node generate-report.js --output ./charts --company "Company A"');
  console.error('Example (file): node generate-report.js december.json ./output');
  process.exit(1);
}

generateReport(cliOptions).catch(error => {
  console.error('Error generating report:', error);
  process.exit(1);
});

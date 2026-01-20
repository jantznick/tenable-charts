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

// Generate HTML for a single chart
function generateChartHTML(title, chartConfig, width = 1400, height = 1200) {
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
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: white;
            padding: 50px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .chart-wrapper {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            width: 100%;
            max-width: ${width}px;
        }
        .chart-title {
            font-size: 2.2em;
            font-weight: 600;
            color: #333;
            margin-bottom: 30px;
            text-align: center;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
        }
        .chart-container {
            position: relative;
            height: ${Math.floor(height * 0.6)}px;
            width: 100%;
            margin-bottom: 20px;
        }
        .legend-container {
            min-height: ${Math.floor(height * 0.4)}px;
            width: 100%;
            padding: 20px 0;
        }
        canvas {
            max-width: 100%;
            max-height: 100%;
        }
    </style>
</head>
<body>
    <div class="chart-wrapper">
        <div class="chart-title">${title}</div>
        <div class="chart-container">
            <canvas id="chart"></canvas>
        </div>
        <div class="legend-container" id="legend-container"></div>
    </div>
    <script>
        Chart.register(ChartDataLabels);
        const config = ${JSON.stringify(chartConfig, null, 8)};
        new Chart(document.getElementById('chart'), config);
    </script>
</body>
</html>`;
}

// Generate HTML for stats summary
function generateStatsHTML(processedData) {
  const totalFindings = Object.values(processedData.severityCounts).reduce((a, b) => a + b, 0);
  const avgVpr = processedData.vprScores.length > 0 
    ? (processedData.vprScores.reduce((a, b) => a + b, 0) / processedData.vprScores.length).toFixed(2)
    : 'N/A';
  const uniqueAssets = Object.keys(processedData.assetCounts).length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Summary Statistics</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            padding: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-width: 1200px;
            width: 100%;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-align: center;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card.info { background: linear-gradient(135deg, #17a2b8 0%, #138496 100%); }
        .stat-card.low { background: linear-gradient(135deg, #28a745 0%, #218838 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); }
        .stat-card.high { background: linear-gradient(135deg, #fd7e14 0%, #dc6502 100%); }
        .stat-card.critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .stat-label {
            font-size: 1.1em;
            opacity: 0.95;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Tenable Vulnerability Report - Summary</h1>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">${totalFindings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value">${processedData.severityCounts[0] || 0}</div>
                <div class="stat-label">Info</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">${processedData.severityCounts[1] || 0}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">${processedData.severityCounts[2] || 0}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">${processedData.severityCounts[3] || 0}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">${processedData.severityCounts[4] || 0}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${uniqueAssets}</div>
                <div class="stat-label">Unique Assets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${avgVpr}</div>
                <div class="stat-label">Avg VPR Score</div>
            </div>
        </div>
    </div>
</body>
</html>`;
}

// Prepare all chart configurations
function prepareCharts(processedData) {
  const severityLabels = ['Info', 'Low', 'Medium', 'High', 'Critical'];
  const severityColors = ['#17a2b8', '#28a745', '#ffc107', '#fd7e14', '#dc3545'];
  
  // Sort top vulnerabilities
  const topVulns = Object.entries(processedData.topVulnerabilities)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Sort top assets
  const topAssets = Object.entries(processedData.assetCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Sort families
  const families = Object.entries(processedData.familyCounts)
    .sort((a, b) => b[1] - a[1]);

  // Create VPR bins
  const vprBins = [0, 2, 4, 6, 8, 10];
  const vprDistribution = new Array(vprBins.length - 1).fill(0);
  processedData.vprScores.forEach(score => {
    for (let i = 0; i < vprBins.length - 1; i++) {
      if (score >= vprBins[i] && score < vprBins[i + 1]) {
        vprDistribution[i]++;
        break;
      }
    }
    if (score >= vprBins[vprBins.length - 1]) {
      vprDistribution[vprBins.length - 2]++;
    }
  });

  // Create age bins
  const ageBins = [0, 7, 30, 90, 180, 365, Infinity];
  const ageLabels = ['0-7 days', '8-30 days', '31-90 days', '91-180 days', '181-365 days', '365+ days'];
  const ageDistribution = new Array(ageBins.length - 1).fill(0);
  processedData.ageInDays.forEach(age => {
    for (let i = 0; i < ageBins.length - 1; i++) {
      if (age >= ageBins[i] && age < ageBins[i + 1]) {
        ageDistribution[i]++;
        break;
      }
    }
  });

  // Create CVSS3 bins
  const cvssBins = [0, 2, 4, 6, 8, 10];
  const cvssLabels = ['0-2', '2-4', '4-6', '6-8', '8-10'];
  const cvssDistribution = new Array(cvssBins.length - 1).fill(0);
  processedData.cvss3Scores.forEach(score => {
    for (let i = 0; i < cvssBins.length - 1; i++) {
      if (score >= cvssBins[i] && score < cvssBins[i + 1]) {
        cvssDistribution[i]++;
        break;
      }
    }
    if (score >= cvssBins[cvssBins.length - 1]) {
      cvssDistribution[cvssBins.length - 2]++;
    }
  });

  return [
    {
      filename: '01-summary-statistics.png',
      title: 'Summary Statistics',
      html: generateStatsHTML(processedData),
      isStats: true
    },
    {
      filename: '02-vulnerabilities-by-severity.png',
      title: 'Vulnerabilities by Severity',
      html: generateChartHTML('Vulnerabilities by Severity', {
        type: 'doughnut',
        data: {
          labels: severityLabels,
          datasets: [{
            data: Object.values(processedData.severityCounts),
            backgroundColor: severityColors,
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 20
              },
              padding: 6,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '03-vulnerability-states.png',
      title: 'Vulnerability States',
      html: generateChartHTML('Vulnerability States', {
        type: 'pie',
        data: {
          labels: Object.keys(processedData.stateCounts),
          datasets: [{
            data: Object.values(processedData.stateCounts),
            backgroundColor: [
              '#667eea', '#764ba2', '#f093fb', '#4facfe', '#00f2fe',
              '#43e97b', '#38f9d7', '#fa709a', '#fee140', '#30cfd0'
            ],
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 20
              },
              padding: 6,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '04-top-10-vulnerabilities.png',
      title: 'Top 10 Vulnerabilities by Count',
      html: generateChartHTML('Top 10 Vulnerabilities by Count', {
        type: 'bar',
        data: {
          labels: topVulns.map(v => v[0].length > 60 ? v[0].substring(0, 60) + '...' : v[0]),
          datasets: [{
            label: 'Count',
            data: topVulns.map(v => v[1]),
            backgroundColor: 'rgba(102, 126, 234, 0.8)',
            borderColor: 'rgba(102, 126, 234, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, 1000)
    },
    {
      filename: '05-vulnerabilities-by-family.png',
      title: 'Vulnerabilities by Family',
      html: generateChartHTML('Vulnerabilities by Family', {
        type: 'bar',
        data: {
          labels: families.map(f => f[0]),
          datasets: [{
            label: 'Count',
            data: families.map(f => f[1]),
            backgroundColor: 'rgba(118, 75, 162, 0.8)',
            borderColor: 'rgba(118, 75, 162, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, Math.max(800, families.length * 60))
    },
    {
      filename: '06-top-10-assets.png',
      title: 'Top 10 Assets by Vulnerability Count',
      html: generateChartHTML('Top 10 Assets by Vulnerability Count', {
        type: 'bar',
        data: {
          labels: topAssets.map(a => a[0]),
          datasets: [{
            label: 'Vulnerability Count',
            data: topAssets.map(a => a[1]),
            backgroundColor: 'rgba(240, 147, 251, 0.8)',
            borderColor: 'rgba(240, 147, 251, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, 1000)
    },
    {
      filename: '07-vpr-score-distribution.png',
      title: 'VPR Score Distribution',
      html: generateChartHTML('VPR Score Distribution', {
        type: 'bar',
        data: {
          labels: vprBins.slice(0, -1).map((b, i) => `${b}-${vprBins[i + 1]}`),
          datasets: [{
            label: 'Count',
            data: vprDistribution,
            backgroundColor: 'rgba(79, 172, 254, 0.8)',
            borderColor: 'rgba(79, 172, 254, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '08-vulnerability-age-distribution.png',
      title: 'Vulnerability Age Distribution',
      html: generateChartHTML('Vulnerability Age Distribution', {
        type: 'bar',
        data: {
          labels: ageLabels,
          datasets: [{
            label: 'Count',
            data: ageDistribution,
            backgroundColor: 'rgba(67, 233, 123, 0.8)',
            borderColor: 'rgba(67, 233, 123, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '09-cvss-v3-score-distribution.png',
      title: 'CVSS v3 Score Distribution',
      html: generateChartHTML('CVSS v3 Score Distribution', {
        type: 'bar',
        data: {
          labels: cvssLabels,
          datasets: [{
            label: 'Count',
            data: cvssDistribution,
            backgroundColor: 'rgba(250, 112, 154, 0.8)',
            borderColor: 'rgba(250, 112, 154, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '10-cvss-severity-levels.png',
      title: 'CVSS Severity Levels',
      html: generateChartHTML('CVSS Severity Levels', {
        type: 'doughnut',
        data: {
          labels: Object.keys(processedData.cvssSeverityCounts),
          datasets: [{
            data: Object.values(processedData.cvssSeverityCounts),
            backgroundColor: ['#6c757d', '#28a745', '#ffc107', '#fd7e14', '#dc3545'],
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 20
              },
              padding: 6,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '11-owasp-top-10-2021.png',
      title: 'OWASP Top 10 (2021)',
      html: generateChartHTML('OWASP Top 10 (2021)', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.owasp2021)
            .sort((a, b) => b[1] - a[1])
            .map(([label]) => label.length > 30 ? label.substring(0, 30) + '...' : label),
          datasets: [{
            label: 'Count',
            data: Object.entries(processedData.owasp2021)
              .sort((a, b) => b[1] - a[1])
              .map(([, count]) => count),
            backgroundColor: 'rgba(102, 126, 234, 0.8)',
            borderColor: 'rgba(102, 126, 234, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, Math.max(800, Object.keys(processedData.owasp2021).length * 70))
    },
    {
      filename: '12-owasp-top-10-2017.png',
      title: 'OWASP Top 10 (2017)',
      html: generateChartHTML('OWASP Top 10 (2017)', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.owasp2017)
            .sort((a, b) => b[1] - a[1])
            .map(([label]) => label.length > 30 ? label.substring(0, 30) + '...' : label),
          datasets: [{
            label: 'Count',
            data: Object.entries(processedData.owasp2017)
              .sort((a, b) => b[1] - a[1])
              .map(([, count]) => count),
            backgroundColor: 'rgba(118, 75, 162, 0.8)',
            borderColor: 'rgba(118, 75, 162, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, Math.max(800, Object.keys(processedData.owasp2017).length * 70))
    },
    {
      filename: '13-cwe-distribution.png',
      title: 'CWE (Common Weakness Enumeration) Distribution',
      html: generateChartHTML('CWE (Common Weakness Enumeration) Distribution', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.cweCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .map(([label]) => label),
          datasets: [{
            label: 'Count',
            data: Object.entries(processedData.cweCounts)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 15)
              .map(([, count]) => count),
            backgroundColor: 'rgba(79, 172, 254, 0.8)',
            borderColor: 'rgba(79, 172, 254, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, 1000)
    },
    {
      filename: '14-risk-modification-status.png',
      title: 'Risk Modification Status',
      html: generateChartHTML('Risk Modification Status', {
        type: 'pie',
        data: {
          labels: Object.keys(processedData.riskModifiedCounts),
          datasets: [{
            data: Object.values(processedData.riskModifiedCounts),
            backgroundColor: [
              '#667eea', '#764ba2', '#f093fb', '#4facfe', '#00f2fe',
              '#43e97b', '#38f9d7', '#fa709a', '#fee140', '#30cfd0'
            ],
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 20
              },
              padding: 6,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '15-wasc-categories.png',
      title: 'WASC (Web Application Security Consortium) Categories',
      html: generateChartHTML('WASC (Web Application Security Consortium) Categories', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.wascCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([label]) => label),
          datasets: [{
            label: 'Count',
            data: Object.entries(processedData.wascCounts)
              .sort((a, b) => b[1] - a[1])
              .map(([, count]) => count),
            backgroundColor: 'rgba(67, 233, 123, 0.8)',
            borderColor: 'rgba(67, 233, 123, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, Math.max(800, Object.keys(processedData.wascCounts).length * 60))
    },
    {
      filename: '16-compliance-frameworks.png',
      title: 'Compliance Framework Coverage',
      html: generateChartHTML('Compliance Framework Coverage', {
        type: 'bar',
        data: {
          labels: [
            'HIPAA',
            'PCI DSS',
            'ISO 27001',
            'NIST',
            'DISA STIG'
          ],
          datasets: [{
            label: 'Vulnerability Count',
            data: [
              processedData.complianceFrameworks.hipaa,
              processedData.complianceFrameworks.pci_dss,
              processedData.complianceFrameworks.iso,
              processedData.complianceFrameworks.nist,
              processedData.complianceFrameworks.disa_stig
            ],
            backgroundColor: 'rgba(240, 147, 251, 0.8)',
            borderColor: 'rgba(240, 147, 251, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
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
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '17-top-10-assets-by-findings.png',
      title: 'Top 10 Assets by Total Findings',
      html: generateChartHTML('Top 10 Assets by Total Findings', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.assetCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([name]) => name.length > 40 ? name.substring(0, 40) + '...' : name),
          datasets: [
            {
              label: 'Critical',
              data: Object.entries(processedData.assetCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name]) => processedData.assetSeverityBreakdown[name]?.[4] || 0),
              backgroundColor: 'rgba(220, 53, 69, 0.8)',
              borderColor: 'rgba(220, 53, 69, 1)',
              borderWidth: 1
            },
            {
              label: 'High',
              data: Object.entries(processedData.assetCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name]) => processedData.assetSeverityBreakdown[name]?.[3] || 0),
              backgroundColor: 'rgba(253, 126, 20, 0.8)',
              borderColor: 'rgba(253, 126, 20, 1)',
              borderWidth: 1
            },
            {
              label: 'Medium',
              data: Object.entries(processedData.assetCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name]) => processedData.assetSeverityBreakdown[name]?.[2] || 0),
              backgroundColor: 'rgba(255, 193, 7, 0.8)',
              borderColor: 'rgba(255, 193, 7, 1)',
              borderWidth: 1
            },
            {
              label: 'Low',
              data: Object.entries(processedData.assetCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name]) => processedData.assetSeverityBreakdown[name]?.[1] || 0),
              backgroundColor: 'rgba(40, 167, 69, 0.8)',
              borderColor: 'rgba(40, 167, 69, 1)',
              borderWidth: 1
            },
            {
              label: 'Info',
              data: Object.entries(processedData.assetCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name]) => processedData.assetSeverityBreakdown[name]?.[0] || 0),
              backgroundColor: 'rgba(23, 162, 184, 0.8)',
              borderColor: 'rgba(23, 162, 184, 1)',
              borderWidth: 1
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              display: false
            }
          },
          scales: {
            x: {
              stacked: true,
              beginAtZero: true,
              ticks: {
                stepSize: 1,
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              },
              title: {
                display: true,
                text: 'Number of Findings',
                font: {
                  size: 18,
                  weight: 'bold'
                },
                padding: 15
              }
            },
            y: {
              stacked: true,
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, 1000)
    },
    {
      filename: '18-top-10-assets-critical-high.png',
      title: 'Top 10 Assets by Critical/High Severity Findings',
      html: generateChartHTML('Top 10 Assets by Critical/High Severity Findings', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.criticalHighByAsset)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([name]) => name.length > 50 ? name.substring(0, 50) + '...' : name),
          datasets: [{
            label: 'Critical/High Findings',
            data: Object.entries(processedData.criticalHighByAsset)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 10)
              .map(([, count]) => count),
            backgroundColor: 'rgba(220, 53, 69, 0.8)',
            borderColor: 'rgba(220, 53, 69, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              },
              title: {
                display: true,
                text: 'Critical/High Findings',
                font: {
                  size: 18,
                  weight: 'bold'
                },
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, 1000)
    },
    {
      filename: '19-asset-exposure-analysis.png',
      title: 'Asset Exposure Analysis (Public vs Private)',
      html: generateChartHTML('Asset Exposure Analysis (Public vs Private)', {
        type: 'doughnut',
        data: {
          labels: ['Public', 'Private'],
          datasets: [{
            data: [
              processedData.assetExposure.Public || 0,
              processedData.assetExposure.Private || 0
            ],
            backgroundColor: ['rgba(220, 53, 69, 0.8)', 'rgba(40, 167, 69, 0.8)'],
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 20
              },
              padding: 6,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                if (total === 0) return '0';
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '20-asset-source-distribution.png',
      title: 'Findings by Asset Source',
      html: generateChartHTML('Findings by Asset Source', {
        type: 'bar',
        data: {
          labels: Object.keys(processedData.assetSourceCounts).length > 0
            ? Object.entries(processedData.assetSourceCounts)
                .sort((a, b) => b[1] - a[1])
                .map(([label]) => label)
            : ['No Data'],
          datasets: [{
            label: 'Findings',
            data: Object.keys(processedData.assetSourceCounts).length > 0
              ? Object.entries(processedData.assetSourceCounts)
                  .sort((a, b) => b[1] - a[1])
                  .map(([, count]) => count)
              : [0],
            backgroundColor: 'rgba(102, 126, 234, 0.8)',
            borderColor: 'rgba(102, 126, 234, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              },
              title: {
                display: true,
                text: 'Number of Findings',
                font: {
                  size: 18,
                  weight: 'bold'
                },
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '20b-findings-by-individual-asset.png',
      title: 'Findings by Individual Asset',
      html: generateChartHTML('Findings by Individual Asset', {
        type: 'pie',
        data: {
          labels: Object.entries(processedData.assetCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([name]) => name.length > 40 ? name.substring(0, 40) + '...' : name),
          datasets: [{
            data: Object.entries(processedData.assetCounts)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 10)
              .map(([, count]) => count),
            backgroundColor: [
              '#667eea', '#764ba2', '#f093fb', '#4facfe', '#00f2fe',
              '#43e97b', '#38f9d7', '#fa709a', '#fee140', '#30cfd0',
              '#ff6b6b', '#4ecdc4', '#45b7d1', '#f7b731', '#5f27cd'
            ],
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 15,
                font: {
                  size: 16,
                  weight: 'bold'
                },
                boxWidth: 25,
                boxHeight: 18
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 5,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                if (total === 0) return '0';
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '21-external-exposure-analysis.png',
      title: 'External Exposure Analysis',
      html: generateChartHTML('External Exposure Analysis', {
        type: 'pie',
        data: {
          labels: Object.keys(processedData.externalExposureCounts).length > 0 
            ? Object.keys(processedData.externalExposureCounts)
            : ['No Data'],
          datasets: [{
            data: Object.keys(processedData.externalExposureCounts).length > 0
              ? Object.values(processedData.externalExposureCounts)
              : [0],
            backgroundColor: ['rgba(220, 53, 69, 0.8)', 'rgba(40, 167, 69, 0.8)'],
            borderWidth: 2,
            borderColor: '#fff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 20,
                font: {
                  size: 18,
                  weight: 'bold'
                },
                boxWidth: 30,
                boxHeight: 20
              }
            },
            datalabels: {
              color: '#fff',
              font: {
                weight: 'bold',
                size: 20
              },
              padding: 6,
              formatter: (value, ctx) => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                if (total === 0) return '0';
                const percentage = ((value / total) * 100).toFixed(1);
                return value + ' (' + percentage + '%)';
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
    },
    {
      filename: '22-top-10-assets-by-vpr.png',
      title: 'Top 10 Assets by Average VPR Score',
      html: generateChartHTML('Top 10 Assets by Average VPR Score', {
        type: 'bar',
        data: {
          labels: Object.entries(processedData.assetVprScores)
            .map(([name, scores]) => [name, scores.reduce((a, b) => a + b, 0) / scores.length])
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([name]) => name.length > 50 ? name.substring(0, 50) + '...' : name),
          datasets: [{
            label: 'Average VPR Score',
            data: Object.entries(processedData.assetVprScores)
              .map(([name, scores]) => [name, scores.reduce((a, b) => a + b, 0) / scores.length])
              .sort((a, b) => b[1] - a[1])
              .slice(0, 10)
              .map(([, avg]) => parseFloat(avg.toFixed(2))),
            backgroundColor: 'rgba(79, 172, 254, 0.8)',
            borderColor: 'rgba(79, 172, 254, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'end',
              color: '#333',
              font: {
                weight: 'bold',
                size: 18
              },
              padding: 4,
              formatter: (value) => value.toFixed(2)
            }
          },
          scales: {
            x: {
              beginAtZero: true,
              max: 10,
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              },
              title: {
                display: true,
                text: 'Average VPR Score',
                font: {
                  size: 18,
                  weight: 'bold'
                },
                padding: 15
              }
            },
            y: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      }, 1400, 1000)
    },
    {
      filename: '23-findings-over-time.png',
      title: 'Findings Over Time (by Month)',
      html: generateChartHTML('Findings Over Time (by Month)', {
        type: 'line',
        data: {
          labels: Object.keys(processedData.findingsByMonth).length > 0
            ? Object.keys(processedData.findingsByMonth).sort()
            : ['No Data'],
          datasets: [{
            label: 'Findings',
            data: Object.keys(processedData.findingsByMonth).length > 0
              ? Object.keys(processedData.findingsByMonth)
                  .sort()
                  .map(month => processedData.findingsByMonth[month])
              : [0],
            borderColor: 'rgba(102, 126, 234, 1)',
            backgroundColor: 'rgba(102, 126, 234, 0.2)',
            borderWidth: 3,
            fill: true,
            tension: 0.4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            datalabels: {
              anchor: 'end',
              align: 'top',
              color: '#333',
              font: {
                weight: 'bold',
                size: 16
              },
              padding: 4
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              },
              title: {
                display: true,
                text: 'Number of Findings',
                font: {
                  size: 18,
                  weight: 'bold'
                },
                padding: 15
              }
            },
            x: {
              ticks: {
                font: {
                  size: 16,
                  weight: 'bold'
                },
                padding: 10
              },
              title: {
                display: true,
                text: 'Month',
                font: {
                  size: 18,
                  weight: 'bold'
                },
                padding: 15
              }
            }
          },
          layout: {
            padding: {
              top: 20,
              bottom: 20,
              left: 20,
              right: 20
            }
          }
        }
      })
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

    // Take screenshot
    await page.screenshot({
      path: outputPath,
      fullPage: true,
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
async function generateReport(jsonPath, outputDir) {
  console.log('Loading findings from:', jsonPath);
  const findings = loadFindings(jsonPath);
  
  console.log(`Processing ${findings.length} findings...`);
  const processedData = processData(findings);
  
  // Create output directory if it doesn't exist
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
const jsonFile = process.argv[2];
const outputDir = process.argv[3];

if (!jsonFile || !outputDir) {
  console.error('Usage: node generate-report.js <jsonFile> <outputDirectory>');
  console.error('Example: node generate-report.js december.json ./output');
  process.exit(1);
}

generateReport(jsonFile, outputDir).catch(error => {
  console.error('Error generating report:', error);
  process.exit(1);
});

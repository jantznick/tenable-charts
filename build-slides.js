import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import PptxGenJS from 'pptxgenjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Chart #6 from `generate-report.js` / `prepareCharts()` */
const CHART_6_FILENAME = '06-top-10-assets.png';

const SLIDE_TITLE = 'Top 10 assets by vulnerability count';

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    chartsDir: path.join(__dirname, 'charts'),
    outputPath: path.join(__dirname, 'slides', 'tenable-chart6.pptx'),
    imagePath: null
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--charts-dir' && args[i + 1]) {
      opts.chartsDir = path.resolve(args[++i]);
    } else if (arg === '--output' && args[i + 1]) {
      opts.outputPath = path.resolve(args[++i]);
    } else if (arg === '--image' && args[i + 1]) {
      opts.imagePath = path.resolve(args[++i]);
    }
  }

  return opts;
}

function resolveImagePath(opts) {
  if (opts.imagePath) {
    return opts.imagePath;
  }
  return path.join(opts.chartsDir, CHART_6_FILENAME);
}

/** PNG IHDR width/height — no extra deps (see PNG spec). */
function readPngPixelSize(filePath) {
  const buf = fs.readFileSync(filePath);
  const pngSig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buf.length < 24 || !buf.subarray(0, 8).equals(pngSig)) {
    throw new Error(`Not a PNG or file too small: ${filePath}`);
  }
  if (buf.toString('ascii', 12, 16) !== 'IHDR') {
    throw new Error(`Invalid PNG (missing IHDR): ${filePath}`);
  }
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

function fitSizePreservingAspect(imgW, imgH, boxW, boxH) {
  const imgAspect = imgW / imgH;
  const boxAspect = boxW / boxH;
  if (imgAspect > boxAspect) {
    return { w: boxW, h: boxW / imgAspect };
  }
  return { w: boxH * imgAspect, h: boxH };
}

async function main() {
  const opts = parseArgs(process.argv);
  const imagePath = resolveImagePath(opts);

  if (!fs.existsSync(imagePath)) {
    console.error(`Chart image not found: ${imagePath}`);
    console.error(
      'Run `npm run generate -- <jsonFile> <outputDirectory>` first (with charts in that directory), or pass --image <path> / --charts-dir <dir>.'
    );
    process.exit(1);
  }

  const outDir = path.dirname(opts.outputPath);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE';
  pptx.author = 'tenable-reports';
  pptx.title = 'Tenable report';

  const slide = pptx.addSlide();

  // LAYOUT_WIDE: 13.333" × 7.5" — title on slide; chart PNG has no title; left = chart, right = insights
  const margin = 0.35;
  const slideW = 13.333;
  const slideH = 7.5;
  const titleY = 0.22;
  const titleH = 0.52;
  const bodyTop = titleY + titleH + 0.12;
  const colGap = 0.35;
  const leftColW = 6.45;
  const rightX = margin + leftColW + colGap;
  const rightW = slideW - margin - rightX;
  const chartH = slideH - bodyTop - margin;

  slide.addText(SLIDE_TITLE, {
    x: margin,
    y: titleY,
    w: slideW - 2 * margin,
    h: titleH,
    fontSize: 22,
    bold: true,
    color: '363636',
    align: 'center',
    valign: 'middle'
  });

  const { width: pxW, height: pxH } = readPngPixelSize(imagePath);
  const { w: dispW, h: dispH } = fitSizePreservingAspect(pxW, pxH, leftColW, chartH);
  const imgX = margin + (leftColW - dispW) / 2;
  const imgY = bodyTop + (chartH - dispH) / 2;

  slide.addImage({
    path: imagePath,
    x: imgX,
    y: imgY,
    w: dispW,
    h: dispH
  });

  const insightsY = bodyTop;
  slide.addText('Insights', {
    x: rightX,
    y: insightsY,
    w: rightW,
    h: 0.38,
    fontSize: 18,
    bold: true,
    color: '4a5568',
    valign: 'top'
  });

  slide.addText(
    [
      {
        text: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore.',
        options: { bullet: true, fontSize: 12, paraSpaceAfter: 8 }
      },
      {
        text: 'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo.',
        options: { bullet: true, fontSize: 12, paraSpaceAfter: 8 }
      },
      {
        text: 'Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.',
        options: { bullet: true, fontSize: 12 }
      }
    ],
    {
      x: rightX,
      y: insightsY + 0.42,
      w: rightW,
      h: chartH - 0.42,
      valign: 'top',
      lineSpacingMultiple: 1.18
    }
  );

  await pptx.writeFile({ fileName: opts.outputPath });
  console.log(`Wrote: ${opts.outputPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

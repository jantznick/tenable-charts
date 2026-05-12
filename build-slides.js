import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import PptxGenJS from 'pptxgenjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CHART_6_FILENAME = '06-top-10-assets.png';

const DEFAULT_SLIDE_TITLE = 'Top 10 assets by vulnerability count';

const DEFAULT_INSIGHTS = [
  'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore.',
  'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo.',
  'Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.'
];

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    chartsDir: path.join(__dirname, 'charts'),
    outputPath: path.join(__dirname, 'slides', 'tenable-chart6.pptx'),
    configPath: null,
    imagePath: null,
    slideTitle: null
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--charts-dir' && args[i + 1]) {
      opts.chartsDir = path.resolve(args[++i]);
    } else if (arg === '--output' && args[i + 1]) {
      opts.outputPath = path.resolve(args[++i]);
    } else if (arg === '--config' && args[i + 1]) {
      opts.configPath = path.resolve(args[++i]);
    } else if (arg === '--image' && args[i + 1]) {
      opts.imagePath = path.resolve(args[++i]);
    } else if (arg === '--title' && args[i + 1]) {
      opts.slideTitle = args[++i];
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

function readPngDimensionsIfApplicable(imagePath) {
  if (path.extname(imagePath).toLowerCase() !== '.png') {
    return null;
  }
  try {
    return readPngPixelSize(imagePath);
  } catch {
    return null;
  }
}

/**
 * @param {unknown} raw
 * @param {string} baseDir - directory used to resolve relative slideImage paths
 * @param {number} index - for error messages
 */
function normalizeSlideSpec(raw, baseDir, index) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`slides[${index}] must be a non-null object`);
  }
  const slideImage = raw.slideImage;
  if (typeof slideImage !== 'string' || !slideImage.trim()) {
    throw new Error(`slides[${index}].slideImage is required (non-empty string)`);
  }
  const resolved = path.isAbsolute(slideImage)
    ? slideImage
    : path.resolve(baseDir, slideImage);

  const slideTitle =
    typeof raw.slideTitle === 'string' ? raw.slideTitle : raw.slideTitle != null ? String(raw.slideTitle) : '';

  let slideInsights = DEFAULT_INSIGHTS;
  if (raw.slideInsights != null) {
    if (!Array.isArray(raw.slideInsights)) {
      throw new Error(`slides[${index}].slideInsights must be an array of strings`);
    }
    slideInsights = raw.slideInsights.map((s, j) => {
      if (typeof s !== 'string') {
        throw new Error(`slides[${index}].slideInsights[${j}] must be a string`);
      }
      return s;
    });
    if (slideInsights.length === 0) {
      slideInsights = DEFAULT_INSIGHTS;
    }
  }

  return { slideTitle: slideTitle.trim(), slideImage: resolved, slideInsights };
}

function loadSlidesFromConfig(configPath) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`Config not found: ${configPath}`);
  }
  const text = fs.readFileSync(configPath, 'utf8');
  const parsed = JSON.parse(text);
  if (!Array.isArray(parsed)) {
    throw new Error('Slide config must be a JSON array, e.g. [{ "slideTitle": "...", ... }]');
  }
  const baseDir = path.dirname(configPath);
  return parsed.map((entry, i) => normalizeSlideSpec(entry, baseDir, i));
}

function printUsage() {
  console.error(`
Usage:
  node build-slides.js --config <slides.json> [--output <file.pptx>]

  node build-slides.js [--image <path.png>] [--title "Slide title"] [--charts-dir <dir>] [--output <file.pptx>]

--config     JSON array of slides: slideTitle, slideImage (path), slideInsights (string array, optional)
--image      Chart/graph image (default: <charts-dir>/${CHART_6_FILENAME})
--title      Slide title when not using --config (optional; default: ${DEFAULT_SLIDE_TITLE})
--output     Output .pptx path
--charts-dir Directory for default chart image (default: ./charts)
`);
}

const LAYOUT = {
  margin: 0.35,
  slideW: 13.333,
  slideH: 7.5,
  titleY: 0.22,
  titleH: 0.52,
  colGap: 0.35,
  leftColW: 6.45
};

function layoutBodyTop(hasTitle) {
  if (!hasTitle) {
    return LAYOUT.margin;
  }
  return LAYOUT.titleY + LAYOUT.titleH + 0.12;
}

/**
 * @param {object} pptx - PptxGenJS presentation instance
 * @param {object} spec
 * @param {string} spec.slideImage
 * @param {string} spec.slideTitle
 * @param {string[]} spec.slideInsights
 */
function addSlideWithChartAndInsights(pptx, spec) {
  const { margin, slideW, slideH, titleY, titleH, colGap, leftColW } = LAYOUT;
  const slide = pptx.addSlide();
  const hasTitle = Boolean(spec.slideTitle);
  const bodyTop = layoutBodyTop(hasTitle);
  const rightX = margin + leftColW + colGap;
  const rightW = slideW - margin - rightX;
  const chartH = slideH - bodyTop - margin;

  if (hasTitle) {
    slide.addText(spec.slideTitle, {
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
  }

  const dim = readPngDimensionsIfApplicable(spec.slideImage);
  if (dim) {
    const { w: dispW, h: dispH } = fitSizePreservingAspect(dim.width, dim.height, leftColW, chartH);
    const imgX = margin + (leftColW - dispW) / 2;
    const imgY = bodyTop + (chartH - dispH) / 2;
    slide.addImage({
      path: spec.slideImage,
      x: imgX,
      y: imgY,
      w: dispW,
      h: dispH
    });
  } else {
    slide.addImage({
      path: spec.slideImage,
      x: margin,
      y: bodyTop,
      w: leftColW,
      h: chartH,
      sizing: { type: 'contain', w: leftColW, h: chartH }
    });
  }

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

  const bulletRuns = spec.slideInsights.map((text, i, arr) => ({
    text,
    options: {
      bullet: true,
      fontSize: 12,
      ...(i < arr.length - 1 ? { paraSpaceAfter: 8 } : {})
    }
  }));

  slide.addText(bulletRuns, {
    x: rightX,
    y: insightsY + 0.42,
    w: rightW,
    h: chartH - 0.42,
    valign: 'top',
    lineSpacingMultiple: 1.18
  });
}

async function main() {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    printUsage();
    process.exit(0);
  }

  const opts = parseArgs(process.argv);

  let slides;
  if (opts.configPath) {
    slides = loadSlidesFromConfig(opts.configPath);
  } else {
    const imagePath = resolveImagePath(opts);
    slides = [
      {
        slideTitle: opts.slideTitle != null ? opts.slideTitle : DEFAULT_SLIDE_TITLE,
        slideImage: imagePath,
        slideInsights: DEFAULT_INSIGHTS
      }
    ];
  }

  for (const spec of slides) {
    if (!fs.existsSync(spec.slideImage)) {
      console.error(`Image not found: ${spec.slideImage}`);
      printUsage();
      process.exit(1);
    }
  }

  const outDir = path.dirname(opts.outputPath);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE';
  pptx.author = 'tenable-reports';
  pptx.title = 'Tenable report';

  for (const spec of slides) {
    addSlideWithChartAndInsights(pptx, spec);
  }

  await pptx.writeFile({ fileName: opts.outputPath });
  console.log(`Wrote ${slides.length} slide(s) to: ${opts.outputPath}`);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});

const gridData = [
  {
    imageSrc: "./images/flagyard.png",
    title: "Recon101",
    details: [
      "Challenge Type: Network traffic analysis (PCAP-based)\nTools Used: Wireshark, tshark, threat intelligence resources\nTasks:\n  • Extract traffic statistics from PCAP\n  • Identify target network's IPv4 range\n  • Detect port scanning activity (e.g., on port 1433)\n  • Identify attacker’s source IP\n  • Validate malicious IP using threat intelligence\n  • Count packets between attacker and hosts using tshark\n  • Decode packet counts (decimal to ASCII) to obtain the flag",
      ,
      "Difficulty: Medium"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "RuleBreaker",
    details: [
      "Challenge Type: Windows forensics (malware behavior analysis via Sysmon logs)\nTools Used: Sysmon logs, Windows Event Viewer, log analysis tools\nTasks:\n  • Analyze Sysmon logs to identify processes executed by the malware\n  • Investigate registry modifications associated with the malware\n  • Examine network connections initiated by the malicious process\n  • Correlate findings to understand malware behavior and retrieve the flag",
     ,
      "Difficulty: Hard"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "Poisoner",
    details: [
      "Challenge Type: Network forensics (NTLM hash extraction and cracking)\nTools Used: Wireshark, Hashcat\nTasks:\n  • Analyze PCAP file to filter NTLMSSP traffic\n  • Extract key values from NTLMSSP_NEGOTIATE, CHALLENGE, and AUTH packets:\n      • User name, domain name, server challenge, NTLM response\n  • Format the NTLM hash correctly\n  • Use Hashcat to crack the hash and recover the password",
     ,
      "Difficulty: Easy"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "Iced",
    details: [
      "Challenge Type: Windows forensics (execution and evasion artifact analysis)\nTools Used: WinPrefetchView, text/code editors for script analysis\nTasks:\n  • Analyze prefetch files to identify executed binaries (e.g., certutil.exe, PowerShell scripts)\n  • Investigate AppData directories (Local, LocalLow, Roaming) for related artifacts\n  • Locate files dropped or cached by certutil from prefetch data\n  • De-obfuscate PowerShell scripts (SECRET.PS1, SECRET[1].PS1, etc.) to uncover attacker intent and retrieve the flag",
     ,
      "Difficulty: Hard"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "Phishy",
    details: [
      "Challenge Type: Email forensics and macro malware analysis\nTools Used: Email analysis tools (oledump, olevba), header analyzers\nTasks:\n  • Extract and analyze metadata from the email\n  • Extract and analyze macro code from the .docm attachment\n  • De-obfuscate the macro script to understand its behavior\n  • Identify and extract any embedded flags from the script",
      ,
      "Difficulty: Insane"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "Collector",
    details: [
      "Challenge Type: Windows forensics (event log analysis and BITS abuse)\nTools Used: Event Viewer, MITRE ATT&CK framework\nTasks:\n  • Analyze event logs to trace execution of a PowerShell script (AnAn.ps1)\n  • Identify suspicious activity involving BITS during timeline analysis\n  • Map BITS behavior to MITRE ATT&CK techniques\n  • Extract BITS job DisplayName values from event logs\n  • Reconstruct the flag by ordering characters from BITS job names",
      ,
      "Difficulty: Medium"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "HereToStay",
    details: [
      "Challenge Type: Windows registry forensics (persistence detection via scheduled tasks)\nTools Used: Registry Explorer, offline registry viewer\nTasks:\n  • Analyze provided registry hives for persistence mechanisms\n  • Investigate TaskCache registry keys to identify suspicious scheduled tasks\n  • Locate and examine the 'Mozilla\\Firefox Default Browser Agent' task\n  • Decode the task’s GUID to reveal and analyze the execution command",
      ,
      "Difficulty: Easy"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  {
    imageSrc: "./images/flagyard.png",
    title: "Persist",
    details: [
      "Challenge Type: Windows registry forensics (persistence detection)\nTools Used: Registry Explorer (Eric Zimmerman), MITRE ATT&CK framework\nTasks:\n  • Analyze provided registry files using Registry Explorer\n  • Investigate persistence mechanisms based on MITRE ATT&CK techniques:\n    • Registry Run Keys\n    • Scheduled Tasks via TaskCache\n    • Image File Execution Options Injection\n  • Extract parts of the flag from each persistence technique\n  • Decode final flag from Base64",
      ,
      "Difficulty: Medium"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  // ... continue for the remaining challenges with the same pattern ...
];

const DIFFICULTY = ["Easy", "Medium", "Hard", "Insane"];
const list = document.getElementById("labs");

// details[0] is one block of "Label: value" lines followed by "Tasks:" and bullet lines;
// the remaining entries are optional extras such as "Difficulty: Hard".
function parseLab(item) {
  const lab = { type: "", tools: "", tasks: [], difficulty: "" };
  item.details.filter(Boolean).forEach((block) => {
    let inTasks = false;
    block.split("\n").forEach((line) => {
      const text = line.trim();
      if (!text) return;
      if (inTasks && text.startsWith("•")) {
        const indent = line.length - line.trimStart().length;
        lab.tasks.push({ text: text.replace(/^•\s*/, ""), sub: indent > 2 });
      } else if (text.startsWith("Challenge Type:")) lab.type = text.slice(15).trim();
      else if (text.startsWith("Tools Used:")) lab.tools = text.slice(11).trim();
      else if (text.startsWith("Difficulty:")) lab.difficulty = text.slice(11).trim();
      else if (text === "Tasks:") inTasks = true;
    });
  });
  return lab;
}

function el(tag, props = {}, children = []) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function row(label, value) {
  return el("p", { className: "row" }, [el("span", { textContent: label }), el("span", { textContent: value })]);
}

const pad = (n) => String(n).padStart(2, "0");
const labs = gridData.map((item) => ({ item, ...parseLab(item) }));
const isHot = (lab) => DIFFICULTY.indexOf(lab.difficulty) >= 2;

labs.forEach((lab, i) => {
  const { item } = lab;
  const body = [
    el("p", { className: "case", textContent: `Case file · Released ${item.publishedDate}` }),
    el("h2", { textContent: item.title }),
  ];
  if (lab.type) body.push(row("Challenge", lab.type));
  if (lab.tools) body.push(row("Tools", lab.tools));
  if (lab.tasks.length) {
    body.push(el("details", {}, [
      el("summary", { textContent: "Tasks" }),
      el("ul", {}, lab.tasks.map((t) => el("li", { className: t.sub ? "sub" : "", textContent: t.text }))),
    ]));
  }
  if (item.buttonLink && item.buttonLink !== "#") {
    body.push(el("a", { className: "play", href: item.buttonLink, target: "_blank", rel: "noopener", textContent: item.buttonText }));
  }

  list.append(el("li", { className: "lab" }, [
    el("span", { className: "idx", textContent: pad(i + 1) }),
    el("div", {}, body),
    el("span", { className: "stamp" + (isHot(lab) ? " hot" : "") }, [el("span", { className: "sr", textContent: "Difficulty: " }), lab.difficulty || "Unrated"]),
  ]));
});

/* ---------------- ink layer: the same hand-drawn line as the main page ---------------- */
const PAPER = "#f2f2ee", DIM = "#8f8f89", RED = "#d8402f";
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const smooth = (a, b, x) => { const t = Math.max(0, Math.min(1, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const lerp = (a, b, t) => a + (b - a) * t;
const ink = document.getElementById("ink"), ix = ink.getContext("2d");
const loupe = document.getElementById("loupe"), lx = loupe.getContext("2d");
const DPR = Math.min(devicePixelRatio || 1, 2);
let W = innerWidth, H = innerHeight, mobile = W <= 720, boil = 0;

function n2(x, y, seed) {
  return Math.sin(x * 0.045 + y * 0.031 + boil * 2.1 + seed) * 0.6 + Math.sin(x * 0.11 - y * 0.07 + boil * 3.3 + seed * 1.7) * 0.4;
}
// Polyline drawn as two wobbly pen strokes, revealed up to `prog`
function inkPath(ctx, pts, prog = 1, amp = 1.6, closed = false) {
  if (prog <= 0) return;
  const P = closed ? pts.concat([pts[0]]) : pts;
  const dense = [];
  for (let i = 0; i < P.length - 1; i++) {
    const [x1, y1] = P[i], [x2, y2] = P[i + 1];
    const n = Math.max(1, Math.ceil(Math.hypot(x2 - x1, y2 - y1) / 7));
    for (let j = 0; j < n; j++) dense.push([lerp(x1, x2, j / n), lerp(y1, y2, j / n)]);
  }
  dense.push(P[P.length - 1]);
  const end = Math.max(2, Math.floor(dense.length * Math.min(1, prog)));
  [[0, 1.25], [4.1, 0.6]].forEach(([seed, w]) => {
    ctx.beginPath(); ctx.lineWidth = w;
    for (let i = 0; i < end; i++) {
      const [x, y] = dense[i];
      const px = x + n2(x, y, seed) * amp, py = y + n2(y, x, seed + 2) * amp;
      i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
    }
    ctx.stroke();
  });
}
const circlePts = (cx, cy, r, n = 40) => Array.from({ length: n }, (_, i) => [cx + Math.cos(i / n * 6.283) * r, cy + Math.sin(i / n * 6.283) * r]);
const byteAt = (c, r) => (Math.imul((c * 73856093) ^ (r * 19349663), 2654435761) >>> 24) & 255;
const hx = (b) => b.toString(16).toUpperCase().padStart(2, "0");

const rows = [...list.children], intro = document.querySelector(".intro"), board = document.getElementById("board");
const numEl = document.getElementById("num"), nameEl = document.getElementById("name");
const rail = document.querySelector(".rail");
rail.innerHTML = rows.map(() => "<span></span>").join("");
const ticks = [...rail.children];

// Evidence board in the intro: every lab pinned, one thread through them in order
// Pin spots as [centre x, top y] fractions of the board; labs past the hand-placed ones fall back to a grid
const SPOTS = {
  desk: [[0.16, 0.06], [0.58, 0.02], [0.86, 0.22], [0.4, 0.3], [0.12, 0.5], [0.66, 0.52], [0.3, 0.78], [0.8, 0.8]],
  phone: [[0.25, 0.02], [0.72, 0.1], [0.28, 0.25], [0.74, 0.34], [0.24, 0.5], [0.72, 0.58], [0.27, 0.75], [0.73, 0.84]],
};
const spot = (i, set) => set[i] || [0.2 + (i % 3) * 0.3, 0.1 + Math.floor(i / 3) * 0.25];
const CARDS = labs.map((lab, i) => ({
  title: lab.item.title, diff: lab.difficulty || "Unrated", hot: isHot(lab), tilt: (byteAt(i, 13) / 255 - 0.5) * 0.12,
}));
function drawBoard(t) {
  const R = board.getBoundingClientRect();
  if (R.bottom < 0 || R.top > H) return;
  const cw = mobile ? 128 : 140, ch = mobile ? 42 : 46, fs = mobile ? 11 : 13;
  const pos = CARDS.map((c, i) => { const [u, v] = spot(i, mobile ? SPOTS.phone : SPOTS.desk); return [R.left + u * R.width, R.top + v * R.height]; });
  ix.strokeStyle = PAPER; ix.globalAlpha = 0.75;
  inkPath(ix, pos, reduced ? 1 : smooth(0.6, 2.8, t), 1.2);
  CARDS.forEach((c, i) => {
    const e = reduced ? 1 : smooth(0.1 + i * 0.12, 0.5 + i * 0.12, t);
    if (e <= 0) return;
    const [x, y] = pos[i];
    ix.save(); ix.translate(x, y); ix.rotate(c.tilt);
    ix.globalAlpha = 1; ix.fillStyle = "#000"; ix.fillRect(-cw / 2, 4, cw, ch);
    ix.strokeStyle = PAPER; inkPath(ix, [[-cw / 2, 4], [cw / 2, 4], [cw / 2, 4 + ch], [-cw / 2, 4 + ch]], e, 1, true);
    ix.globalAlpha = e; ix.textBaseline = "middle";
    ix.fillStyle = PAPER; ix.font = `650 ${fs + 1}px Archivo, sans-serif`; ix.fillText(c.title, -cw / 2 + 9, 4 + ch * 0.36);
    ix.fillStyle = c.hot ? RED : DIM; ix.font = `${fs - 2}px 'Special Elite', monospace`; ix.fillText(c.diff.toUpperCase(), -cw / 2 + 9, 4 + ch * 0.72);
    ix.restore();
    ix.globalAlpha = e; ix.fillStyle = c.hot ? RED : PAPER; ix.beginPath(); ix.arc(x, y + 3, 4, 0, 6.283); ix.fill();
  });
  ix.globalAlpha = 1;
}

// The lab nearest the reading line gets corner brackets, and its stamp gets circled
let active = -2, activeSince = 0;
function currentLab() {
  if (intro.getBoundingClientRect().bottom > H * 0.55) return -1;
  const mid = H * 0.45;
  let best = -1, bestD = Infinity;
  rows.forEach((li, i) => {
    const r = li.getBoundingClientRect();
    const d = r.top <= mid && r.bottom >= mid ? 0 : Math.min(Math.abs(r.top - mid), Math.abs(r.bottom - mid));
    if (d < bestD) { bestD = d; best = i; }
  });
  return best;
}
function drawActive(t) {
  const i = currentLab();
  if (i !== active) {
    active = i; activeSince = t;
    numEl.textContent = pad(i + 1);
    nameEl.textContent = i < 0 ? "Case files" : labs[i].item.title;
    ticks.forEach((tk, k) => tk.classList.toggle("on", k === i));
  }
  if (i < 0) return;
  const age = reduced ? 9 : t - activeSince, p = smooth(0, 0.5, age);
  const r = rows[i].getBoundingClientRect(), k = 16;
  const x0 = r.left - (mobile ? 6 : 14), y0 = r.top + 12, x1 = r.right + (mobile ? 6 : 14), y1 = r.bottom - 12;
  ix.strokeStyle = PAPER; ix.globalAlpha = 0.9;
  [[[x0, y0 + k * 2], [x0, y0], [x0 + k * 2, y0]], [[x1 - k * 2, y0], [x1, y0], [x1, y0 + k * 2]],
   [[x1, y1 - k * 2], [x1, y1], [x1 - k * 2, y1]], [[x0 + k * 2, y1], [x0, y1], [x0, y1 - k * 2]]].forEach((b) => inkPath(ix, b, p, 1));
  const stamp = rows[i].querySelector(".stamp"), s = stamp.getBoundingClientRect();
  const cx = s.left + s.width / 2, cy = s.top + s.height / 2, rx = s.width * 0.72, ry = s.height * 1.15;
  const ring = Array.from({ length: 46 }, (_, j) => { const a = j / 40 * 6.283 - 0.7; return [cx + Math.cos(a) * rx, cy + Math.sin(a) * ry]; });   // runs past a full turn, like a pen circle
  ix.strokeStyle = stamp.classList.contains("hot") ? RED : PAPER;
  inkPath(ix, ring, smooth(0.3, 0.9, age), 1.1);
  ix.globalAlpha = 1;
}

// Loupe over the intro: raw bytes under the page, as on the main page; steps aside over links, buttons and text
const UI = "a, button, summary, input, textarea, select, label, header, h1, h2, p, li";
const pointer = { x: -999, y: -999, on: false, last: 0, overUI: false };
const overUI = (el) => !!(el instanceof Element && el.closest(UI));
const track = (e) => { pointer.x = e.clientX; pointer.y = e.clientY; pointer.on = true; pointer.last = performance.now(); pointer.overUI = overUI(e.target); };
addEventListener("pointermove", track, { passive: true });
addEventListener("pointerdown", track, { passive: true });
addEventListener("pointerup", (e) => { if (e.pointerType !== "mouse") pointer.on = false; });
document.addEventListener("pointerleave", () => { pointer.on = false; });
addEventListener("scroll", () => { if (pointer.on) pointer.overUI = overUI(document.elementFromPoint(pointer.x, pointer.y)); }, { passive: true });
let loupeA = 0;
function drawLoupe() {
  lx.setTransform(DPR, 0, 0, DPR, 0, 0);
  lx.clearRect(0, 0, W, H);
  const ir = intro.getBoundingClientRect();
  const want = pointer.on && !pointer.overUI && performance.now() - pointer.last <= 2500 && pointer.y >= ir.top && pointer.y <= ir.bottom ? 1 : 0;
  loupeA += (want - loupeA) * (reduced ? 1 : 0.3);
  if (loupeA < 0.02) return;
  loupe.style.opacity = loupeA;
  const r = mobile ? 58 : 74, { x, y } = pointer, cw = 22, ch = 16;
  lx.save();
  lx.beginPath(); lx.arc(x, y, r, 0, 6.283); lx.fillStyle = "#000"; lx.fill(); lx.clip();
  lx.font = "11px ui-monospace, Menlo, monospace"; lx.textBaseline = "middle";
  const c0 = Math.floor((x - r) / cw), c1 = Math.ceil((x + r) / cw), r0 = Math.floor((y - r) / ch), r1 = Math.ceil((y + r) / ch);
  const rowShift = Math.floor(scrollY / ch);
  for (let c = c0; c <= c1; c++) for (let q = r0; q <= r1; q++) {
    const d = Math.hypot(c * cw + cw / 2 - x, q * ch + ch / 2 - y) / r;
    lx.globalAlpha = Math.max(0, 1 - d * 0.9);
    lx.fillStyle = d < 0.45 ? PAPER : DIM;
    lx.fillText(hx(byteAt(c, q + rowShift)), c * cw + 3, q * ch + ch / 2);
  }
  lx.restore();
  lx.strokeStyle = PAPER; lx.globalAlpha = 1;
  inkPath(lx, circlePts(x, y, r, 48), 1, 1.2, true);
  const h0 = [x + r * 0.73, y + r * 0.73], h1 = [x + r * 1.3, y + r * 1.3], o = 5 / Math.SQRT2;
  const handle = [[h0[0] - o, h0[1] + o], [h1[0] - o, h1[1] + o], [h1[0] + o, h1[1] - o], [h0[0] + o, h0[1] - o]];
  lx.fillStyle = "#000"; lx.beginPath(); handle.forEach(([px, py], i) => i ? lx.lineTo(px, py) : lx.moveTo(px, py)); lx.fill();
  inkPath(lx, handle, 1, 1, true);
}

// Film grain: one noise tile, re-offset on every boil tick
const grain = document.getElementById("grain");
{
  const c = document.createElement("canvas"); c.width = c.height = 160;
  const g = c.getContext("2d"), im = g.createImageData(160, 160);
  for (let i = 0; i < im.data.length; i += 4) { const v = Math.random(); im.data[i] = im.data[i + 1] = im.data[i + 2] = 255; im.data[i + 3] = v > 0.82 ? (v - 0.82) * 1400 : 0; }
  g.putImageData(im, 0, 0); grain.style.backgroundImage = `url(${c.toDataURL()})`;
}

function resize() {
  W = innerWidth; H = innerHeight; mobile = W <= 720;
  [ink, loupe].forEach((c) => { c.width = W * DPR; c.height = H * DPR; });
}
addEventListener("resize", resize); resize();

const t0 = performance.now();
let lastBoil = -1;
function frame() {
  const t = (performance.now() - t0) / 1000;
  boil = reduced ? 0 : Math.floor(t * 8) / 8;   // lines redraw ~8 times a second, like hand-drawn animation
  if (boil !== lastBoil) { lastBoil = boil; grain.style.backgroundPosition = `${byteAt(boil * 8, 1) % 160}px ${byteAt(boil * 8, 2) % 160}px`; }
  ix.setTransform(DPR, 0, 0, DPR, 0, 0);
  ix.clearRect(0, 0, W, H);
  drawBoard(t);
  drawActive(t);
  drawLoupe();
  requestAnimationFrame(frame);
}
frame();

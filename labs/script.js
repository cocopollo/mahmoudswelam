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

gridData.forEach((item, i) => {
  const lab = parseLab(item);
  const level = DIFFICULTY.indexOf(lab.difficulty) + 1;
  const ticks = DIFFICULTY.map((_, k) => el("b", { className: k < level ? "on" : "" }));

  const body = [
    el("h2", { textContent: item.title }),
    el("div", { className: "meta" }, [
      el("span", { className: "diff" }, [el("i", { ariaHidden: "true" }, ticks), lab.difficulty]),
      el("span", { textContent: `Released ${item.publishedDate}` }),
    ]),
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
    el("span", { className: "idx", textContent: String(i + 1).padStart(2, "0") }),
    el("div", {}, body),
  ]));
});

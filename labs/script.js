const gridData = [
  {
    imageSrc: "./images/flagyard.png",
    title: "Recon101",
    details: [
      "Challenge Type: Network traffic analysis (PCAP-based)\nTools Used: Wireshark, tshark, threat intelligence resources\nTasks:\n  • Extract traffic statistics from PCAP\n  • Identify target network's IPv4 range\n  • Detect port scanning activity (e.g., on port 1433)\n  • Identify attacker’s source IP\n  • Validate malicious IP using threat intelligence\n  • Count packets between attacker and hosts using tshark\n  • Decode packet counts (decimal to ASCII) to obtain the flag",
      "Competitions:\n  - CTFCreators (1st Challenge)\n  - FlagYard 1st patch",
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
      "Competitions:\n  - FlagYard 1st patch",
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
      "Competitions:\n  - FlagYard 1st patch",
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
      "Competitions:\n  - FlagYard 1st patch",
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
      "Competitions:\n  - FlagYard 1st patch",
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
      "Competitions:\n  - FlagYard 1st patch",
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
      "Competitions:\n  - FlagYard 1st patch",
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
      "Competitions:\n  - CTFCreators (3rd Challenge)\n  - EGCERT (CAISEC 2025)",
      "Difficulty: Medium"
    ],
    publishedDate: "10 Jun 2025",
    buttonText: "Try The Lab",
    buttonLink: "#",
    isVIP: true,
  },
  // ... continue for the remaining challenges with the same pattern ...
];

const gridContainer = document.querySelector(".girgis-grid");
const prevPageBtn = document.getElementById("prevPage");
const nextPageBtn = document.getElementById("nextPage");
const currentPageIndicator = document.getElementById("currentPage");

let currentPage = 1;
const itemsPerPage = 6;

function renderGridItems(page) {
  gridContainer.innerHTML = ""; // Clear existing grid items

  const startIndex = (page - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;

  gridData.slice(startIndex, endIndex).forEach((item) => {
    const card = document.createElement("a");
    card.setAttribute("href", item.buttonLink);
    card.setAttribute("target", "_blank");
    card.classList.add("girgis-card");

    if (item.isVIP) {
      card.classList.add("vip");
    }

    const image = document.createElement("img");
    image.setAttribute("src", item.imageSrc);
    image.setAttribute("alt", "");

    const title = document.createElement("h6");
    title.textContent = item.title;

    const detailsList = document.createElement("ul");
    item.details.forEach((detail) => {
      const listItem = document.createElement("li");
      if (detail.startsWith("Difficulty:")) {
        const parts = detail.split(":");
        const level = parts[1].trim();
        listItem.innerHTML = `${parts[0]}: <span class=\"${getDifficultyClass(level)}\">${level}</span>`;
      } else {
        listItem.textContent = detail;
      }
      detailsList.appendChild(listItem);
    });

    // Published date
    const dateItem = document.createElement("li");
    dateItem.textContent = `Released on: ${item.publishedDate}`;
    dateItem.classList.add("published-date");
    detailsList.appendChild(dateItem);

    const button = document.createElement("button");
    button.textContent = item.buttonText;

    card.append(image, title, detailsList, button);
    gridContainer.appendChild(card);
  });

  currentPageIndicator.textContent = `Page ${currentPage}`;
}

function getDifficultyClass(d) {
  return {
    Easy: 'difficulty-easy',
    Medium: 'difficulty-medium',
    Hard: 'difficulty-hard',
    Insane: 'difficulty-insane'
  }[d] || '';
}

prevPageBtn.addEventListener("click", () => {
  if (currentPage > 1) { currentPage--; renderGridItems(currentPage); }
});

nextPageBtn.addEventListener("click", () => {
  const total = Math.ceil(gridData.length / itemsPerPage);
  if (currentPage < total) { currentPage++; renderGridItems(currentPage); }
});

renderGridItems(currentPage);

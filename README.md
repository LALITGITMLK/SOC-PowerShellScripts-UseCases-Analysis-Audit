# SOC PowerShell Scripts: Use Cases, Analysis & Audit Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-0078d7?logo=powershell&logoColor=white) ![Security](https://img.shields.io/badge/SOC-Security-green)

## Overview

This repository provides a comprehensive collection of PowerShell scripts tailored for Security Operations Center (SOC) teams. It features automation solutions for a broad set of security, analysis, and audit scenarios—streamlining routine SOC processes and improving incident response efficiency.

- **70+ ready-to-use PowerShell scripts**
- Modular master toolkit: easy to customize, extend, and integrate
- Use-case-driven collections for automation and manual analysis
- Documentation and runbooks to guide operation

---

## Table of Contents

- [Features](#features)
- [Scripts & Use Cases](#scripts--use-cases)
- [Getting Started](#getting-started)
- [How to Use](#how-to-use)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Features

- 🌐 **Domain & Certificate Audits:** Check domain age, monitor certificate transparency, and more.
- 🔎 **IOC/Threat Analysis:** Automate threat intel lookups and IOC enrichment.
- 💡 **Best Practice Runbooks:** Standard Operating Procedures (SOPs) for script execution.
- 🗃️ **Comprehensive Documentation:** All scripts and use-cases documented for quick reference.

## Scripts & Use Cases

Examples include:
- **Domain Age Checker:** `UC-012-DomainAgeChecker.ps1`
- **Certificate Transparency Scanner:** `UC-013-CertTransparencyScanner.ps1`
- **[Add other scripts/use cases as needed]**

Refer to the [comprehensive use cases documentation](./comprehensive%20use%20cases%20Powershell%20scripts.txt) for detailed descriptions.

---

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone https://github.com/LALITGITMLK/SOC-PowerShellScripts-UseCases-Analysis-Audit.git
   cd SOC-PowerShellScripts-UseCases-Analysis-Audit
   ```
2. **Review prerequisites:**  
   Ensure you are running PowerShell 5.x or above, with any required dependencies noted per script.
3. **Browse available scripts:**  
   Scripts are organized by use case. Review the documentation files for operational guidance.

---

## How to Use

- Each use case script can be run independently.  
  Example:
  ```sh
  powershell.exe -File .\UC-012-DomainAgeChecker.ps1 -Domain example.com
  ```

- The master toolkit script, `SOC-PowerShell-Toolkit.ps1`, merges all use cases into a single interface for efficiency—see script comments for available functions and parameters.

- For operating procedures and environments, see [`Where to run which script to run SOP.txt`](./Where%20to%20run%20which%20script%20to%20run%20SOP.txt)

---

## Contributing

Want to contribute new scripts or suggest features?

- Fork this repo and submit a pull request
- Create or help resolve issues—ideas and improvements are welcome!
- See `CONTRIBUTING.md` (Add this file for detailed contribution guidelines.)

---

## License

[MIT License](LICENSE)  
Feel free to use, modify, and distribute with attribution.

---

## Acknowledgements

- Script author & maintainer: [Lalit Kumar](https://github.com/LALITGITMLK)
- Inspired by real-world SOC operations and analyst feedback
- Thanks to the open-source PowerShell and security communities for inspiration and reusable modules.

---

> _Empowering Security Teams to automate, analyze, and audit—with PowerShell!_

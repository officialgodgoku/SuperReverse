# SuperReverse

<p align="center">
  <img src="docs/banner.png" alt="SuperReverse Banner" width="100%"><br>
  <b>Fluid 3D Liquid-Glass Drag-and-Drop Software & Website Architecture Mapper</b><br>
  <i>Created by <b>Manish</b> (<a href="https://github.com/officialgodgoku">@officialgodgoku</a>)</i>
</p>

<p align="center">
  <a href="https://github.com/officialgodgoku/SuperReverse/releases/latest"><img src="https://img.shields.io/badge/version-1.0.0-cyan.svg?style=flat-square" alt="Version 1.0.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License MIT"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.11+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://buymeacoffee.com/officialgodgoku"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=flat-square&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee"></a>
  <a href="https://github.com/officialgodgoku"><img src="https://img.shields.io/badge/GitHub-officialgodgoku-181717.svg?style=flat-square&logo=github&logoColor=white" alt="GitHub Profile"></a>
</p>

---

## 🌟 Visual Showcase

Drop any software, binary, package, or website URL onto SuperReverse to instantly throw out an **Autonomous AI Architecture Map (`<Target>_AI_MAP.md`)**:

<p align="center">
  <img src="docs/preview.png" alt="SuperReverse Visual Interface & AI Map Viewer" width="100%">
</p>

### 🎬 Live Autonomous Analysis Pipeline
Watch SuperReverse decompile, audit security mitigations, and synthesize a complete AI blueprint in real time:

<p align="center">
  <img src="docs/demo.gif" alt="SuperReverse Dynamic Analysis Flow" width="80%">
</p>

---

## 🚀 Key Features

### 1. 📥 Fluid Drag-and-Drop Drop Zone
- **Universal Multi-Platform Support**:
  - 🤖 **Android Packages**: `.apk`, `.aab`, `.xapk`, and unpacked trees
  - 🪟 **Windows Native & .NET**: `.exe`, `.dll`, `.sys`, `.ocx`
  - 🌐 **Live Web Applications**: Any URL (`https://...`, `http://...`) or `.url` internet shortcuts
  - ⚡ **Electron & Node.js**: `.asar` archives, unpacked JavaScript applications
  - 🐧 **Linux**: ELF binaries, `.so` shared libraries
  - 🍎 **macOS / iOS**: Mach-O executables, universal fat binaries, `.dylib`
  - ☕ **Java & WebAssembly**: `.jar`, `.war`, `.wasm`
- **Instant Output Generation**: Outputs `<Target>_AI_MAP.md` directly next to the source file or on your Desktop.

### 2. 🎛️ Liquid-Glass Radial Action Menu
Interact with the radial dial to dispatch actions:
- 🗺️ **AI Map**: Instant full-spectrum architecture generation.
- 🛡️ **Security**: Exploit mitigations, dangerous permissions, and risk audit.
- 📦 **Unpack**: Extract resources, assets, and binary manifests (APKTool / ASAR).
- ☕ **Decompile**: Java decompilation via JADX / source recovery.
- 🔍 **Strings & Secrets**: Harvest URLs, endpoints, IPs, registry keys, and API tokens.
- 📋 **AI Prompt**: One-click copy of an LLM-ready context prompt to system clipboard.

---

## 🔬 Multi-Engine Reverse Engineering Matrix

| Target Engine | Features Implemented (from REA & APK-Reverse) |
| :--- | :--- |
| **Android Applications** (`.apk`, `.aab`) | • **Binary AXML Parser**: Decodes `AndroidManifest.xml` (package, versions, SDKs)<br>• **Component Security Audit**: Activities, Services, Receivers, Providers flagged for unauthenticated external access<br>• **DEX & Multi-Dex**: Class hierarchy, method counts, framework fingerprinting (Flutter, React Native, Unity, Cordova)<br>• **Native JNI Inventory**: `.so` libraries mapped by ABI (`arm64-v8a`, `x86_64`)<br>• **Dynamic Hooking**: Auto-generates **Frida scripts** for SSL Unpinning, Root Detection bypass, and Activity tracing |
| **Windows Executables** (`.exe`, `.dll`, `.sys`) | • **Headers & Subsystems**: PE32 / PE32+ (x86, x64, ARM64), GUI vs Console<br>• **Section Shannon Entropy**: Detects crypters, packers (UPX, VMProtect, Themida)<br>• **Semantic IAT Clustering**: Categorizes imported APIs into Process Injection, Network/C2, Registry, Cryptography, and Anti-Debugging<br>• **Security Mitigations**: ASLR, High-Entropy ASLR, DEP/NX, SafeSEH, Control Flow Guard (CFG), and Authenticode digital signatures |
| **Web Applications & URLs** (`https://...`) | • **Security Headers Audit**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy<br>• **Tech Stack Detection**: React, Next.js, Vue, Nuxt, Angular, Svelte, WordPress, Shopify, Tailwind<br>• **API Endpoint Discovery**: Scrapes HTML & JS bundles for REST/GraphQL endpoints (`/api/...`, `fetch()`, `axios()`)<br>• **Third-Party Services**: Google Analytics, Stripe, Firebase, Cloudflare, Sentry, AWS |
| **Electron & JavaScript** (`.asar`) | • **Pure-Python ASAR Reader**: Virtual file system indexing & unpacking<br>• **IPC Communication Map**: Maps `ipcMain.on`, `ipcMain.handle`, `ipcRenderer.send`, and `ipcRenderer.invoke`<br>• **Security Audit**: Flags `nodeIntegration`, `contextIsolation`, `enableRemoteModule`, and `webSecurity` |
| **Linux & macOS Native** (ELF, Mach-O, WASM) | • **ELF**: Class, endianness, machine ABI, DT_NEEDED dependencies, PIE, Canary, and NX bits<br>• **Mach-O**: Fat Universal binaries, architectures, linked dylibs<br>• **WebAssembly**: WASM binary validation & section layout |
| **REA CLI & Tool Bridge** | • Integrates with local tools: `rea 6.7.0`, `jadx 1.5.6`, `apktool 3.0.2`, and `frida` |

---

## 🗺️ The Autonomous AI Software Blueprint (`*_AI_MAP.md`)

Each generated blueprint follows a standardized specification designed for AI agents:
1. **Executive Summary & Machine Signature**: Format, platform, SHA-256 digest, size, entry points.
2. **Security Posture & Vulnerability Matrix**: Exploit mitigations checklist, dangerous permissions, exported components.
3. **Execution Lifecycle & Architecture Flow**: Mermaid flowchart diagram mapping process startup.
4. **Modular & Component Hierarchy**: Full component breakdown with security notes.
5. **Interface & Communication Surface**: Exported functions, IPC channels, deep links, and APIs.
6. **Extracted Intelligence**: Discovered web endpoints, IP addresses, registry keys, and secrets.
7. **AI Agent Navigation Prompt**: Compact, copy-pasteable context block for LLMs.
8. **Reconstruction Obligation Ledger**: Step-by-step implementation checklist for AI rebuilding.
9. **Dynamic Instrumentation & Frida Playbook**: Ready-to-run Frida scripts customized for the package.

---

## 📥 Installation & Download

### 1. Download Standalone Software
Download the latest executable from the [Releases](https://github.com/officialgodgoku/SuperReverse/releases) tab.

### 2. Run from Source
```bash
# Clone the repository
git clone https://github.com/officialgodgoku/SuperReverse.git
cd SuperReverse

# Install dependencies
pip install -r requirements.txt

# Launch GUI
python run.py
```

### 3. Headless Command-Line Interface (CLI)
```bash
# Analyze any website URL:
python run.py --cli https://example.com

# Analyze an Android APK:
python run.py --cli path/to/app.apk

# Analyze a Windows executable:
python run.py --cli path/to/program.exe -o custom_map.md
```

---

## ☕ Support & Sponsoring

If SuperReverse saves you hours of reverse engineering or helps your AI workflows:

<p align="center">
  <a href="https://buymeacoffee.com/officialgodgoku">
    <img src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=☕&slug=officialgodgoku&button_colour=FFDD00&font_colour=000000&font_family=Poppins&outline_colour=000000&coffee_colour=ffffff" alt="Buy Me A Coffee" width="220">
  </a>
</p>

---

## 📜 License

Distributed under the **MIT License**. Created with 💖 by **[Manish](https://github.com/officialgodgoku)**.

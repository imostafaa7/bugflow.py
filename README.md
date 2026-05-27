# BugFlow

BugFlow is a lightweight Python workflow that automates recon and web vulnerability checks using ProjectDiscovery tools.

It chains together:
- Subfinder for subdomain enumeration.
- httpx for live web target probing.
- Naabu for port discovery.
- Nuclei for vulnerability scanning.

## Features
- Automated subdomain discovery.
- Clean host normalization before scanning.
- Separate handling for web targets and port-scan targets.
- Structured output files for each stage.
- Easy to run from a single command.

## Requirements
- Python 3.10+
- Go installed
- ProjectDiscovery tools:
  - `subfinder`
  - `httpx`
  - `naabu`
  - `nuclei`

## Installation

Clone the repository:

```bash
git clone https://github.com/imostafaa7/bugflow.py.git
cd bugflow.py
```

Install ProjectDiscovery tools:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Add Go binaries to your PATH:

```bash
export PATH="$HOME/go/bin:$PATH"
```

## Usage

Run the workflow against a target domain:

```bash
python3 bugflow.py -d example.com -o results
```

## Output Files

BugFlow creates the following files inside the output directory:

- `subdomains.txt` — raw subdomain enumeration.
- `subdomains_clean.txt` — normalized subdomains.
- `web_targets.txt` — hosts extracted for port scanning.
- `live.txt` — live web targets discovered by httpx.
- `ports.txt` — open ports discovered by naabu.
- `nuclei.jsonl` — vulnerability scan results.
- `report.txt` — summary report.

## Notes
- Use this tool only on assets you are authorized to test.
- Results may vary depending on target scope, rate limits, and template coverage.

## License
Specify your license here.

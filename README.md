# Shodan Host Lookup Tool

A Python script to gather information about a target host using the Shodan API.  
It can resolve a domain to an IP, query Shodan for host information, display banners for open services, and list vulnerabilities with potential exploits.

---

## Features
- Resolve a hostname to an IP using Shodan DNS API
- Retrieve host information:
  - IP address
  - Organization
  - Operating System
- Display banners for open ports/services
- List known vulnerabilities (CVEs)
- Search for exploits associated with vulnerabilities
- Uses a `.env` file for secure API key management

---

## Requirements

- Python 3.8+
- [Shodan API key](https://account.shodan.io/)
- Packages listed in `requirements.txt`:
  ```text
  shodan
  requests
  python-dotenv

Setup

    Clone the repository:

git clone https://github.com/aidenmjeda/shodan-host-lookup.git
cd Gathering-Information

Create a .env file in the project root:

SHODAN_API_KEY=your_new_shodan_api_key_here

Install dependencies:

    python3 -m pip install -r requirements.txt

Usage

Run the script with Python:

python3 main.py

The script will:

    Resolve the domain from .env (TARGET_HOST)

    Query Shodan for the IP

    Print host info, banners, and vulnerabilities

Security Notes

    Never commit your API key to a public repository.

    .env is included in .gitignore to protect sensitive information.

    Treat your Shodan API key like a password. If exposed, revoke it immediately.


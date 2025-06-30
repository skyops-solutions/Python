# Docker Containers Audit Script

This Python script quickly gathers information about all local Docker containers, including:

- Container status (running, exited, etc.)
- Uptime (start time)
- CPU usage percentage
- Memory usage (in MB and percentage)

## Requirements

- Python 3.6 or higher
- Docker installed and running locally
- Access to Docker daemon (usually available if Docker is running)
- Python packages:
  - `docker`
  - `tabulate`

## Installation

1. Clone the repository or save the script locally.
2. Install dependencies:

```bash
pip install -r requirements.txt

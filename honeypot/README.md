# Honeypot-Project
# SSH Honeypot

## Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Run
```bash
source venv/bin/activate
python -m src.server
```

## Configuration
Edit `config/config.yaml` to change settings.
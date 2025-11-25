# 🍯 Decoy Defense: Honeypot-Based Threat Intelligence Platform

A full-stack threat intelligence system that captures, analyzes, and visualizes SSH attacks using honeypots.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-6+-green.svg)](https://www.mongodb.com/)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org/)

## 🏗️ Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Attacker  │────▶│  Honeypot   │────▶│   MongoDB   │
│             │     │  (Python)   │     │             │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌──────────────────────────┘
                    │
                    ▼
            ┌───────────────┐
            │   Backend API │
            │   (Node.js)   │
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │   Dashboard   │
            │    (React)    │
            └───────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- Node.js 18 or higher
- MongoDB 6 or higher

### Installation
```bash
# 1. Clone repository
git clone https://github.com/rohittsainii/Honeypot-Project.git
cd Honeypot-Project

# 2. Run setup script
./scripts/setup.sh

# 3. Start MongoDB
./scripts/start-mongodb.sh

# 4. Start all services
./scripts/start-all.sh
```

### Access

- **Dashboard**: http://localhost:3000
- **API**: http://localhost:5000
- **Honeypot**: localhost:2222 (SSH)

### Stop Services
```bash
./scripts/stop-all.sh
```

## 📖 Manual Setup

### 1. Honeypot
```bash
cd honeypot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m src.server
```

### 2. Backend
```bash
cd backend
npm install
cp .env.example .env
npm run import-logs  # Import existing logs
npm run dev
```

### 3. Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm start
```

## 📊 Features

- ✅ SSH Honeypot with interactive fake shell
- ✅ Real-time attack monitoring with WebSocket
- ✅ GeoIP location tracking
- ✅ MITRE ATT&CK framework mapping
- ✅ Interactive dashboard with visualizations
- ✅ Attack pattern analysis
- ✅ Top credentials & commands tracking
- ⏳ YARA rule generation (coming soon)
- ⏳ Sigma rule generation (coming soon)

## 📁 Project Structure
```
Honeypot-Project/
├── honeypot/      # Python SSH honeypot
├── backend/       # Node.js REST API
├── frontend/      # React dashboard
├── data/          # MongoDB data & logs
├── docs/          # Documentation
└── scripts/       # Utility scripts
```
## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This project is for educational and research purposes only. Deploy honeypots responsibly and in compliance with local laws.
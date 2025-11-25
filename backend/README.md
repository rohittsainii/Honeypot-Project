# Backend API

## Setup
```bash
npm install
```

## Configure
Copy `.env.example` to `.env` and update values.

## Run
```bash
# Development mode (auto-restart on changes)
npm run dev

# Production mode
npm start
```

## Import Logs
```bash
npm run import-logs
```

## API Endpoints
See `docs/API.md` for full documentation.

- `GET /api/stats/overview` - Overall statistics
- `GET /api/attacks/recent` - Recent attacks
- `GET /api/attacks/map` - Attack geolocation data
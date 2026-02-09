# KeyGuard - API Key Exposure Scanner

## Overview
A web-based security scanning tool that detects exposed API keys in public GitHub repositories and live websites. Users enter a URL (GitHub repo or public website) and get a scan report showing any detected exposed API keys with their type, location, and the actual key value.

## Architecture
- **Frontend**: React SPA with Tailwind CSS + shadcn/ui, single-page app with scan form and results
- **Backend**: Express.js with scanning engine
- **No database needed** - stateless scanning tool

## Key Files
- `client/src/pages/home.tsx` - Main page with scan form and results display
- `server/scanner.ts` - Core scanning engine with 30+ API key patterns
- `server/routes.ts` - API endpoint `/api/scan`
- `shared/schema.ts` - Shared types for scan requests/results
- `client/src/components/theme-provider.tsx` - Dark/light theme support

## How Scanning Works
1. User enters a GitHub repo URL or public website URL
2. **GitHub repos**: Fetches repo tree via GitHub API, downloads text files (up to 100), runs pattern matching
3. **Websites**: Fetches HTML, extracts and fetches linked JS/CSS files, scans inline scripts
4. Pattern matching against 30+ known API key formats (AWS, Stripe, OpenAI, GitHub, Firebase, etc.)
5. Results show key type, actual value (masked by default), file location, and severity

## Design
- Security-focused blue/dark theme
- Dark mode by default with light mode toggle
- Monospace font for key display
- Copy and reveal/hide functionality for detected keys

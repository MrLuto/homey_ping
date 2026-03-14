# Homey Ping

Ping devices from Homey and use the online/offline status in Flows.

This app started as ICMP-based monitoring.  
Because some Homey environments do not include a `ping` binary, the app supports three probe modes:
- `AUTO (ICMP -> TCP fallback)`
- `ICMP only`
- `TCP only`

## Features

- Add one or more ping targets manually (host/IP).
- Periodic probing with configurable interval and timeout.
- Manual probe via capability (`Ping nu` / `Ping now`).
- Status capability with clear values: `Online` / `Offline`.
- Flow cards for automation:
  - Trigger: `Device came online`
  - Trigger: `Device went offline`
  - Condition: `Is online`
  - Condition: `Is offline`
  - Action: `Ping now`

## Device Settings

- `Host or IP`: target to monitor (for example `192.168.1.20` or `nas.local`)
- `Ping interval (seconds)`: how often to probe
- `Ping timeout (ms)`: timeout per attempt
- `Probe mode`:
  - `Auto (ICMP -> TCP)`: tries ICMP first, falls back to TCP when ICMP is unavailable
  - `ICMP only`: strict ICMP mode
  - `TCP only`: connection check on configured port
- `TCP fallback port`: port used for TCP mode/fallback (default `443`)

## Flow Usage

Common use cases:

- Notify when NAS/printer/server comes online.
- Trigger "offline alert" after device disappears.
- Use `Ping now` action before running dependent automations.

## Development

### Requirements

- Node.js (LTS)
- Homey CLI (`npm i -g homey`)
- Access to a Homey Pro (local)

### Install dependencies

```bash
npm install
```

### Run in development

```bash
npm run run
```

### Install directly to Homey

```bash
npm run install
```

### Validate/build

```bash
npm run lint
npm run validate
npm run build
```

## GitHub Workflows

This repository includes Homey workflows:

- `.github/workflows/homey-app-validate.yml`
- `.github/workflows/homey-app-version.yml`
- `.github/workflows/homey-app-publish.yml`

Required repository secret:

- `HOMEY_PAT`  
  Create it at: https://tools.developer.homey.app/me

## Publish Checklist (Homey App Store)

1. Validate locally:
   - `npm run lint`
   - `npm run validate`
2. Update version and changelog:
   - `homey app version patch` (or minor/major)
3. Ensure metadata is correct:
   - `.homeycompose/app.json` (name, description, author, images, brandColor)
4. Push to GitHub.
5. Optionally run version/publish workflows.
6. Publish:
   - `homey app publish`

## Notes About ICMP

- If Homey runtime has no `ping` binary, ICMP-only mode cannot work.
- In that case use `AUTO` or `TCP only`.
- For strict ICMP, the target device must reply to echo requests (firewall/network policy may block this).

## License

GPL-3.0 (see [`LICENSE`](./LICENSE)).

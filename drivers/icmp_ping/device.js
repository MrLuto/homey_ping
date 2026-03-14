'use strict';

const Homey = require('homey');
const net = require('net');
const { spawn } = require('child_process');

module.exports = class IcmpPingDevice extends Homey.Device {

  async onInit() {
    this.log(`Ping device gestart: ${this.getName()}`);

    this._interval = null;
    this._isPinging = false;
    this._online = false;

    if (!this.hasCapability('ping_status')) {
      await this.addCapability('ping_status');
    }

    if (this.hasCapability('alarm_generic')) {
      await this.removeCapability('alarm_generic');
    }

    this.registerCapabilityListener('onoff', async () => {
      await this.pingNow({ triggerFlows: true });
      return this._online;
    });

    await this.setAvailable();
    this.startPolling();
    await this.pingNow({ triggerFlows: false });
  }

  async onAdded() {
    this.log('Ping device toegevoegd');
    await this.pingNow({ triggerFlows: false });
  }

  async onSettings({ changedKeys }) {
    if (
      changedKeys.includes('host')
      || changedKeys.includes('interval')
      || changedKeys.includes('timeout')
      || changedKeys.includes('probe_mode')
      || changedKeys.includes('tcp_port')
    ) {
      this.startPolling();
      await this.pingNow({ triggerFlows: false });
    }
  }

  async onDeleted() {
    this.stopPolling();
    this.log('Ping device verwijderd');
  }

  isOnline() {
    return this._online;
  }

  getHost() {
    const { host } = this.getSettings();
    return String(host || '').trim();
  }

  startPolling() {
    this.stopPolling();

    const intervalSeconds = this._clampNumber(this.getSettings().interval, 30, 5, 3600);
    this.log('[ping]', this.getHost() || '(geen host)', `polling gestart: elke ${intervalSeconds}s`);
    // eslint-disable-next-line homey-app/global-timers
    this._interval = setInterval(() => {
      this.log('[ping]', this.getHost() || '(geen host)', 'interval tick');
      this.pingNow({ triggerFlows: true }).catch((error) => this.error(error));
    }, intervalSeconds * 1000);
  }

  stopPolling() {
    if (this._interval) {
      clearInterval(this._interval);
      this._interval = null;
      this.log('[ping]', this.getHost() || '(geen host)', 'polling gestopt');
    }
  }

  async pingNow({ triggerFlows = true } = {}) {
    const host = this.getHost();
    if (!host) {
      await this.setAvailable();
      await this.setWarning(this.homey.__('errors.no_host'));
      await this._applyOnlineState(false, triggerFlows);
      this.log('[ping]', 'geen host ingesteld');
      return false;
    }

    if (this._isPinging) {
      this.log('[ping]', host, 'skip: ping al bezig');
      return this._online;
    }

    this._isPinging = true;
    this.log('[ping]', host, 'start');

    try {
      const timeoutMs = this._clampNumber(this.getSettings().timeout, 5000, 1000, 15000);
      const probeMode = this._getProbeMode();
      const tcpPort = this._clampNumber(this.getSettings().tcp_port, 443, 1, 65535);
      const online = await this._probeHost(host, timeoutMs, probeMode, tcpPort);
      await this.setAvailable();
      if (online) {
        await this.unsetWarning();
      } else {
        await this.setWarning(this.homey.__('errors.no_reply'));
      }
      await this._applyOnlineState(online, triggerFlows);
      this.log('[ping]', host, `resultaat: ${online ? 'ONLINE' : 'OFFLINE'}`);
      return online;
    } catch (error) {
      this.error('Ping mislukt', error);
      const reason = this._formatError(error);
      await this.setAvailable();
      await this.setWarning(`${this.homey.__('errors.ping_failed')}: ${reason}`.slice(0, 255));
      await this._applyOnlineState(false, triggerFlows);
      this.error('[ping]', host, `fout: ${reason}`);
      return false;
    } finally {
      this._isPinging = false;
      this.log('[ping]', host, 'einde');
    }
  }

  async _probeHost(host, timeoutMs, probeMode, tcpPort) {
    if (probeMode === 'tcp') {
      return this._probeTcpHost(host, tcpPort, timeoutMs);
    }

    if (probeMode === 'icmp') {
      return this._probeIcmpHost(host, timeoutMs);
    }

    try {
      return await this._probeIcmpHost(host, timeoutMs);
    } catch (error) {
      const isIcmpUnavailable = error && (error.code === 'ENOENT' || String(error.message || '').includes('ENOENT'));
      if (!isIcmpUnavailable) {
        throw error;
      }

      this.log('[ping]', host, `ICMP niet beschikbaar, fallback naar TCP:${tcpPort}`);
      return this._probeTcpHost(host, tcpPort, timeoutMs);
    }
  }

  async _probeIcmpHost(host, timeoutMs) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      this.log('[ping]', host, `attempt ${attempt + 1}/2`);
      const online = await this._probeIcmpHostOnce(host, timeoutMs, attempt + 1);
      if (online) {
        return true;
      }
    }

    return false;
  }

  async _probeIcmpHostOnce(host, timeoutMs, attempt) {
    const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
    const pingArgs = ['-n', '-c', '1', '-W', String(timeoutSec), host];
    const candidates = this._getPingCandidates(pingArgs);

    for (const candidate of candidates) {
      try {
        return await this._runPingProcess(host, timeoutMs, attempt, candidate.command, candidate.args);
      } catch (error) {
        const isNotFound = error && (error.code === 'ENOENT' || String(error.message || '').includes('ENOENT'));
        if (isNotFound) {
          this.log('[ping]', host, `attempt ${attempt}: command niet gevonden: ${candidate.command}`);
          continue;
        }

        throw error;
      }
    }

    const missingErr = new Error('Geen ping binary gevonden');
    missingErr.code = 'ENOENT';
    throw missingErr;
  }

  async _probeTcpHost(host, port, timeoutMs) {
    this.log('[ping]', host, `tcp probe start: port ${port}`);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const online = await this._probeTcpHostOnce(host, port, timeoutMs, attempt + 1);
      if (online) {
        return true;
      }
    }

    return false;
  }

  async _probeTcpHostOnce(host, port, timeoutMs, attempt) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let settled = false;

      const finalize = (online) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(online);
      };

      socket.setTimeout(timeoutMs);

      socket.once('connect', () => {
        this.log('[ping]', host, `tcp attempt ${attempt}: connect OK op ${port}`);
        finalize(true);
      });

      socket.once('timeout', () => {
        this.log('[ping]', host, `tcp attempt ${attempt}: timeout ${timeoutMs}ms op ${port}`);
        finalize(false);
      });

      socket.once('error', (error) => {
        const code = error && error.code ? error.code : 'UNKNOWN';
        this.log('[ping]', host, `tcp attempt ${attempt}: error ${code}`);

        if (code === 'ECONNREFUSED') {
          // Host is bereikbaar, poort is dicht.
          finalize(true);
          return;
        }

        finalize(false);
      });

      socket.connect(port, host);
      this.log('[ping]', host, `tcp attempt ${attempt}: connect ${host}:${port}`);
    });
  }

  _getPingCandidates(pingArgs) {
    return [
      { command: 'ping', args: pingArgs },
      { command: '/bin/ping', args: pingArgs },
      { command: '/usr/bin/ping', args: pingArgs },
      { command: '/sbin/ping', args: pingArgs },
      { command: '/system/bin/ping', args: pingArgs },
      { command: 'busybox', args: ['ping', ...pingArgs] },
      { command: '/bin/busybox', args: ['ping', ...pingArgs] },
      { command: '/usr/bin/busybox', args: ['ping', ...pingArgs] },
    ];
  }

  async _runPingProcess(host, timeoutMs, attempt, command, args) {
    return new Promise((resolve, reject) => {
      this.log('[ping]', host, `attempt ${attempt}: exec ${command} ${args.join(' ')}`);
      const child = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        // eslint-disable-next-line prefer-object-spread
        env: Object.assign({}, process.env, {
          PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        }),
      });

      let stdout = '';
      let stderr = '';
      let settled = false;

      // eslint-disable-next-line homey-app/global-timers
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGKILL');
        this.log('[ping]', host, `attempt ${attempt}: timeout na ${timeoutMs}ms`);
        if (stdout.trim()) this.log('[ping]', host, `attempt ${attempt}: stdout:\n${stdout.trim()}`);
        if (stderr.trim()) this.log('[ping]', host, `attempt ${attempt}: stderr:\n${stderr.trim()}`);
        resolve(false);
      }, timeoutMs);

      if (child.stdout) {
        child.stdout.on('data', (chunk) => {
          stdout += String(chunk);
        });
      }

      if (child.stderr) {
        child.stderr.on('data', (chunk) => {
          stderr += String(chunk);
        });
      }

      child.on('error', (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.error('[ping]', host, `attempt ${attempt}: spawn error (${command}): ${error.message || String(error)}`);
        reject(error);
      });

      child.on('close', (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.log('[ping]', host, `attempt ${attempt}: close code=${code} signal=${signal || 'none'}`);
        if (stdout.trim()) this.log('[ping]', host, `attempt ${attempt}: stdout:\n${stdout.trim()}`);
        if (stderr.trim()) this.log('[ping]', host, `attempt ${attempt}: stderr:\n${stderr.trim()}`);

        if (code === 0) {
          resolve(true);
          return;
        }

        const outputLower = `${stdout}\n${stderr}`.toLowerCase();
        if (outputLower.includes('1 received') || outputLower.includes('bytes from')) {
          resolve(true);
          return;
        }

        if (
          outputLower.includes('operation not permitted')
          || outputLower.includes('permission denied')
          || outputLower.includes('not found')
          || outputLower.includes('unknown host')
          || outputLower.includes('bad address')
        ) {
          reject(new Error(stderr.trim() || stdout.trim() || `ping exited with code ${code}`));
          return;
        }

        resolve(false);
      });
    });
  }

  async _applyOnlineState(online, triggerFlows) {
    const changed = this._online !== online;
    this._online = online;

    await this.setCapabilityValue('onoff', online);
    await this.setCapabilityValue('ping_status', online ? 'online' : 'offline');

    if (!changed || !triggerFlows) {
      return;
    }

    if (online) {
      await this.driver.triggerBecameOnline(this);
      return;
    }

    await this.driver.triggerBecameOffline(this);
  }

  _clampNumber(value, fallback, min, max) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) {
      return fallback;
    }

    return Math.min(max, Math.max(min, parsed));
  }

  _formatError(error) {
    if (!error) return this.homey.__('errors.unknown_error');
    if (typeof error === 'string') return error;
    if (error.message) return error.message;
    return this.homey.__('errors.unknown_error');
  }

  _getProbeMode() {
    const mode = String(this.getSettings().probe_mode || 'auto').toLowerCase();
    if (mode === 'icmp' || mode === 'tcp') {
      return mode;
    }

    return 'auto';
  }

};

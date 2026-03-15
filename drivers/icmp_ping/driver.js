'use strict';

const Homey = require('homey');
const os = require('os');
const dns = require('dns').promises;
const fs = require('fs/promises');
const net = require('net');
const { spawn } = require('child_process');

const DEFAULT_INTERVAL = 30;
const DEFAULT_TIMEOUT = 2000;
const DEFAULT_TCP_PORT = 443;
const DISCOVERY_TCP_TIMEOUT_MS = 220;
const DISCOVERY_CONCURRENCY = 256;
const DISCOVERY_MAX_HOSTS = 70000;
const DISCOVERY_SCAN_PORTS = [443];
const HOSTNAME_LOOKUP_TIMEOUT_MS = 700;
const HOSTNAME_LOOKUP_CONCURRENCY = 32;

module.exports = class IcmpPingDriver extends Homey.Driver {
  async onInit() {
    this.log('ICMP ping driver gestart');

    this._becameOnlineCard = this.homey.flow.getDeviceTriggerCard('became-online');
    this._becameOfflineCard = this.homey.flow.getDeviceTriggerCard('became-offline');

    this.homey.flow
      .getConditionCard('is-online')
      .registerRunListener(async ({ device }) => device.isOnline());

    this.homey.flow
      .getConditionCard('is-offline')
      .registerRunListener(async ({ device }) => !device.isOnline());

    this.homey.flow
      .getActionCard('ping-now')
      .registerRunListener(async ({ device }) => device.pingNow({ triggerFlows: true }));
  }

  async onPair(session) {
    session.setHandler('list_devices', async () => {
      const discovered = await this._discoverNetworkDevices();
      return discovered
        .filter((item) => !item.alreadyAdded)
        .map((item) => item.device);
    });

    session.setHandler('discover_devices', async () => {
      return this._discoverNetworkDevices();
    });
  }

  async triggerBecameOnline(device) {
    await this._becameOnlineCard.trigger(device);
  }

  async triggerBecameOffline(device) {
    await this._becameOfflineCard.trigger(device);
  }

  async _discoverNetworkDevices() {
    const discovered = new Map();

    this._logLocalNetworkContext();

    await this._collectArpEntries(discovered);

    const scanTargets = this._buildScanTargets();
    if (scanTargets.length > 0) {
      this.log(`[pair] discovery scan start (${scanTargets.length} hosts)`);
      const scanHits = await this._scanSubnet(scanTargets);
      for (const ip of scanHits) {
        this._mergeDiscoveredEntry(discovered, { ip, source: 'tcp-scan' });
      }
    } else {
      this.log('[pair] discovery scan overgeslagen: geen lokale subnetten gevonden');
    }

    await this._enrichHostnames(discovered);
    await this._collectArpEntries(discovered, { skipMacIfHostname: true });
    this.log(`[pair] discovery scan klaar (${discovered.size} kandidaten)`);

    const existingHosts = this._getExistingHosts();
    const results = Array.from(discovered.values())
      .map((entry) => this._toDiscoveredItem(entry, existingHosts))
      .sort((a, b) => this._compareIp(a.host, b.host));

    return results;
  }

  async _collectArpEntries(discovered, options = {}) {
    const parsers = [
      () => this._readProcArp(),
      () => this._readIpNeigh(),
      () => this._readArpCommand(),
    ];

    for (const parser of parsers) {
      try {
        const entries = await parser();
        for (const entry of entries) {
          this._mergeDiscoveredEntry(discovered, entry, options);
        }
      } catch (error) {
        this.log('[pair] discovery parser fout:', error.message || String(error));
      }
    }
  }

  async _readProcArp() {
    let raw = '';
    try {
      raw = await fs.readFile('/proc/net/arp', 'utf8');
    } catch (error) {
      return [];
    }

    const lines = raw.split('\n').slice(1);
    const entries = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const cols = trimmed.split(/\s+/);
      if (cols.length < 6) continue;

      const ip = cols[0];
      const mac = cols[3];
      const flags = cols[2];

      if (!this._isIpv4(ip)) continue;
      if (!this._isValidMac(mac)) continue;
      if (flags !== '0x2') continue;

      entries.push({ ip, mac, source: 'proc-arp' });
    }

    return entries;
  }

  async _readIpNeigh() {
    const output = await this._runCommandCandidates([
      { command: 'ip', args: ['neigh'] },
      { command: '/sbin/ip', args: ['neigh'] },
      { command: '/usr/sbin/ip', args: ['neigh'] },
      { command: 'busybox', args: ['ip', 'neigh'] },
    ]);

    if (!output) return [];

    const entries = [];
    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/^(\d+\.\d+\.\d+\.\d+).*\slladdr\s([0-9a-f:]{17})\s/i);
      if (match) {
        const ip = match[1];
        const mac = match[2].toLowerCase();
        if (!this._isIpv4(ip) || !this._isValidMac(mac)) continue;
        entries.push({ ip, mac, source: 'ip-neigh' });
        continue;
      }

      // Some environments expose entries without lladdr (e.g. stale cache states).
      const fallbackMatch = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+/);
      if (!fallbackMatch) continue;
      if (/FAILED|INCOMPLETE/i.test(line)) continue;
      const ip = fallbackMatch[1];
      if (!this._isIpv4(ip)) continue;
      entries.push({ ip, source: 'ip-neigh' });
    }

    return entries;
  }

  async _readArpCommand() {
    const output = await this._runCommandCandidates([
      { command: 'arp', args: ['-an'] },
      { command: '/usr/sbin/arp', args: ['-an'] },
      { command: '/sbin/arp', args: ['-an'] },
      { command: 'busybox', args: ['arp', '-a'] },
    ]);

    if (!output) return [];

    const entries = [];
    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})/i);
      if (!match) continue;
      const ip = match[1];
      const mac = match[2].toLowerCase();
      if (!this._isIpv4(ip) || !this._isValidMac(mac)) continue;
      entries.push({ ip, mac, source: 'arp-cmd' });
    }

    return entries;
  }

  async _runCommandCandidates(candidates) {
    for (const candidate of candidates) {
      try {
        const output = await this._runCommand(candidate.command, candidate.args);
        if (output && output.trim()) {
          return output;
        }
      } catch (error) {
        // Ignore and try next candidate.
      }
    }

    return '';
  }

  async _runCommand(command, args) {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let settled = false;

      // eslint-disable-next-line homey-app/global-timers
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGKILL');
        reject(new Error(`Command timeout: ${command}`));
      }, 3000);

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
        reject(error);
      });

      child.on('close', (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (code === 0 || stdout.trim()) {
          resolve(stdout);
          return;
        }
        reject(new Error(stderr || `${command} exited with code ${code}`));
      });
    });
  }

  _buildScanTargets() {
    const interfaces = os.networkInterfaces();
    const targets = new Set();

    for (const ifaceName of Object.keys(interfaces)) {
      const ifaceRecords = interfaces[ifaceName] || [];
      for (const iface of ifaceRecords) {
        const family = String(iface.family || '').toLowerCase();
        if (family !== 'ipv4' && iface.family !== 4) continue;
        if (iface.internal) continue;

        const subnetTargets = this._targetsForInterface(iface.address, iface.netmask);
        for (const ip of subnetTargets) {
          targets.add(ip);
          if (targets.size >= DISCOVERY_MAX_HOSTS) {
            return Array.from(targets);
          }
        }
      }
    }

    this._logScanTargetSummary(targets);
    return Array.from(targets);
  }

  _logLocalNetworkContext() {
    const interfaces = os.networkInterfaces();
    const lines = [];

    for (const ifaceName of Object.keys(interfaces)) {
      const ifaceRecords = interfaces[ifaceName] || [];
      for (const iface of ifaceRecords) {
        const family = String(iface.family || '').toLowerCase();
        if (family !== 'ipv4' && iface.family !== 4) continue;
        if (!iface.address || !iface.netmask) continue;

        const network = this._calculateNetworkAddress(iface.address, iface.netmask);
        const prefix = this._netmaskToPrefix(iface.netmask);
        const internalLabel = iface.internal ? 'internal' : 'external';
        const networkLabel = network ? `${network}/${prefix}` : 'unknown';
        lines.push(`${ifaceName}: ${iface.address}/${prefix} net=${networkLabel} (${internalLabel})`);
      }
    }

    if (lines.length === 0) {
      this.log('[pair] lokale IPv4 interfaces: geen');
      return;
    }

    this.log('[pair] lokale IPv4 interfaces:');
    for (const line of lines) {
      this.log(`[pair]   ${line}`);
    }
  }

  _logScanTargetSummary(targets) {
    let tenCount = 0;
    let oneSevenTwoCount = 0;
    let oneNineTwoCount = 0;

    for (const ip of targets) {
      if (ip.startsWith('10.')) tenCount += 1;
      else if (ip.startsWith('172.')) oneSevenTwoCount += 1;
      else if (ip.startsWith('192.168.')) oneNineTwoCount += 1;
    }

    this.log(
      '[pair] scan targets:',
      `total=${targets.size}`,
      `10.x=${tenCount}`,
      `172.x=${oneSevenTwoCount}`,
      `192.168.x=${oneNineTwoCount}`
    );
  }

  _targetsForInterface(address, netmask) {
    const addressInt = this._ipToInt(address);
    const maskInt = this._ipToInt(netmask);
    if (addressInt === null || maskInt === null) return [];

    const invertedMask = (~maskInt) >>> 0;
    let hostCount = Math.max(0, invertedMask - 1);

    let startIp = ((addressInt & maskInt) + 1) >>> 0;
    let endIp = ((addressInt | invertedMask) - 1) >>> 0;

    if (hostCount > 512) {
      // Limit larger subnets to /24 to keep scan time predictable.
      const base = (addressInt & 0xffffff00) >>> 0;
      startIp = (base + 1) >>> 0;
      endIp = (base + 254) >>> 0;
      hostCount = 254;
    }

    const targets = [];
    for (let ipInt = startIp; ipInt <= endIp; ipInt += 1) {
      if (ipInt === addressInt) continue;
      targets.push(this._intToIp(ipInt));
      if (targets.length >= DISCOVERY_MAX_HOSTS) {
        break;
      }
      if (targets.length >= hostCount) {
        break;
      }
    }

    return targets;
  }

  async _scanSubnet(targetIps) {
    const hitSet = new Set();
    let index = 0;
    const workers = Array.from({ length: DISCOVERY_CONCURRENCY }).map(async () => {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const currentIndex = index;
        index += 1;
        if (currentIndex >= targetIps.length) {
          return;
        }

        const ip = targetIps[currentIndex];
        const reachable = await this._touchHost(ip);
        if (reachable) {
          hitSet.add(ip);
        }
      }
    });

    await Promise.all(workers);
    return hitSet;
  }

  async _touchHost(ip) {
    for (const port of DISCOVERY_SCAN_PORTS) {
      const result = await this._probeTcp(ip, port);
      if (result.reachable) {
        return true;
      }
    }

    return false;
  }

  async _probeTcp(host, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let finished = false;

      const done = (reachable) => {
        if (finished) return;
        finished = true;
        socket.destroy();
        resolve({ reachable });
      };

      socket.setTimeout(DISCOVERY_TCP_TIMEOUT_MS);
      socket.once('connect', () => done(true));
      socket.once('timeout', () => done(false));
      socket.once('error', (error) => {
        const code = error && error.code ? String(error.code) : '';
        // RST on closed port still means host is online.
        if (code === 'ECONNREFUSED') {
          done(true);
          return;
        }
        done(false);
      });
      socket.connect(port, host);
    });
  }

  _getExistingHosts() {
    const hosts = new Set();
    const devices = this.getDevices();
    for (const device of devices) {
      const settings = device.getSettings ? device.getSettings() : {};
      const host = String((settings && settings.host) || '').trim().toLowerCase();
      if (host) {
        hosts.add(host);
      }
    }
    return hosts;
  }

  _toDiscoveredItem(entry, existingHosts) {
    const host = entry.ip;
    const hostKey = host.toLowerCase();
    const alreadyAdded = existingHosts.has(hostKey);
    const displayName = entry.hostname
      ? `${entry.hostname} (${host})`
      : host;

    return {
      host,
      ip: host,
      hostname: entry.hostname || '',
      mac: entry.mac || '',
      name: displayName,
      alreadyAdded,
      source: Array.from(entry.sources || []).join(', '),
      device: {
        name: displayName,
        data: {
          id: this._makeDeviceId(host),
        },
        settings: {
          host,
          interval: DEFAULT_INTERVAL,
          timeout: DEFAULT_TIMEOUT,
          probe_mode: 'auto',
          tcp_port: DEFAULT_TCP_PORT,
        },
      },
    };
  }

  _mergeDiscoveredEntry(discovered, entry, options = {}) {
    if (!entry || !this._isIpv4(entry.ip)) return;
    const ip = entry.ip;
    const skipMacIfHostname = Boolean(options.skipMacIfHostname);
    const existing = discovered.get(ip) || {
      ip,
      hostname: '',
      mac: '',
      sources: new Set(),
    };

    if (entry.hostname) {
      existing.hostname = String(entry.hostname).trim();
    }

    if (entry.mac && this._isValidMac(entry.mac) && !(skipMacIfHostname && existing.hostname)) {
      existing.mac = entry.mac.toLowerCase();
    }

    if (entry.source) {
      existing.sources.add(String(entry.source));
    }

    discovered.set(ip, existing);
  }

  _makeDeviceId(host) {
    const normalized = String(host)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
    return `icmp-${normalized || Date.now()}`;
  }

  _compareIp(a, b) {
    const ai = this._ipToInt(a);
    const bi = this._ipToInt(b);
    if (ai === null && bi === null) return String(a).localeCompare(String(b));
    if (ai === null) return 1;
    if (bi === null) return -1;
    return ai - bi;
  }

  _isIpv4(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every((part) => {
      if (!/^\d+$/.test(part)) return false;
      const n = Number(part);
      return n >= 0 && n <= 255;
    });
  }

  _isValidMac(mac) {
    if (!mac || typeof mac !== 'string') return false;
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)) return false;
    return mac !== '00:00:00:00:00:00';
  }

  _ipToInt(ip) {
    if (!this._isIpv4(ip)) return null;
    const [a, b, c, d] = ip.split('.').map(Number);
    return (((a << 24) >>> 0) + ((b << 16) >>> 0) + ((c << 8) >>> 0) + d) >>> 0;
  }

  _intToIp(intValue) {
    return [
      (intValue >>> 24) & 255,
      (intValue >>> 16) & 255,
      (intValue >>> 8) & 255,
      intValue & 255,
    ].join('.');
  }

  _calculateNetworkAddress(address, netmask) {
    const addressInt = this._ipToInt(address);
    const maskInt = this._ipToInt(netmask);
    if (addressInt === null || maskInt === null) return null;
    return this._intToIp((addressInt & maskInt) >>> 0);
  }

  _netmaskToPrefix(netmask) {
    const maskInt = this._ipToInt(netmask);
    if (maskInt === null) return 0;
    const maskBinary = maskInt.toString(2).padStart(32, '0');
    const ones = maskBinary.indexOf('0');
    if (ones === -1) return 32;
    return ones;
  }

  async _enrichHostnames(discovered) {
    const entries = Array.from(discovered.values()).filter((entry) => !entry.hostname && entry.ip);
    if (entries.length === 0) return;

    this.log(`[pair] hostname lookup start (${entries.length} hosts)`);

    let index = 0;
    const workers = Array.from({ length: HOSTNAME_LOOKUP_CONCURRENCY }).map(async () => {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const currentIndex = index;
        index += 1;
        if (currentIndex >= entries.length) {
          return;
        }

        const entry = entries[currentIndex];
        const hostname = await this._resolveHostname(entry.ip);
        if (hostname) {
          entry.hostname = hostname;
          this.log(`[pair] hostname ${entry.ip} -> ${hostname}`);
        }
      }
    });

    await Promise.all(workers);
  }

  async _resolveHostname(ip) {
    try {
      const hostnames = await this._withTimeout(dns.reverse(ip), HOSTNAME_LOOKUP_TIMEOUT_MS);
      if (!Array.isArray(hostnames) || hostnames.length === 0) {
        return '';
      }
      const first = String(hostnames[0] || '').trim();
      const normalized = this._normalizeHostname(first);
      return this._isUsableHostname(normalized) ? normalized : '';
    } catch (error) {
      return '';
    }
  }

  async _withTimeout(promise, timeoutMs) {
    return new Promise((resolve, reject) => {
      let settled = false;

      // eslint-disable-next-line homey-app/global-timers
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error('timeout'));
      }, timeoutMs);

      promise
        .then((value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(value);
        })
        .catch((error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  _isUsableHostname(hostname) {
    if (!hostname) return false;
    if (hostname.length > 253) return false;
    if (!/^[a-z0-9._-]+$/i.test(hostname)) return false;
    return true;
  }

  _normalizeHostname(hostname) {
    let value = String(hostname || '').trim().replace(/\.$/, '');
    value = value.replace(/\.localdomain$/i, '');
    value = value.replace(/\.local$/i, '');
    return value;
  }
};

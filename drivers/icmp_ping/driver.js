'use strict';

const Homey = require('homey');

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

  async triggerBecameOnline(device) {
    await this._becameOnlineCard.trigger(device);
  }

  async triggerBecameOffline(device) {
    await this._becameOfflineCard.trigger(device);
  }

};

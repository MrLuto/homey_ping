'use strict';

const Homey = require('homey');

module.exports = class HomeyPingApp extends Homey.App {

  async onInit() {
    this.log('Homey Ping is gestart');
  }

};

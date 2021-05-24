const BaseDevice = require('../../base/BaseDevice.js');
const HeaterProperties = require('./HeaterProperties.js');
const Constants = require('../../constants/Constants.js');
const DevTypes = require('../../constants/DevTypes.js');


class HeaterDevice extends BaseDevice {
  constructor(miioDevice, model, deviceId, name, logger) {
    super(miioDevice, model, deviceId, name, logger);
  }


  /*----------========== INIT ==========----------*/

  initialPropertyFetchDone() {
    super.initialPropertyFetchDone();
    // nothing special yet
  }


  /*----------========== INFO ==========----------*/

  getType() {
    return DevTypes.HEATER;
  }


  /*----------========== CONFIG ==========----------*/

  fanSwingModeValue() {
    return -1;
  }

  fanNotSwingModeValue() {
    return -1;
  }


  /*----------========== FEATURES ==========----------*/


  // heat levels
  supportsHeatLevels() {
    return this.hasProperty(HeaterProperties.HEAT_LEVEL);
  }
  
  // swing mode
  supportsFanSwingMode() {
    return this.fanSwingModeValue() !== -1;
  }

  supportsFanNotSwingMode() {
    return this.fanNotSwingModeValue() !== -1;
  }

  supportsSwingModes() {
    return this.supportsFanSwingMode() && this.supportsFanNotSwingMode() && this.hasProperty(HeaterProperties.MODE);
  }

  // target temperature
  supportsTargetTemperature() {
    return this.hasProperty(HeaterProperties.TARGET_TEMPERATURE);
  }

  targetTemperatureRange() {
    let range = this.getPropertyValueRange(HeaterProperties.TARGET_TEMPERATURE);
    return (range.length > 2) ? range : [10, 35, 1];
  }


  /*----------========== GETTERS ==========----------*/

  getHeatLevel() {
    return this.getPropertyValue(HeaterProperties.HEAT_LEVEL);
  }

  getTargetTemperature() {
    return this.getSafePropertyValue(HeaterProperties.TARGET_TEMPERATURE);
  }


  /*----------========== SETTERS ==========----------*/

  async setHeatLevel(level) {
    this.setPropertyValue(HeaterProperties.HEAT_LEVEL, level);
  }

  async setTargetTemperature(targetTemp) {
    this.setPropertyValue(HeaterProperties.TARGET_TEMPERATURE, targetTemp);
  }


  /*----------========== ACTIONS ==========----------*/


  /*----------========== CONVENIENCE ==========----------*/

  isFanSwingModeEnabled() {
    if (this.supportsFanSwingMode()) {
      return this.getMode() === this.fanSwingModeValue();
    }
    return false;
  }

  isFanNotSwingModeEnabled() {
    if (this.supportsFanNotSwingMode()) {
      return this.getMode() === this.fanNotSwingModeValue();
    }
    return false;
  }

  async enableFanSwingMode() {
    if (this.supportsFanSwingMode()) {
      this.setMode(this.fanSwingModeValue());
    }
  }

  async enableFanNotSwingMode() {
    if (this.supportsFanNotSwingMode()) {
      this.setMode(this.fanNotSwingModeValue());
    }
  }

  isHeating() {
    return this.isPowerOn();
  }


  /*----------========== HELPERS ==========----------*/


}

module.exports = HeaterDevice;

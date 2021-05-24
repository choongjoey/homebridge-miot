const MiotDevice = require('../protocol/MiotDevice.js');
const Properties = require('../constants/Properties.js');
const Constants = require('../constants/Constants.js');
const DevTypes = require('../constants/DevTypes.js');
const PropFormat = require('../constants/PropFormat.js');
const PropUnit = require('../constants/PropUnit.js');
const PropAccess = require('../constants/PropAccess.js');

// DEVICES: http://miot-spec.org/miot-spec-v2/instances?status=released

class BaseDevice extends MiotDevice {
  constructor(miioDevice, model, deviceId, name, logger) {
    super(miioDevice, model, deviceId, name, logger);
  }


  /*----------========== INIT ==========----------*/

  initDeviceProperties() {
    //implemented by superclasses
  }

  initialPropertyFetchDone() {
    // log the the use time when supported
    if (this.supportsUseTimeReporting()) {
      this.logger.info(`Use time: ${this.getUseTime()} minutes.`);
    }
  }


  /*----------========== INFO ==========----------*/

  getType() {
    return DevTypes.UNKNOWN;
  }

  /*----------========== CONFIG ==========----------*/

  hasBuiltInBattery() {
    return false;
  }

  emulateSteplessFanSpeed() {
    return false;
  }

  chargingStateChargingValue() {
    return -1;
  }

  chargingStateNotChargingValue() {
    return -1;
  }

  chargingStateGoChargingValue() {
    return -1;
  }


  /*----------========== FEATURES ==========----------*/

  // power
  supportsPowerControl() {
    return this.hasProperty(Properties.POWER);
  }

  // child lock
  supportsChildLock() {
    return this.hasProperty(Properties.CHILD_LOCK);
  }

  // power off timer
  supportsPowerOffTimer() {
    return this.hasProperty(Properties.POWER_OFF_TIME);
  }

  powerOffTimerUnit() {
    return this.supportsPowerOffTimer() ? this.properties[Properties.POWER_OFF_TIME].getUnit() : PropUnit.MINUTES;
  }

  powerOffTimerRange() {
    return this.getPropertyValueRange(Properties.POWER_OFF_TIME);
  }

  // alarm
  supportsBuzzerControl() {
    return this.hasProperty(Properties.ALARM);
  }

  // led
  supportsLedControl() {
    return this.hasProperty(Properties.LED);
  }

  ledControlRange() {
    return this.getPropertyValueRange(Properties.LED);
  }

  supportsLedControlRange() {
    return this.ledControlRange().length > 0;
  }

  supportsLedControlBrightness() {
    return this.supportsLedControlRange() && this.ledControlRange()[1] === 100 && this.properties[Properties.LED].getUnit() === PropUnit.PERCENTAGE;
  }

  ledControlList() {
    return this.getPropertyValueList(Properties.LED);
  }

  supportsLedControlList() {
    return this.ledControlList().length > 0;
  }

  // screen
  supportsScreenControl() {
    return this.hasProperty(Properties.SCREEN_BRIGHTNESS);
  }

  screenBrightnessRange() {
    return this.getPropertyValueRange(Properties.SCREEN_BRIGHTNESS);
  }

  supportsScreenBrightnessRange() {
    return this.screenBrightnessRange().length > 0;
  }

  screenBrightnessList() {
    return this.getPropertyValueList(Properties.SCREEN_BRIGHTNESS);
  }

  supportsScreenBrightnessList() {
    return this.screenBrightnessList().length > 0;
  }

  // modes
  supportsModes() {
    return this.hasProperty(Properties.MODE);
  }

  // fan levels
  fanLevels() {
    return this.getPropertyValueList(Properties.FAN_LEVEL);
  }

  supportsFanLevels() {
    return this.fanLevels().length > 0;
  }

  //fan speed
  supportsSteplesFanSpeed() {
    return this.hasProperty(Properties.FAN_SPEED);
  }

  supportsSteplessFanSpeedEmulation() {
    return this.supportsSteplesFanSpeed() === false && this.emulateSteplessFanSpeed() && this.supportsFanLevels();
  }

  supportsRotationSpeed() {
    return this.supportsSteplesFanSpeed() || this.supportsSteplessFanSpeedEmulation();
  }

  //fan speed rpm
  supportsFanSpeedRpmReporting() {
    return this.hasProperty(Properties.FAN_SPEED_RPM);
  }

  // brightness
  supportsBrightness() {
    return this.hasProperty(Properties.BRIGHTNESS);
  }

  // color temp
  supportsColorTemp() {
    return this.hasProperty(Properties.COLOR_TEMP);
  }

  // temperature
  supportsTemperatureReporting() {
    return this.hasProperty(Properties.TEMPERATURE);
  }

  // relative humidity
  supportsRelativeHumidityReporting() {
    return this.hasProperty(Properties.RELATIVE_HUMIDITY);
  }

  // status
  supportsStatusReporting() {
    return this.hasProperty(Properties.STATUS);
  }

  // battery
  supportsBatteryLevelReporting() {
    return this.hasProperty(Properties.BATTERY_LEVEL);
  }

  supportsBatteryPowerReporting() {
    return this.hasProperty(Properties.BATTERY_POWER);
  }

  supportsAcPowerReporting() {
    return this.hasProperty(Properties.AC_POWER);
  }

  //charging state
  supportsChargingStateReporting() {
    return this.hasProperty(Properties.CHARGING_STATE);
  }

  // use time
  supportsUseTimeReporting() {
    return this.hasProperty(Properties.USE_TIME);
  }

  useTimeUnit() {
    return this.supportsUseTimeReporting() ? this.properties[Properties.USE_TIME].getUnit() : PropUnit.MINUTES;
  }


  /*----------========== GETTERS ==========----------*/

  isPowerOn() {
    return this.getPropertyValue(Properties.POWER);
  }

  isChildLockActive() {
    return this.getPropertyValue(Properties.CHILD_LOCK);
  }

  isBuzzerEnabled() {
    return this.getPropertyValue(Properties.ALARM);
  }

  getLedValue() {
    return this.getPropertyValue(Properties.LED);
  }

  getLedPercentage() {
    let ledPercentage = this.convertPropValueToPercentage(Properties.LED);
    if (this.supportsLedControlBrightness()) {
      return ledPercentage;
    }
    return 100 - ledPercentage; // last one in value range is usually off so we need to reverse the value
  }

  getScreenBrightnessValue() {
    return this.getPropertyValue(Properties.SCREEN_BRIGHTNESS);
  }

  getScreenBrightnessPercentage() {
    return this.convertPropValueToPercentage(Properties.SCREEN_BRIGHTNESS);
  }

  getShutdownTimer() {
    let value = this.getPropertyValue(Properties.POWER_OFF_TIME);
    value = this.convertToMinutes(value, this.powerOffTimerUnit());
    return value;
  }

  getMode() {
    return this.getPropertyValue(Properties.MODE);
  }

  getFanLevel() {
    return this.getPropertyValue(Properties.FAN_LEVEL);
  }

  getFanSpeed() {
    if (this.supportsSteplessFanSpeedEmulation()) {
      let numberOfFanLevels = this.fanLevels().length;
      let speedPerLevel = Math.floor(100 / numberOfFanLevels);
      return speedPerLevel * this.getFanLevel();
    }
    return this.getPropertyValue(Properties.FAN_SPEED);
  }

  getBrightness() {
    return this.getSafePropertyValue(Properties.BRIGHTNESS);
  }

  getColorTemp() {
    let colorTempKelvin = this.getSafePropertyValue(Properties.COLOR_TEMP);
    let miredVal = 140; // default val, default min for characteristic, needs to be calculated from prop range
    if (colorTempKelvin > 0) {
      miredVal = 1000000 / colorTempKelvin;
    }
    return miredVal;
  }

  getTemperature() {
    return this.getPropertyValue(Properties.TEMPERATURE);
  }

  getRelativeHumidity() {
    return this.getPropertyValue(Properties.RELATIVE_HUMIDITY);
  }

  getStatus() {
    return this.getPropertyValue(Properties.STATUS);
  }

  isOnBatteryPower() {
    return this.getPropertyValue(Properties.BATTERY_POWER);
  }

  getBatteryLevel() {
    return this.getPropertyValue(Properties.BATTERY_LEVEL);
  }

  getChargingState() {
    return this.getPropertyValue(Properties.CHARGING_STATE);
  }

  getUseTime() {
    let useTime = this.getPropertyValue(Properties.USE_TIME);
    useTime = this.convertToMinutes(useTime, this.useTimeUnit());
    return useTime;
  }

  getFanSpeedRpm() {
    return this.getPropertyValue(Properties.FAN_SPEED_RPM);
  }


  /*----------========== SETTERS ==========----------*/

  async setPowerOn(power) {
    this.setPropertyValue(Properties.POWER, power);
  }

  async setChildLock(active) {
    this.setPropertyValue(Properties.CHILD_LOCK, active);
  }

  async setBuzzerEnabled(enabled) {
    this.setPropertyValue(Properties.ALARM, enabled);
  }

  async setLedValue(value) {
    this.setPropertyValue(Properties.LED, value);
  }

  async setLedPercentage(percentage) {
    let adjustedPercentage = percentage;
    if (this.supportsLedControlRange() && this.supportsLedControlBrightness() === false) {
      adjustedPercentage = 100 - adjustedPercentage; // last one in value range is usually off so we need to reverse the value
    }
    this.setLedValue(this.convertPercentageToPropValue(adjustedPercentage, Properties.LED));
  }

  async setScreenBrightnessValue(value) {
    this.setPropertyValue(Properties.SCREEN_BRIGHTNESS, value);
  }

  async setScreenBrightnessPercentage(percentage) {
    this.setScreenBrightnessValue(this.convertPercentageToPropValue(percentage, Properties.SCREEN_BRIGHTNESS));
  }

  async setShutdownTimer(minutes) {
    let value = this.convertMinutesToUnit(minutes, this.powerOffTimerUnit());
    this.setPropertyValue(Properties.POWER_OFF_TIME, value);
  }

  async setMode(mode) {
    this.setPropertyValue(Properties.MODE, mode);
  }

  async setFanLevel(level) {
    this.setPropertyValue(Properties.FAN_LEVEL, level);
  }

  async setFanSpeed(speed) {
    if (this.supportsSteplesFanSpeed()) {
      this.setPropertyValue(Properties.FAN_SPEED, speed);
    } else if (this.supportsSteplessFanSpeedEmulation()) {
      let levelToSet = this.convertFanSpeedToFanLevel(speed);
      this.setFanLevel(levelToSet);
    }
  }

  async setBrightness(value) {
    this.setPropertyValue(Properties.BRIGHTNESS, value);
  }

  async setColorTemp(miredVal) {
    let kelvinVal = 3000; // default val, needs to be calculated from prop range
    if (miredVal > 0) {
      kelvinVal = 1000000 / miredVal;
    }
    this.setPropertyValue(Properties.COLOR_TEMP, kelvinVal);
  }

  /*----------========== ACTIONS ==========----------*/

  getActionFriendlyName(actionName) {
    if (actionName && actionName.length > 0) {
      return actionName.split('_').map((item) => {
        return item.charAt(0).toUpperCase() + item.substring(1);
      }).join(' ');
    }
    return actionName;
  }


  /*----------========== CONVENIENCE ==========----------*/

  isLedEnabled() {
    if (this.supportsLedControlBrightness()) {
      return this.getLedValue() > 0;
    } else if (this.supportsLedControlRange()) {
      let minLevel = this.ledControlRange()[0];
      let maxLevel = this.ledControlRange()[1];
      return this.getLedValue() !== maxLevel; // last one is usually off
    }
    return this.getLedValue();
  }

  async setLedEnabled(enabled) {
    let value = enabled;
    if (this.supportsLedControlRange()) {
      let minLevel = this.ledControlRange()[0];
      let maxLevel = this.ledControlRange()[1];
      if (this.supportsLedControlBrightness()) {
        // if percentage then highest is full brightness, lowest is off
        value = enabled ? maxLevel : minLevel;
      } else if (this.supportsLedControlRange()) {
        // if a list then lowest is usually full brightness and highest is usually off
        value = enabled ? minLevel : maxLevel;
      }
    }
    this.setLedValue(value);
  }

  isScreenEnabled() {
    if (this.supportsScreenBrightnessRange()) {
      return this.getScreenBrightnessValue() > 0; // if value greater then 0 then usually it is on
    }
    return this.getScreenBrightnessValue();
  }


  async setScreenEnabled(enabled) {
    let value = enabled;
    if (this.supportsScreenBrightnessRange()) {
      let minLevel = this.screenBrightnessRange()[0];
      let maxLevel = this.screenBrightnessRange()[1];
      value = enabled ? maxLevel : minLevel;
    }
    this.setScreenBrightnessValue(value);
  }

  isShutdownTimerEnabled() {
    return this.getShutdownTimer() > 0;
  }

  isCharging() {
    return this.getChargingState() === this.chargingStateChargingValue();
  }

  isNotCharging() {
    return this.getChargingState() === this.chargingStateNotChargingValue();
  }

  isGoCharging() {
    return this.getChargingState() === this.chargingStateGoChargingValue();
  }

  turnOnIfNecessary() {
    // if the device is turned off then turn it on
    if (this.isPowerOn() === false) {
      this.setPowerOn(true);
    }
  }


  /*----------========== HELPERS ==========----------*/

  convertToMinutes(value, unit) {
    if (unit === PropUnit.HOURS) {
      value = value * 60;
    } else if (unit === PropUnit.SECONDS) {
      value = Math.ceil(value / 60);
    }
    return value;
  }

  convertMinutesToUnit(minutes, unit) {
    let converted = minutes;
    if (unit === PropUnit.SECONDS) {
      converted = minutes * 60;
    } else if (unit === PropUnit.HOURS) {
      converted = Math.ceil(minutes / 60);
    }
    return converted;
  }

  convertFanSpeedToFanLevel(fanSpeed) {
    let numberOfFanLevels = this.fanLevels().length;
    let firstValue = this.fanLevels()[0].value;
    let lastValue = this.fanLevels()[numberOfFanLevels - 1].value;
    let speedPerLevel = Math.floor(100 / numberOfFanLevels);
    let level = Math.floor(fanSpeed / speedPerLevel);
    level = firstValue + level; // sometimes the levels do not start at value 0
    if (level > lastValue) level = lastValue; // make sure we stay in range
    return level;
  }

  convertPropValueToPercentage(propName) {
    let prop = this.getProperty(propName);
    if (prop && prop.hasValueRange()) {
      let propValue = prop.getSafeValue();
      let propValRange = prop.getValueRange();
      if (propValRange.length > 1) {
        let from = propValRange[0];
        let to = propValRange[1];
        let valuePercentage = (((propValue - from) * 100) / to - from);
        return Math.round(valuePercentage);
      }
      return propValue;
    }
    return null;
  }

  convertPercentageToPropValue(percentage, propName) {
    let prop = this.getProperty(propName);
    if (prop && prop.hasValueRange()) {
      let propValRange = prop.getValueRange();
      if (propValRange.length > 1) {
        let from = propValRange[0];
        let to = propValRange[1];
        let value = (percentage * (to - from) / 100) + from;
        return Math.round(value);
      }
    }
    return percentage;
  }


}

module.exports = BaseDevice;

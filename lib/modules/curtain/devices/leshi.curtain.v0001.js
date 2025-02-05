const CurtainDevice = require('../CurtainDevice.js');
const CurtainProperties = require('../CurtainProperties.js');
const Actions = require('../../../constants/Actions.js');
const Constants = require('../../../constants/Constants.js');
const PropFormat = require('../../../constants/PropFormat.js');
const PropUnit = require('../../../constants/PropUnit.js');
const PropAccess = require('../../../constants/PropAccess.js');

// Spec:
// http://miot-spec.org/miot-spec-v2/instance?type=urn:miot-spec-v2:device:curtain:0000A00C:leshi-v0001:2


class LeshiCurtainV0001 extends CurtainDevice {
  constructor(miioDevice, model, deviceId, name, logger) {
    super(miioDevice, model, deviceId, name, logger);
  }


  /*----------========== INIT ==========----------*/

  initDeviceProperties() {
    // READ/WRITE
    this.addProperty(CurtainProperties.POWER, 2, 3, PropFormat.BOOL, PropAccess.READ_WRITE_NOTIFY, PropUnit.NONE);
    this.addProperty(CurtainProperties.TARGET_POSITION, 2, 6, PropFormat.UINT8, PropAccess.READ_WRITE_NOTIFY, PropUnit.PERCENTAGE, [0, 100, 1]);
    this.addProperty(CurtainProperties.MOTOR_REVERSE, 2, 4, PropFormat.BOOL, PropAccess.READ_WRITE_NOTIFY, PropUnit.NONE);

    // WRITE ONLY
    this.addProperty(CurtainProperties.MOTOR_CONTROL, 2, 2, PropFormat.UINT8, PropAccess.WRITE, PropUnit.NONE, [], [{
        "value": 0,
        "description": "Close"
      },
      {
        "value": 1,
        "description": "Pause"
      },
      {
        "value": 2,
        "description": "Open"
      }
    ]);

    // READ ONLY
    this.addProperty(CurtainProperties.DEVICE_FAULT, 2, 1, PropFormat.UINT8, PropAccess.READ_NOTIFY, PropUnit.NONE, [], [{
      "value": 0,
      "description": "Fault-free"
    }]);
    this.addProperty(CurtainProperties.CURRENT_POSITION, 2, 5, PropFormat.UINT8, PropAccess.READ_NOTIFY, PropUnit.PERCENTAGE, [0, 100, 1]);
  }

  initDeviceActions() {
    //none
  }


  /*----------========== CONFIG ==========----------*/


}

module.exports = LeshiCurtainV0001;

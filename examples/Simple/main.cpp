/**
 * Simple August Lock example, opens and closes the lock and checks lock status
 */

#include <Arduino.h>
#include <stdint.h>
#include "august.h"

bool isLocked;

AugustLock augustLock("00:00:00:00:00:00", "00000000000000000000000000000000", 1); // Lock Bluetooth address, lock handshakeKey, lock handshakeKeyIndex

//These two callback decls required here for the case of mutiple instances of AugustLock.
//It would be required to switch them here based on client address. TODO: It may be possible to fold them into the AugustLock class
void notifyCB(NimBLERemoteCharacteristic *pRemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    //If you have multiple locks you'll need to switch here using the service address: pRemoteCharacteristic->getRemoteService()->getClient()->getPeerAddress()
    augustLock._notifyCB(pRemoteCharacteristic, pData, length);
}

void secureLockCallback(NimBLERemoteCharacteristic *pRemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    augustLock._secureLockCallback(pRemoteCharacteristic, pData, length);
}


void statusCallback(const char *msg, bool status)
{
    Serial.print("Status Callback: ");
    Serial.println(msg);
    isLocked = status;
}

//Note: you may need this if you are using the lock together with a WiFi connection
//ESP32 doesn't like BlueTooth and WiFi being used together
void disconnectCallback()
{
    Serial.println("BlueTooth disconnected");
}

long checkmillis;
bool status = true;

void setup()
{
    Serial.begin(115200);
    Serial.println("Starting Arduino BLE Client application...");
    augustLock.init();

    augustLock.connect(&statusCallback, &notifyCB, &secureLockCallback, &disconnectCallback);
    checkmillis = millis();
    augustLock.lockAction(TOGGLE_LOCK); //initially toggle the lock, once connection is ready
}

void loop()
{
    augustLock.checkStatus(); //required in loop() to handle lock comms, in case of connection failure
    delay(100);

    if (millis() > (checkmillis + 1000 * 30))
    {
        LockAction act = status ? GET_STATUS : (isLocked ? UNLOCK : LOCK);
        //periodically get the status, this will trigger the 'connectCallback' above after it gets the state
        augustLock.lockAction(act);
        checkmillis = millis();
        status = !status;
    }
}

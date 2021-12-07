/**
 * A BLE client example that is rich in capabilities.
 * There is a lot new capabilities implemented.
 * author unknown
 * updated by chegewara
 * updated for NimBLE by H2zero
 */

/** NimBLE differences highlighted in comment blocks **/

#include <Arduino.h>
#include "NimBLEDevice.h"
#include <stdint.h>
#include "mbedtls/aes.h"

static BLEUUID readCharacteristic("bd4ac614-0b45-11e3-8ffd-0800200c9a66");
static BLEUUID writeCharacteristic("bd4ac613-0b45-11e3-8ffd-0800200c9a66");
static BLEUUID readCharacteristic2("bd4ac612-0b45-11e3-8ffd-0800200c9a66");
static BLEUUID writeCharacteristic2("bd4ac611-0b45-11e3-8ffd-0800200c9a66");

static BLEUUID serviceUUID("0000FE24-0000-1000-8000-00805F9B34FB");

//Your lock settings go in here!
const char *deviceAddress = "00:00:00:00:00:00";		//BlueTooth address of your smartlock
const char *handshakeKey = "00000000000000000000000000000000";  //Secret Handshake key from the setup file
static uint8_t offlineKeyOffset = 1;				//KeyOffset value from setup file (usually 1)

uint8_t *handshakeKeyBytes;

uint8_t *handshakeSessionKey; // session key
uint8_t *sessionKey;

uint8_t iv[16];   //Encrypt IV
uint8_t iv2[16];  //Decrypt IV
mbedtls_aes_context lockCypher;

bool lockIsLocked = false;
bool doLockToggle = true;
bool doneConnect = false;

static boolean connected = false;
static boolean doScan = false;
static BLERemoteCharacteristic *pWriteCharacteristic;
static BLERemoteCharacteristic *pWriteCharacteristic2;

NimBLEClient *pClient = nullptr;


void encryptMessage(uint8_t *plainText, uint8_t *encryptBuffer);
void decryptMessage(uint8_t *encryptedMessage, uint8_t *decryptBuffer);
void cbcEncryptMessage(uint8_t *plainText, uint8_t *encryptBuffer);
void cbcDecryptMessage(uint8_t *encryptedMessage, uint8_t *decryptBuffer);
void forceUnlock();
void forceLock();
void getStatus();

std::vector<char> HexToBytes(const std::string &hex)
{
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

uint8_t *BuildCommand(byte opcode)
{
    uint8_t *cmd = new byte[18];
    memset(cmd, 0, 18);
    cmd[0] = opcode;
    cmd[16] = 0x0f; // unknown
    cmd[17] = offlineKeyOffset;
    return cmd;
}

uint32_t ReadUInt32LE(uint8_t *buffer, int startIndex)
{
    return *((uint32_t *)&buffer[startIndex]);
}

void WriteUInt32LE(uint8_t *buffer, uint value, int startIndex)
{
    *((uint32_t *)&buffer[startIndex]) = value;
}

uint32_t SecSecurityChecksum(uint8_t *buffer)
{
    return (0 - (ReadUInt32LE(buffer, 0x00) + ReadUInt32LE(buffer, 0x04) + ReadUInt32LE(buffer, 0x08))) >> 0;
}

void SecWriteChecksum(uint8_t *buffer)
{
    uint32_t cs = SecSecurityChecksum(buffer);
    WriteUInt32LE(buffer, cs, 0x0c);
}

uint8_t SimpleChecksum(uint8_t *buffer)
{
    uint32_t cs = 0;
    for (int i = 0; i < 18; i++)
    {
        cs = (cs + buffer[i]) & 0xff;
    }
    return (uint8_t)((-cs) & 0xff);
}

void WriteChecksum(uint8_t *buffer)
{
    buffer[3] = SimpleChecksum(buffer);
}

void lockCmd(uint8_t *cmd, uint8_t opcode)
{
    memset(cmd, 0, 18);
    cmd[0] = 0xee; // magic
    cmd[1] = opcode;
    cmd[16] = 0x02; //unknown
}

static const char *_web3e_hexStr = "0123456789ABCDEF";

std::string ConvertBytesToHex(const uint8_t *bytes, int length)
{
    char *buffer = (char *)__builtin_alloca(length * 2 + 3);
    char *pout = buffer;
    *pout++ = '0';
    *pout++ = 'x';
    for (int i = 0; i < length; i++)
    {
        *pout++ = _web3e_hexStr[((bytes)[i] >> 4) & 0xF];
        *pout++ = _web3e_hexStr[(bytes)[i] & 0xF];
    }
    *pout = 0;
    return std::string(buffer);
}

/** Notification / Indication receiving handler callback */
void notifyCB(NimBLERemoteCharacteristic *pRemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    Serial.println("NOTIFY!!");
    std::string str = (isNotify == true) ? "Notification" : "Indication";
    str += " from ";
    /** NimBLEAddress and NimBLEUUID have std::string operators */
    str += std::string(pRemoteCharacteristic->getRemoteService()->getClient()->getPeerAddress());
    str += ": Service = " + std::string(pRemoteCharacteristic->getRemoteService()->getUUID());
    str += ", Characteristic = " + std::string(pRemoteCharacteristic->getUUID());
    str += ", Value = " + ConvertBytesToHex(pData, length); //  std::string((char*)pData, length);

    Serial.println(str.c_str());

    if (pRemoteCharacteristic->getUUID().equals(readCharacteristic))
    {
        //secure read, handshake response
        uint8_t *decryptMessageBytes = (uint8_t *)__builtin_alloca(length);
        decryptMessage(pData, decryptMessageBytes);

        Serial.print("Decrypt: ");
        Serial.println(ConvertBytesToHex(decryptMessageBytes, length).c_str());

        //check
        if (decryptMessageBytes[0] == 0x02)
        {
            Serial.println("handshake pt1 complete");
            memcpy(handshakeKeyBytes, handshakeSessionKey, 8);
            memcpy(&handshakeKeyBytes[8], &decryptMessageBytes[4], 8);

            mbedtls_aes_setkey_enc( &lockCypher, handshakeKeyBytes, 128 );

            //send init command
            uint8_t *cmd = BuildCommand(0x03);
            memcpy(&cmd[4], &handshakeSessionKey[8], 8);
            SecWriteChecksum(cmd);

            Serial.print("SEC_INITIALIZATION_COMMAND: ");
            Serial.println(ConvertBytesToHex(cmd, 18).c_str());

            uint8_t secMessage[18];

            //encrypt
            encryptMessage(cmd, secMessage);

            Serial.println(ConvertBytesToHex(secMessage, 18).c_str());

            delay(100);

            NimBLERemoteCharacteristic *pChr = pRemoteCharacteristic->getRemoteService()->getCharacteristic(writeCharacteristic);
            if (pChr->canWriteNoResponse())
            {
                Serial.println("Write no response SEC_INITIALIZATION_COMMAND");
                if (pChr->writeValue(secMessage, 18, false))
                {
                    Serial.print("Wrote new value to: ");
                    Serial.println(pChr->getUUID().toString().c_str());
                }
                else
                {
                    Serial.println("bork");
                }
            }
        }
        else if (decryptMessageBytes[0] == 0x04)
        {   
            Serial.println("handshake pt2 complete");
            Serial.println("Lock initialised");

            //get status
            delay(100);
            getStatus();
        }
        else
        {
            Serial.println("handshake failed");
        }
    }
}

void closeConnection()
{
    if (pWriteCharacteristic->canWrite())
    {
        uint8_t *cmd = BuildCommand(0x05);
        memcpy(&cmd[4], &handshakeSessionKey[8], 8);
        SecWriteChecksum(cmd);

        Serial.print("DISCONNECT: ");
        Serial.println(ConvertBytesToHex(cmd, 18).c_str());

        uint8_t secMessage[18];

        // encrypt
        encryptMessage(cmd, secMessage);

        Serial.println(ConvertBytesToHex(secMessage, 18).c_str());

        delay(100);

        Serial.println("Write for disconnect");
        if (pWriteCharacteristic->writeValue(secMessage, 18, false))
        {
            Serial.print("Wrote new value to: ");
            Serial.println(pWriteCharacteristic->getUUID().toString().c_str());
        }
        else
        {
            Serial.println("bork");
            pClient->disconnect();
        }
    }
}

void forceLock()
{
    if (pWriteCharacteristic2->canWrite())
    {
        uint8_t cmd[18];
        lockCmd(cmd, 0x0b);
        WriteChecksum(cmd);

        Serial.print("lock: ");
        Serial.println(ConvertBytesToHex(cmd, 18).c_str());

        uint8_t lockMessage[18];

        //encrypt
        cbcEncryptMessage(cmd, lockMessage);

        delay(50);

        Serial.print("lock (encrypt): ");
        Serial.println(ConvertBytesToHex(lockMessage, 18).c_str());
        
        Serial.println("Write for lock");
        if (pWriteCharacteristic2->writeValue(lockMessage, 18, false))
        {
            Serial.print("Wrote new value to: ");
            Serial.println(pWriteCharacteristic2->getUUID().toString().c_str());
        }
        else
        {
            Serial.println("bork");
            pClient->disconnect();
        }
    }
}

void forceUnlock()
{
    if (pWriteCharacteristic2->canWrite())
    {
        uint8_t cmd[18];
        lockCmd(cmd, 0x0a);
        WriteChecksum(cmd);

        Serial.print("unlock: ");
        Serial.println(ConvertBytesToHex(cmd, 18).c_str());

        uint8_t lockMessage[18];

        //encrypt
        cbcEncryptMessage(cmd, lockMessage);

        Serial.print("unlock (encrypt): ");
        Serial.println(ConvertBytesToHex(lockMessage, 18).c_str());

        delay(50);
        
        Serial.println("Write for unlock");
        if (pWriteCharacteristic2->writeValue(lockMessage, 18, false))
        {
            Serial.print("Wrote new value to: ");
            Serial.println(pWriteCharacteristic2->getUUID().toString().c_str());
        }
        else
        {
            Serial.println("bork");
            pClient->disconnect();
        }
    }
}

void secureLockCallback(NimBLERemoteCharacteristic *pRemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    Serial.print("Secure Lock: ");
    Serial.println(ConvertBytesToHex(pData, length).c_str());

    uint8_t *decryptMessageBytes = (uint8_t *)__builtin_alloca(length);
    cbcDecryptMessage(pData, decryptMessageBytes);

    Serial.print("Decrypt: ");
    Serial.println(ConvertBytesToHex(decryptMessageBytes, length).c_str());

    uint8_t status = decryptMessageBytes[8];

    if (status == 0x03)
    {
        Serial.println("Lock is Unlocked");
        lockIsLocked = false;
        if (doLockToggle) forceLock();
        else closeConnection();
    }
    else if (status == 0x05)
    {
        Serial.println("Lock is Locked");
        lockIsLocked = true;
        if (doLockToggle) forceUnlock();
        else closeConnection();
    }

    doLockToggle = false;
}

void statusCmd(uint8_t *cmd)
{
    memset(cmd, 0, 18);
    cmd[0] = 0xee; // magic
    cmd[1] = 0x02;
    cmd[4] = 0x02;
    cmd[16] = 0x02;
}

void getStatus()
{
    if (pWriteCharacteristic2->canWrite())
    {
        uint8_t status[18];
        statusCmd(status);
        WriteChecksum(status);

        Serial.print("status: ");
        Serial.println(ConvertBytesToHex(status, 18).c_str());

        uint8_t lockMessage[18];

        //encrypt
        cbcEncryptMessage(status, lockMessage);

        Serial.print("status(Encrypt): ");
        Serial.println(ConvertBytesToHex(lockMessage, 18).c_str());

        Serial.println("Write for status");
        if (pWriteCharacteristic2->writeValue(lockMessage, 18, false))
        {
            Serial.print("Wrote new value to: ");
            Serial.println(pWriteCharacteristic2->getUUID().toString().c_str());
        }
        else
        {
            Serial.println("bork");
            pClient->disconnect();
        }
    }
}


void scanEndedCB(NimBLEScanResults results);

static NimBLEAdvertisedDevice *advDevice;

static bool doConnect = false;
static uint32_t scanTime = 0; /** 0 = scan forever */

class ClientCallbacks : public NimBLEClientCallbacks
{
    void onConnect(NimBLEClient *pClient)
    {
        Serial.println("Connected ...");
        pClient->updateConnParams(12, 120, 0, 300);
    };

    void onDisconnect(NimBLEClient *pClient)
    {
        Serial.print(pClient->getPeerAddress().toString().c_str());
        Serial.println(" Disconnected - Starting scan");
        delay(2000);
        NimBLEDevice::getScan()->start(scanTime, scanEndedCB);
    };

    /** Called when the peripheral requests a change to the connection parameters.
     *  Return true to accept and apply them or false to reject and keep
     *  the currently used parameters. Default will return true.
     */
    bool onConnParamsUpdateRequest(NimBLEClient *pClient, const ble_gap_upd_params *params)
    {
        if (params->itvl_min < 24)
        { /** 1.25ms units */
            return false;
        }
        else if (params->itvl_max > 40)
        { /** 1.25ms units */
            return false;
        }
        else if (params->latency > 2)
        { /** Number of intervals allowed to skip */
            return false;
        }
        else if (params->supervision_timeout > 100)
        { /** 10ms units */
            return false;
        }

        return true;
    };
};

/** Callback to process the results of the last scan or restart it */
void scanEndedCB(NimBLEScanResults results)
{
    Serial.println("Scan Ended");
}

/** Create a single global instance of the callback class to be used by all clients */
static ClientCallbacks clientCB;

/** Define a class to handle the callbacks when advertisments are received */
class AdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks
{

    void onResult(NimBLEAdvertisedDevice *advertisedDevice)
    {
        Serial.print("Advertised Device found: ");
        Serial.println(advertisedDevice->toString().c_str());
        if (advertisedDevice->isAdvertisingService(serviceUUID))
        {
            Serial.println("Found Our Service");
            /** stop scan before connecting */
            NimBLEDevice::getScan()->stop();
            /** Save the device reference in a global for the client to use*/
            advDevice = advertisedDevice;
            /** Ready to connect now */
            doConnect = true;
        }
    };
};

void initSessionKey()
{
    // need 16 bytes random key; use a quick dirty old-school C pointers method
    handshakeSessionKey = new uint8_t[16];
    for (int i = 0; i < 4; i++)
    {
        *((uint32_t *)&handshakeSessionKey[i * 4]) = esp_random();
    }

    Serial.println(ConvertBytesToHex(handshakeSessionKey, 16).c_str());
}

void getHandshakeBytes(uint8_t *handshakeBytes)
{
    initSessionKey();

    // now build the command
    uint8_t *handshakeCommand = BuildCommand(0x01);
    memcpy(&handshakeCommand[4], handshakeSessionKey, 8);

    Serial.println(ConvertBytesToHex(handshakeCommand, 18).c_str());
    SecWriteChecksum(handshakeCommand);

    Serial.println(ConvertBytesToHex(handshakeCommand, 18).c_str());

    encryptMessage(handshakeCommand, handshakeBytes);

    Serial.println(ConvertBytesToHex(handshakeBytes, 18).c_str());
    delete(handshakeCommand);
}

void encryptMessage(uint8_t *plainText, uint8_t *encryptBuffer)
{
    mbedtls_aes_context aes;
    uint8_t messageChop[16];
    memcpy(encryptBuffer, plainText, 18); // should we remove this hardcoding? Are all messages here 16/18 bytes?
    memcpy(messageChop, plainText, 16);
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, (const unsigned char *)handshakeKeyBytes, 128);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char *)messageChop, encryptBuffer);
    mbedtls_aes_free(&aes);
}

void decryptMessage(uint8_t *encryptedMessage, uint8_t *decryptBuffer)
{
    mbedtls_aes_context aes;
    uint8_t messageChop[16];
    memcpy(decryptBuffer, encryptedMessage, 18); // should we remove this hardcoding? Are all messages here 16/18 bytes?
    memcpy(messageChop, encryptedMessage, 16);
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, (const unsigned char *)handshakeKeyBytes, 128);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char *)messageChop, decryptBuffer);
    mbedtls_aes_free(&aes);
}

void cbcEncryptMessage(uint8_t *plainText, uint8_t *encryptBuffer)
{
    uint8_t messageChop[16];
    memcpy(encryptBuffer, plainText, 18); // should we remove this hardcoding? Are all messages here 16/18 bytes?
    memcpy(messageChop, plainText, 16);
    mbedtls_aes_crypt_cbc( &lockCypher, MBEDTLS_AES_ENCRYPT, 16, iv, (const unsigned char *)messageChop, (uint8_t*)encryptBuffer );
}

void cbcDecryptMessage(uint8_t *encryptedMessage, uint8_t *decryptBuffer)
{
    uint8_t messageChop[16];
    memcpy(decryptBuffer, encryptedMessage, 18); // should we remove this hardcoding? Are all messages here 16/18 bytes?
    memcpy(messageChop, encryptedMessage, 16);
	mbedtls_aes_crypt_cbc( &lockCypher, MBEDTLS_AES_DECRYPT, 16, iv2, (const unsigned char *)messageChop, (uint8_t*)decryptBuffer );
}

void setup()
{
    Serial.begin(115200);
    Serial.println("Starting Arduino BLE Client application...");
    std::vector<char> localBytes = HexToBytes(handshakeKey);
    handshakeKeyBytes = new uint8_t[16];
    memcpy( handshakeKeyBytes, localBytes.data(), 16 );
    memset( iv, 0, sizeof( iv ) );
    memset( iv2, 0, sizeof( iv2 ) );
    mbedtls_aes_init(&lockCypher);

    NimBLEDevice::init("");
    NimBLEDevice::setSecurityAuth(BLE_SM_PAIR_AUTHREQ_SC);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEScan *pScan = NimBLEDevice::getScan();
    pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
    pScan->setInterval(45);
    pScan->setWindow(15);
    pScan->setActiveScan(true);
    pScan->start(scanTime, scanEndedCB);
} 

/** Handles the provisioning of clients and connects / interfaces with the server */
bool connectToServer()
{
    if (pClient != 0)
    {
        NimBLEDevice::deleteClient(pClient);
    }

    NimBLEClient *pClient = nullptr;

    NimBLEAddress *addr = new NimBLEAddress(deviceAddress);

    /** No client to reuse? Create a new one. */
    if (!pClient)
    {
        if (NimBLEDevice::getClientListSize() >= NIMBLE_MAX_CONNECTIONS)
        {
            Serial.println("Max clients reached - no more connections available");
            return false;
        }

        pClient = NimBLEDevice::createClient();

        Serial.println("New client created");

        pClient->setClientCallbacks(&clientCB, false);
        pClient->setConnectionParams(12, 12, 0, 300);
        pClient->setConnectTimeout(30);

        if (!pClient->connect(advDevice))
        {
            /** Created a client but failed to connect, don't need to keep it as it has no data */
            NimBLEDevice::deleteClient(pClient);
            Serial.println("Failed to connect, deleted client");
            return false;
        }
    }

    if (!pClient->isConnected())
    {
        if (!pClient->connect(advDevice))
        {
            Serial.println("Failed to connect");
            return false;
        }
    }

    // Serial.print("Connected to: ");
    // Serial.println(pClient->getPeerAddress().toString().c_str());
    // Serial.print("RSSI: ");
    // Serial.println(pClient->getRssi());

    NimBLERemoteService *pSvc = pClient->getService(serviceUUID);

    if (pSvc)
    {
        NimBLERemoteCharacteristic *pReadLockCmd = pSvc->getCharacteristic(readCharacteristic2);
        NimBLERemoteCharacteristic *pReadSecureChannel = pSvc->getCharacteristic(readCharacteristic);
        pWriteCharacteristic2 = pSvc->getCharacteristic(writeCharacteristic2);
        pWriteCharacteristic = pSvc->getCharacteristic(writeCharacteristic);
        
        if (pReadLockCmd)
        {
            if (pReadLockCmd->canIndicate())
            {
                /** Send false as first argument to subscribe to indications instead of notifications */
                // if(!pChr->registerForNotify(notifyCB, false)) {
                if (!pReadLockCmd->subscribe(false, secureLockCallback))
                {
                    Serial.println("Lock command channel indicate fail");
                    /** Disconnect if subscribe failed */
                    pClient->disconnect();
                }
                else
                {
                    Serial.println("Lock command channel notification listener success");
                }
            }
        }

        if (pReadSecureChannel)
        { /** make sure it's not null */
            if (pReadSecureChannel->canIndicate())
            {
                if (!pReadSecureChannel->subscribe(false, notifyCB))
                {
                    Serial.println("Handshake channel setup fail");
                    /** Disconnect if subscribe failed */
                    pClient->disconnect();
                    return false;
                }
                else
                {
                    Serial.println("Handshake channel setup complete");
                }
            }
        }

        // initiate handshake with Lock, via secure channel
        if (pWriteCharacteristic)
        {
            uint8_t handshakeBytes[18];

            getHandshakeBytes(handshakeBytes);
            size_t len = 18;

            if (pWriteCharacteristic->canWriteNoResponse())
            {
                Serial.println("Write no response");
                if (pWriteCharacteristic->writeValue(handshakeBytes, 18, false))
                {
                    Serial.print("Wrote new value to: ");
                    Serial.println(pWriteCharacteristic->getUUID().toString().c_str());
                }
                else
                {
                    Serial.println("bork");
                    pClient->disconnect();
                    return false;
                }
            }
        }
    }

    Serial.println("Setup complete");
    return true;
}

void loop()
{
    /** Loop here until we find a device we want to connect to */
    while (!doConnect)
    {
        delay(1);
    }

    doConnect = false;

    /** Found a device we want to connect to, do it now */
    if (!doneConnect && connectToServer())
    {
        Serial.println("Success! we should now be getting notifications, scanning for more!");
        doneConnect = true;
    }
    else if (!doneConnect)
    {
        Serial.println("Failed to connect, starting scan");
        NimBLEDevice::getScan()->start(scanTime, scanEndedCB);
    }

    //
    delay(100);
}

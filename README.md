# AugustESP32  [![PlatformIO Registry](https://badges.registry.platformio.org/packages/jamessmartcell/library/AugustESP32.svg)](https://registry.platformio.org/libraries/jamessmartcell/AugustESP32)

What's new:

v1.2:

- Added 'stopScanning' command to allow firmware to cancel a scan that didn't find the door.

v1.1:

- Added finer control to bluetooth connection so connection state can be managed better. Call an 'open comms' command to establish connection ready for use eg:

User logs into app or device receives request for challenge

Establish connection:

```augustLock.lockAction(ESTABLISH_CONNECTION);```

... Wait for user action (user locks August lock)

```augustLock.lockCommand(LOCK);```

... Wait 2 mins for any other action (nothing happens)

```augustLock.closeConnection();```


## ESP32 BlueTooth implementation for August smart lock.

Requires h2zero/NimBLE-Arduino@^1.3.1

This library is an interface library for the August/Yale smartlocks.

Based on work by Marcus Lum https://github.com/Marcus-L/xamarin-august-ble

https://user-images.githubusercontent.com/12689544/145123443-9971d171-e03e-4fe3-90ad-1638ccd9b0cc.mp4

To obtain the required credentials you can use a rooted Android phone and this opensource app (which is also available on PlayStore):

[GitHub repo for AugustLockCredentials](https://github.com/JamesSmartCell/AugustLockCredentials)

This will allow you to copy/paste the constructor for the August library instance directly into your firmware sketch program.

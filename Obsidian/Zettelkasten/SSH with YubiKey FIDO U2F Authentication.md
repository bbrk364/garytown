SSH with YubiKey FIDO U2F Authentication

This is the accompanying a guide for the video SSH with YubiKey FIDO U2F Authentication. Of note this should work with other keys that support FIDO U2F such as [https://www.nitrokey.com/](https://www.nitrokey.com/) & [https://solokeys.com/](https://solokeys.com/) but do not have those other keys to test.

First we need to make sure both your client and the servers you are connecting to are running OpenSSH 8.2 or greater. You can use this command to check the version:

```
ssh -V
```

The SSH key-pair can be either an ecdsa-sk or an ed25519-sk key-pair. The sk extension stands for security key. Note that an ed25519-sk key-pair is only supported by new YubiKeys with firmware 5.2.3 or higher which supports FIDO2. Use this to check the firmware version of your Yubikey:

```
lsusb -v 2>/dev/null | grep -A2 Yubico | grep "bcdDevice" | awk '{print $2}'
```

The **libsk-libfido2.so** middleware library must be present on the host to provide functionality to communicate with a FIDO device over USB, and to verify attestation and assertion signatures.

```
sudo apt install libfido2-dev
```

Next we have to create a new SSH ed25519-sk key-pair which is the same as generating a ed25519 key but the sk extension stands for security key.

```
ssh-keygen -t ed25519-sk -C "$(hostname)-$(date +'%d-%m-%Y')-yubikey1"
```

Once this is done only part of the key is on your system the other part comes form the FIDO U2F device but it’s not simply read form the device as a value but part of a challenge response from the devices. The enrollment operation returns a public key, a key handle that must be used to invoke  
the hardware-backed private key, some flags and signed attestation information that may be used to verify that a private key is hosted on a particular hardware instance.

Full write up of the protocol here: [openssh-portable/PROTOCOL.u2f at master · openssh/openssh-portable · GitHub](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f)
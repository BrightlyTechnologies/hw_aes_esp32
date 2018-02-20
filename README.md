# hw_aes_esp32
Sample ESP32/Arduino IDE code demonstrating the basics of hardware-accelerated AES

Basic functions ripped from hwcrypto/aes.c.

Simple demo of hardware-encoded encryption on the ESP32 with LoRa
This is the receiver code. It expects two things:

• A JSON packet [hence the use of the ArduinoJson library].
 Required elements:
 - from
 - msg
 - sendCount
• If you want to turn on the encryption mode [which is the point here...]
 - a 256-bit [ie 32-byte] key: unsigned char key[32];
 - a boolean flag: bool needDecoding = true;
 - init the key with your passphrase ine setup();
   if (needDecoding) {
     memcpy(key, "YELLOW SUBMARINEENIRAMBUS WOLLEY", 32);
   }

On your sender, the code is similar and looks like this:

      LoRa.beginPacket();
      String pkt = "{\"from\": \"" + String(myUUID) + "\", \"sendCount\": " + String(counter) + ", \"msg\": \"PING\"";
      IPAddress ip = WiFi.localIP();
      pkt += ", \"IP\": \"" + String(ip[0]) + '.' + ip[1] + '.' + ip[2] + '.' + ip[3] + "\"}";
      uint16_t len = pkt.length() + 1;
      // +1 = don't forget to account for the '\0' at the end...
      pkt.toCharArray(pktBuf, len);

      // Let's flip a switch
      if (needDecoding) {
        Serial.println("len before adjustment = " + String(len));
        if (len % 16 > 0) {
          if (len < 16) len = 16;
          else len += 16 - (len % 16);
        }
        // BEWARE! The buffers are 256 bytes long.
        // Exceeding that could make the code go boom.
        memcpy(encBuf, pktBuf, len);
        esp_aes_hw_hexDump((unsigned char*)encBuf, len);
        uint8_t rslt = esp_aes_hw_multiple_blocks(ESP_AES_ENCRYPT, key, encBuf, (unsigned char*)pktBuf, len);
        Serial.println("len after adjustment = " + String(len));
      }

      Serial.println("Sending:");
      esp_aes_hw_hexDump((unsigned char*)pktBuf, len);
      LoRa.write((const unsigned char*)pktBuf, len);
      LoRa.endPacket();

That's it. You're now communicating (somewhat) securely.

# Functions:

- void esp_aes_hw_hexDump(unsigned char *, uint16_t);
- uint8_t esp_aes_hw_multiple_blocks(int, unsigned char *, unsigned char *, unsigned char *, uint16_t);
- int esp_aes_hw_crypt_cbc(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char *);
- int esp_aes_hw_crypt_cfb8(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char 

# Installation:

- M5_LoRa_Receiver.ino goes into the main Arduino folder, inside its own M5_LoRa_Receiver folder.
- HW_AES.cpp and HW_AES.h go into the Arduino/libraries folder, inside their own HW_AES folder.
- You'll need to write your own LoRa sender code [see above].

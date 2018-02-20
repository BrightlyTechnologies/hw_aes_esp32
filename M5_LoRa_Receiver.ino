/*

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

*/

#include <M5Stack.h>
#include <M5LoRa.h>
#include <SPI.h>
#include <ArduinoJson.h>
#include "HW_AES.h"

#define LORA_CS_PIN   5
#define LORA_RST_PIN  26
#define LORA_IRQ_PIN  36
#define BAND    433E6
#define myUUID "DECA-FBAD-M5ST-ACK0"
// make your own :-)
#define FSSB9 &FreeSansBold9pt7b
#define FSSB12 &FreeSansBold12pt7b
#define FSS9 &FreeSans9pt7b
#define FF1 &FreeMono9pt7b

uint8_t ix = 0;
char buff[256];
char decBuff[256];
uint8_t receivedCount = 0;
uint8_t brightness = 100;
bool lcdSleep = false;
bool needDecoding = true;
unsigned char key[32];

void buttons_test() {
  while (M5.BtnA.isPressed()) {
    if (brightness > 0) brightness -= 5;
    Serial.println("-5 brightness: " + String(brightness));
    M5.Lcd.setBrightness(brightness);
    delay(200);
    M5.update();
  }
  while (M5.BtnC.isPressed()) {
    if (brightness < 100) brightness += 5;
    Serial.println("+5 brightness: " + String(brightness));
    M5.Lcd.setBrightness(brightness);
    delay(200);
    M5.update();
  }

  if (M5.BtnB.isPressed()) {
    M5.setWakeupButton(BUTTON_B_PIN);
    M5.powerOFF();
  }
}

std::string lnaGain[8] = {
  "reserved", "G1", "G2", "G3",
  "G4", "G5", "G6", "reserved"
};

std::string RFI_LF_Adjustment[4] = {
  "default", "reserved", "reserved", "reserved"
};

std::string RFI_HF_Adjustment[4] = {
  "default", "reserved", "reserved", "Boost 150%"
};

std::string PaSelectValues[2] = {
  "RFO pin: +14 dBm max", "PA BOOST: +20 dBm max"
};

std::string longRangeModes[2] = {
  "FSK/OOK", "LoRa"
};

std::string modulationTypes[4] = {
  "FSK", "OOK", "reserved", "reserved"
};

std::string transModes[8] = {
  "sleep", "standby", "FSTx", "transmitter",
  "FSRx", "receiver", "reserved", "reserved"
};

void displayRegisters() {
  Serial.println("\n----------------------------" );
  // readRegister is private, I moved it up to public.
  uint8_t value = LoRa.readRegister(REG_LNA);
  // REG_LNA
  uint8_t x = value >> 5;
  String s = String(value, BIN);
  while (s.length() < 8) s = "0" + s;
  Serial.println("REG_LNA: 0b" + s);
  Serial.print(" . LNA Gain: [" + String(x, BIN) + "] ");
  Serial.println(lnaGain[x].c_str());
  x = (value & 0b00011000) >> 3;
  Serial.print(" . RFI_LF LNA adjustment: [" + String(x, BIN) + "] "); Serial.println(RFI_LF_Adjustment[x].c_str());
  x = (value & 0b00000011);
  Serial.print(" . RFI_HF LNA adjustment: [" + String(x, BIN) + "] "); Serial.println(RFI_HF_Adjustment[x].c_str());

  Serial.println("\n----------------------------" );
  value = LoRa.readRegister(REG_PA_CONFIG);
  // REG_PA_CONFIG
  uint8_t paSelect = value >> 7;
  s = String(value, BIN);
  while (s.length() < 8) s = "0" + s;
  Serial.println("REG_PA_CONFIG: 0b" + s);
  Serial.print(" . PaSelect: [0b" + String(paSelect, BIN) + ", " + String(paSelect) + "] ");
  Serial.println(PaSelectValues[paSelect].c_str());
  x = (value & 0b01110000) >> 4;
  uint16_t paMax = 10.8 + 0.6 * x;
  Serial.print(" . MaxPower: [0b" + String(x, BIN) + ", " + String(x) + "] "); Serial.print(paMax); Serial.println(" dBm");
  uint16_t Pout = (value & 0b00001111);
  Serial.print(" . OutputPower: [0b" + String(Pout, BIN) + ", " + String(Pout) + "] ");
  if (paSelect == 0) Pout = paMax - (15 - Pout);
  else Pout = 17 - (15 - Pout);
  Serial.print(Pout); Serial.println(" dBm");

  Serial.println("\n----------------------------" );
  value = LoRa.readRegister(REG_OP_MODE);
  // REG_PA_CONFIG
  x = value >> 7;
  s = String(value, BIN);
  while (s.length() < 8) s = "0" + s;
  Serial.println("REG_OP_MODE: 0b" + s);
  Serial.print(" . LongRangeMode: [0b" + String(x, BIN) + ", " + String(x) + "] ");
  Serial.print(longRangeModes[x].c_str());
  Serial.println(" mode");
  x = (value & 0b01100000) >> 5;
  Serial.print(" . ModulationType: [0b" + String(x, BIN) + ", " + String(x) + "] "); Serial.println(modulationTypes[x].c_str());
  x = (value & 0b00000111);
  Serial.print(" . Mode: [0b" + String(x, BIN) + ", " + String(x) + "] ");
  Serial.print(transModes[x].c_str());
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  M5.begin();
  LoRa.setPins(LORA_CS_PIN, LORA_RST_PIN, LORA_IRQ_PIN); // set CS, reset, IRQ pin
  Serial.println(F("LoRa Receiver"));
  M5.Lcd.setTextColor(TFT_BLACK, TFT_WHITE);
  M5.Lcd.fillScreen(TFT_WHITE);
  M5.Lcd.drawJpgFile(SD, "/LoRaLogoSmall.jpg", 0, 0);
  M5.Lcd.setFreeFont(FSSB12);
  // Select the font: FreeMono18pt7b – see Free_Fonts.h
  M5.Lcd.drawString(F("Receiver"), 85, 18, 1);
  M5.Lcd.setFreeFont(FSS9); // FreeSans9pt7b
  if (!LoRa.begin(BAND)) {
    Serial.println(F("Starting LoRa failed!"));
    M5.Lcd.drawString(F("Starting LoRa failed!"), 24, 57, 1);
    M5.Lcd.drawString(F("Cannot do anything!"), 24, 82, 1);
    M5.Lcd.drawJpgFile(SD, "/XMark20.jpg", 2, 55);
    //while (1);
  }

  // This is option 1
  LoRa.writeRegister(REG_PA_CONFIG, 0b11111111); // That's for the transceiver
  // This is option 2
  LoRa.writeRegister(REG_LNA, 0b00100011); // That's for the receiver

  Serial.println(F("LoRa init succeeded."));
  M5.Lcd.drawString(F("LoRa init succeeded."), 24, 57, 1);
  M5.Lcd.drawJpgFile(SD, "/Check20.jpg", 2, 55);
  displayRegisters();
  M5.Lcd.drawString(F("Listening to packets..."), 24, 82, 1);

  if (needDecoding) {
    memcpy(key, "YELLOW SUBMARINEENIRAMBUS WOLLEY", 32);
  }
}

void loop() {
  // try to parse packet
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    // received a packet
    // print RSSI of packet
    Serial.print(F("Received packet with RSSI "));
    int rssiLvl = LoRa.packetRssi();
    Serial.println(rssiLvl);
    // read packet
    ix = 0;
    while (LoRa.available()) {
      buff[ix++] = LoRa.read();;
    }

    // Let's flip a switch
    if (needDecoding) {
      Serial.println("len before adjustment = " + String(ix));
      uint16_t len = ix;
      if (len % 16 > 0) {
        if (len < 16) len = 16;
        else len += 16 - (len % 16);
      }
      // BEWARE! The buffers are 256 bytes long.
      // Exceeding that could make the code go boom.
      memcpy(decBuff, buff, len);
      esp_aes_hw_hexDump((unsigned char*)buff, ix);
      uint8_t rslt = esp_aes_hw_multiple_blocks(ESP_AES_DECRYPT, key, (unsigned char*)decBuff, (unsigned char*)buff, len);
    }

    esp_aes_hw_hexDump((unsigned char*)buff, ix);
    uint8_t linePos = 110;
    M5.Lcd.fillRect(0, 100, 320, 137, TFT_WHITE);
    M5.Lcd.setFreeFont(FF1);
    // FreeMono9pt7b
    StaticJsonBuffer<256> jsonBuffer;
    JsonObject& root = jsonBuffer.parseObject(buff);
    if (!root.success()) {
      Serial.println("parseObject() failed");
      M5.Lcd.setFreeFont(FSSB9);
      M5.Lcd.drawString(F("* parseObject() failed!"), 5, linePos, 1);
      linePos += 20;
      M5.Lcd.drawString(buff, 5, linePos, 1);
      return;
    }
    const char* from = root["from"];
    const char* msg = root["msg"];
    //const char* time = root["time"];
    const char* sendCount = root["sendCount"];
    // Print values.
    Serial.print(F("from: "));
    Serial.println(from);
    Serial.print(F("sendCount: "));
    Serial.println(sendCount);
    Serial.print(F("msg: "));
    Serial.println(msg);

    M5.Lcd.setFreeFont(FSSB9);
    M5.Lcd.drawString(F("* from: "), 5, linePos, 1);
    linePos += 20;
    M5.Lcd.drawString(F("* count: "), 5, linePos, 1);
    linePos += 20;
    M5.Lcd.drawString(F("* msg: "), 5, linePos, 1);
    //linePos += 20;
    //M5.Lcd.drawString(F("* time: "), 5, linePos, 1);
    linePos += 20;
    M5.Lcd.drawString(F("* RSSI: "), 5, linePos, 1);
    M5.Lcd.setFreeFont(FSS9);
    linePos -= 60;
    M5.Lcd.drawString(from, 100, linePos, 1);
    linePos += 20;
    M5.Lcd.drawString(sendCount, 100, linePos, 1);
    linePos += 20;
    M5.Lcd.drawString(msg, 100, linePos, 1);
    //linePos += 20;
    //M5.Lcd.drawString(time, 100, linePos, 1);
    linePos += 20;
    M5.Lcd.drawString(String(rssiLvl), 100, linePos, 1);
    String fp;
    if (rssiLvl > -51) fp = "/rssiExcellent40.jpg";
    else if (rssiLvl > -61) fp = "/rssiGood40.jpg";
    else if (rssiLvl > -71) fp = "/rssiFair40.jpg";
    else fp = "/rssiPoor40.jpg";
    M5.Lcd.drawJpgFile(SD, fp.c_str(), 280, 0);
    uint16_t ch0, ch7;
    float vCh0, vCh7;
    ch0 = analogRead(ADC1_CH0);
    ch7 = analogRead(ADC1_CH7);
    Serial.print("ADC1_CH7: ");
    Serial.print(ch7); Serial.write(' ');
    vCh7 = ch7 / 1023.0 * 2.1;
    Serial.println(vCh7);
    Serial.print("ADC1_CH0: ");
    Serial.print(ch0); Serial.write(' ');
    vCh0 = ch0 / 1023.0 * 2.1;
    Serial.println(vCh0);
  }
  buttons_test();
  M5.update(); // 好importantですね！
  // If not the buttons status is not updated lo.
}


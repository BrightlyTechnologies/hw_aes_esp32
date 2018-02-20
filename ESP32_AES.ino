#include <HW_AES.h>


uint32_t t0, t1, t2, t3;

void setup() {
  Serial.begin(115200);
  delay(1000);
  randomSeed(analogRead(0));
  Serial.flush();
  Serial.println("\n\nStart\n\n");
  unsigned char key[32];
  unsigned char output[48];
  unsigned char input[48];
  unsigned char iv[16];
  uint8_t i;
  for (i = 0; i < 48; i++) {
    output[i] = random(0, 255);
    iv[i % 16] = random(0, 255);
  }
  // Just to make sure :-)
  memcpy(key, "YELLOW SUBMARINEENIRAMBUS WOLLEY", 32);
  // Yes, a Matasano reference
  memcpy(input, "WE ALL LIVE IN A YELLOW SUBMARINE, BROTHER", 48);
  for (i = 42; i < 48 ; i++) input[i] = 6;

  Serial.println("\nKey:");
  esp_aes_hw_hexDump(key, 32);
  doBlockTest(key, input, output, 32);
  doBlockTest(key, input, output, 48);
  doBufferTest(key, input, output, iv, 48);
  input[14] = 2;
  input[15] = 2;
  doBlockTest(key, input, output, 16);
}

void loop() {
}

void doBlockTest(unsigned char *key, unsigned char *input, unsigned char *output, uint16_t len) {
  unsigned char *result = (unsigned char*)malloc(48);
  Serial.println("\n\nInput:");
  esp_aes_hw_hexDump(input, len);
  uint8_t rslt = esp_aes_hw_multiple_blocks(ESP_AES_ENCRYPT, key, input, output, len);
  Serial.println("\nOutput [encoded] [" + String(rslt) + "]:");
  esp_aes_hw_hexDump(output, len);
  Serial.print("esp_aes_hw_block: "); Serial.print(t1 - t0); Serial.println(" microseconds");
  Serial.print("full encode :  "); Serial.print(t3 - t2); Serial.println(" microseconds\n");
  rslt = esp_aes_hw_multiple_blocks(ESP_AES_DECRYPT, key, output, result, len);
  Serial.println("\nOutput [decoded] [" + String(rslt) + "]:");
  esp_aes_hw_hexDump(result, len);
  Serial.print("esp_aes_hw_block: "); Serial.print(t1 - t0); Serial.println(" microseconds");
  Serial.print("full decode :  "); Serial.print(t3 - t2); Serial.println(" microseconds\n\n");
}

void doBufferTest(unsigned char *key, unsigned char *input, unsigned char *output, unsigned char iv[16], uint16_t len) {
  unsigned char *result = (unsigned char*)malloc(48);
  unsigned char myIV[16];

  memcpy(myIV, iv, 16);

  Serial.println("\n\nInput:");
  esp_aes_hw_hexDump(input, len);
  Serial.println("iv:");
  esp_aes_hw_hexDump(myIV, 16);

  Serial.println("\nesp_aes_hw_crypt_cbc:");
  t0 = system_get_time();
  int rslt = esp_aes_hw_crypt_cbc(ESP_AES_ENCRYPT, len, myIV, key, input, output);
  t1 = system_get_time();
  Serial.println("\nOutput [encoded] [" + String(rslt) + "]:");
  esp_aes_hw_hexDump(output, len);
  Serial.print("esp_aes_hw_crypt_cbc: "); Serial.print(t1 - t0); Serial.println(" microseconds\n");

  memcpy(myIV, iv, 16);
  Serial.println("iv:");
  esp_aes_hw_hexDump(myIV, 16);
  t0 = system_get_time();
  rslt = esp_aes_hw_crypt_cbc(ESP_AES_DECRYPT, len, myIV, key, output, result);
  t1 = system_get_time();
  Serial.println("\nOutput [decoded] [" + String(rslt) + "]:");
  esp_aes_hw_hexDump(result, len);
  Serial.print("esp_aes_hw_crypt_cbc: "); Serial.print(t1 - t0); Serial.println(" microseconds\n");

  memcpy(myIV, iv, 16);
  Serial.println("\nesp_aes_hw_crypt_cfb8:");
  t0 = system_get_time();
  rslt = esp_aes_hw_crypt_cfb8(ESP_AES_ENCRYPT, len, myIV, key, input, output);
  t1 = system_get_time();
  Serial.println("\nOutput [encoded] [" + String(rslt) + "]:");
  esp_aes_hw_hexDump(output, len);
  Serial.print("esp_aes_hw_crypt_cfb8: "); Serial.print(t1 - t0); Serial.println(" microseconds");

  memcpy(myIV, iv, 16);
  t0 = system_get_time();
  rslt = esp_aes_hw_crypt_cfb8(ESP_AES_DECRYPT, len, myIV, key, output, result);
  t1 = system_get_time();
  Serial.println("\nOutput [decoded] [" + String(rslt) + "]:");
  esp_aes_hw_hexDump(result, len);
  Serial.print("esp_aes_hw_crypt_cfb8: "); Serial.print(t1 - t0); Serial.println(" microseconds\n");

  Serial.println("---------------------------------------------------------------------------");
}


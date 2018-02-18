#include <string.h>
#include "mbedtls/aes.h"
#include "hwcrypto/aes.h"
#include "soc/dport_reg.h"
#include "soc/hwcrypto_reg.h"
#include <sys/lock.h>
#include <freertos/FreeRTOS.h>
#include "soc/cpu.h"
#include <stdio.h>

static portMUX_TYPE aes_spinlock = portMUX_INITIALIZER_UNLOCKED;

/*
   AES-CBC buffer encryption/decryption
*/

int esp_aes_crypt_cbc(
  int mode, size_t length, unsigned char iv[16], const unsigned char *key,
  const unsigned char *input, unsigned char *output
) {
  int i;
  uint32_t *output_words = (uint32_t *)output;
  const uint32_t *input_words = (const uint32_t *)input;
  uint32_t *iv_words = (uint32_t *)iv;
  unsigned char temp[16];
  esp_aes_context ctx;

  esp_aes_init(&ctx);
  esp_aes_setkey(&ctx, key, 256);

  if (length % 16) {
    return (ERR_ESP_AES_INVALID_INPUT_LENGTH);
  }
  esp_aes_setkey(&ctx, key, 256);
  esp_aes_acquire_hardware();
  esp_aes_setkey_hardware(&ctx, mode);
  if (mode == ESP_AES_DECRYPT) {
    while (length > 0) {
      memcpy(temp, input_words, 16);
      esp_aes_block(input_words, output_words);
      for (i = 0; i < 4; i++) {
        output_words[i] = output_words[i] ^ iv_words[i];
      }
      memcpy(iv_words, temp, 16);
      input_words += 4;
      output_words += 4;
      length -= 16;
    }
  } else { // ESP_AES_ENCRYPT
    while (length > 0) {
      for (i = 0; i < 4; i++) {
        output_words[i] = input_words[i] ^ iv_words[i];
      }
      esp_aes_block(output_words, output_words);
      memcpy(iv_words, output_words, 16);
      input_words  += 4;
      output_words += 4;
      length -= 16;
    }
  }
  esp_aes_release_hardware();
  return 0;
}

void esp_aes_acquire_hardware(void) {
  /* newlib locks lazy initialize on ESP-IDF */
  portENTER_CRITICAL(&aes_spinlock);
  DPORT_STALL_OTHER_CPU_START();
  {
    /* Enable AES hardware */
    _DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_AES);
    /* Clear reset on digital signature & secure boot units,
       otherwise AES unit is held in reset also. */
    _DPORT_REG_CLR_BIT(
      DPORT_PERI_RST_EN_REG,
      DPORT_PERI_EN_AES
      | DPORT_PERI_EN_DIGITAL_SIGNATURE
      | DPORT_PERI_EN_SECUREBOOT
    );
  }
  DPORT_STALL_OTHER_CPU_END();
}

void esp_aes_release_hardware(void) {
  DPORT_STALL_OTHER_CPU_START();
  {
    /* Disable AES hardware */
    _DPORT_REG_SET_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_AES);
    /* Don't return other units to reset, as this pulls
       reset on RSA & SHA units, respectively. */
    _DPORT_REG_CLR_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_AES);
  }
  DPORT_STALL_OTHER_CPU_END();
  portEXIT_CRITICAL(&aes_spinlock);
}

void esp_aes_init(esp_aes_context *ctx) {
  if (ctx == NULL) {
    Serial.println("ctx is NULL!");
    while (1);
  }
}

void esp_aes_free(esp_aes_context *ctx) {
  if (ctx == NULL) return;
  bzero(ctx, sizeof(esp_aes_context));
}

/*
   AES key schedule (same for encryption or decryption, as hardware handles schedule)

*/
int esp_aes_setkey(esp_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
  if (keybits != 128 && keybits != 192 && keybits != 256) return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
  ctx->key_bytes = keybits / 8;
  memcpy(ctx->key, key, ctx->key_bytes);
  return 0;
}

/*
   Helper function to copy key from esp_aes_context buffer
   to hardware key registers.

   Call only while holding esp_aes_acquire_hardware().
*/
static inline void esp_aes_setkey_hardware(esp_aes_context *ctx, int mode) {
  const uint32_t MODE_DECRYPT_BIT = 4;
  unsigned mode_reg_base = (mode == ESP_AES_ENCRYPT) ? 0 : MODE_DECRYPT_BIT;
  memcpy((uint32_t *)AES_KEY_BASE, ctx->key, ctx->key_bytes);
  DPORT_REG_WRITE(AES_MODE_REG, mode_reg_base + ((ctx->key_bytes / 8) - 2));
}

/* Run a single 16 byte block of AES, using the hardware engine.

   Call only while holding esp_aes_acquire_hardware().
*/
static inline void esp_aes_block(const void *input, void *output) {
  const uint32_t *input_words = (const uint32_t *)input;
  uint32_t *output_words = (uint32_t *)output;
  uint32_t *mem_block = (uint32_t *)AES_TEXT_BASE;
  for (int i = 0; i < 4; i++) {
    mem_block[i] = input_words[i];
  }
  DPORT_REG_WRITE(AES_START_REG, 1);
  DPORT_STALL_OTHER_CPU_START();
  {
    while (_DPORT_REG_READ(AES_IDLE_REG) != 1) { }
    for (int i = 0; i < 4; i++) {
      output_words[i] = mem_block[i];
    }
  }
  DPORT_STALL_OTHER_CPU_END();
}

uint32_t t0, t1, t2, t3;

uint8_t encLong(unsigned char *key, unsigned char *input, unsigned char *output, uint16_t len) {
  uint16_t i = 0;
  esp_aes_context ctx;

  if (len % 16 != 0) {
    Serial.println("encLong: len(" + String(len) + ") % 16 = " + String(len % 16));
    if (len < 16) return 16 - len;
    else return (uint8_t)(16 - (len % 16));
    // warn the user that we can't proceed
    // returning the required length
  }

  t2 = system_get_time();
  esp_aes_init(&ctx);
  esp_aes_setkey(&ctx, key, 256);
  t0 = system_get_time();
  esp_aes_acquire_hardware();
  esp_aes_setkey_hardware(&ctx, ESP_AES_ENCRYPT);
  for (i = 0; i < len; i += 16) {
    esp_aes_block(&input[i], &output[i]); // 16 bytes
  }
  esp_aes_release_hardware();
  t1 = system_get_time();
  esp_aes_free(&ctx);
  t3 = system_get_time();
  return 0;
}

uint8_t decLong(unsigned char *key, unsigned char *input, unsigned char *output, uint16_t len) {
  uint16_t i = 0;
  esp_aes_context ctx;

  if (len % 16 != 0) {
    Serial.println("decLong: len(" + String(len) + ") % 16 = " + String(len % 16));
    if (len < 16) return 16;
    else return (uint8_t)(len + 16 - (len % 16));
    // warn the user that we can't proceed
    // returning the required length
  }

  t2 = system_get_time();
  esp_aes_init(&ctx);
  esp_aes_setkey(&ctx, key, 256);
  t0 = system_get_time();
  esp_aes_acquire_hardware();
  esp_aes_setkey_hardware(&ctx, ESP_AES_DECRYPT);
  for (i = 0; i < len; i += 16) {
    esp_aes_block(&input[i], &output[i]); // 16 bytes
  }
  esp_aes_release_hardware();
  t1 = system_get_time();
  esp_aes_free(&ctx);
  t3 = system_get_time();
  hexDump(output, len);
  return 0;
}

void hexDump(unsigned char *buf, uint16_t len) {
  String s = "|", t = "| |";
  Serial.println(F("+------------------------------------------------+ +----------------+"));
  for (uint16_t i = 0; i < len; i += 16) {
    for (uint8_t j = 0; j < 16; j++) {
      if (i + j >= len) {
        s = s + "   "; t = t + " ";
      } else {
        char c = buf[i + j];
        if (c < 16) s = s + "0";
        s = s + String(c, HEX) + " ";
        if (c < 32 || c > 127) t = t + ".";
        else t = t + (char)c;
      }
    }
    Serial.println(s + t + "|");
    s = "|"; t = "| |";
  }
  Serial.println(F("+------------------------------------------------+ +----------------+"));
}

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
  hexDump(key, 32);
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
  hexDump(input, len);
  uint8_t rslt = encLong(key, input, output, len);
  Serial.println("\nOutput [encoded] [" + String(rslt) + "]:");
  hexDump(output, len);
  Serial.print("esp_aes_block: "); Serial.print(t1 - t0); Serial.println(" microseconds");
  Serial.print("full encode :  "); Serial.print(t3 - t2); Serial.println(" microseconds\n");
  rslt = decLong(key, output, result, len);
  Serial.println("\nOutput [decoded] [" + String(rslt) + "]:");
  hexDump(result, len);
  Serial.print("esp_aes_block: "); Serial.print(t1 - t0); Serial.println(" microseconds");
  Serial.print("full decode :  "); Serial.print(t3 - t2); Serial.println(" microseconds\n\n");
}

void doBufferTest(unsigned char *key, unsigned char *input, unsigned char *output, unsigned char iv[16], uint16_t len) {
  unsigned char *result = (unsigned char*)malloc(48);
  esp_aes_context ctx;

  Serial.println("\n\nInput:");
  hexDump(input, len);
  t0 = system_get_time();
  int rslt = esp_aes_crypt_cbc(ESP_AES_ENCRYPT, len, iv, key, input, output);
  t1 = system_get_time();
  Serial.println("\nOutput [encoded] [" + String(rslt) + "]:");
  hexDump(output, len);
  Serial.print("esp_aes_crypt_cbc: "); Serial.print(t1 - t0); Serial.println(" microseconds");

  t0 = system_get_time();
  rslt = esp_aes_crypt_cbc(ESP_AES_DECRYPT, len, iv, key, output, result);
  t1 = system_get_time();
  Serial.println("\nOutput [decoded] [" + String(rslt) + "]:");
  hexDump(result, len);
  Serial.print("esp_aes_crypt_cbc: "); Serial.print(t1 - t0); Serial.println(" microseconds");
  esp_aes_free(&ctx);
}


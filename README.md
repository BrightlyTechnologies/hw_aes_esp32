# hw_aes_esp32
Sample ESP32/Arduino IDE code demonstrating the basics of hardware-accelerated AES

- Basic functions ripped from hwcrypto/aes.c
- uint8_t encLong(unsigned char *key, unsigned char *input, unsigned char *output, uint16_t len)
   For input and output, len must be a multiple of 16. If not the function returns the number of extra bytes needed.
   Block-encrypts input into output, using key.
- uint8_t decLong(unsigned char *key, unsigned char *input, unsigned char *output, uint16_t len)
   Same as above.
   Block-encrypts input into output, using key.
 - int esp_aes_crypt_cbc(int mode, size_t length, unsigned char iv[16], const unsigned char *key, const unsigned char *input, unsigned char *output)
   CBC EN|DEcrypt. You need to provide an IV on top of the other elements. Dual mode, so pass either ESP_AES_ENCRYPT or ESP_AES_DECRYPT.

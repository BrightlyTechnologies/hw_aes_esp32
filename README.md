# hw_aes_esp32
Sample ESP32/Arduino IDE code demonstrating the basics of hardware-accelerated AES

Basic functions ripped from hwcrypto/aes.c. Current lineup of functions:

   For input and output, len must be a multiple of 16. If not the function returns the number of extra bytes needed.
   Block-encrypts/decrypts input into output, using key.
 - int esp_aes_crypt_cbc(int mode, size_t length, unsigned char iv[16], const unsigned char *key, const unsigned char *input, unsigned char *output)
   CBC EN|DEcrypt. You need to provide an IV on top of the other elements. Dual mode, so pass either ESP_AES_ENCRYPT or ESP_AES_DECRYPT.
uint8_t esp_aes_multiple_blocks(int, unsigned char *, unsigned char *, unsigned char *, uint16_t);
   For input and output, len must be a multiple of 16. If not the function returns the number of extra bytes needed.
   Block-encrypts/decrypts input into output, using key.
 - int esp_aes_crypt_cfb8(int, size_t, unsigned char[16], const unsigned char *, const unsigned char *, unsigned char *);
   CFB8 EN|DEcrypt. You need to provide an IV on top of the other elements. Dual mode, so pass either ESP_AES_ENCRYPT or ESP_AES_DECRYPT. IV is updated for the next run.
 - void esp_aes_hexDump(unsigned char *, uint16_t);
   Helper function to pretty-print a block. Trust but verify, right?

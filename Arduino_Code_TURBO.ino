/*

   ____  __  __  ____  _  _  _____       ___  _____  ____  _  _ 
  (  _ \(  )(  )(_  _)( \( )(  _  )___  / __)(  _  )(_  _)( \( )
   )(_) ))(__)(  _)(_  )  (  )(_)((___)( (__  )(_)(  _)(_  )  ( 
  (____/(______)(____)(_)\_)(_____)     \___)(_____)(____)(_)\_)
  Official code for Arduino boards (and relatives)   version 4.3
  
  Duino-Coin Team & Community 2019-2024 © MIT Licensed
  https://duinocoin.com
  https://github.com/revoxhere/duino-coin
  If you don't know where to start, visit official website and navigate to
  the Getting Started page. Have fun mining!
*/

/* For microcontrollers with low memory change that to -Os in all files,
for default settings use -O0. -O may be a good tradeoff between both */
#pragma GCC optimize ("-Ofast")
/* For microcontrollers with custom LED pins, adjust the line below */
#ifndef LED_BUILTIN
#define LED_BUILTIN 13
#endif
#define SEP_TOKEN ","
#define END_TOKEN "\n"
/* For 8-bit microcontrollers we should use 16 bit variables since the
difficulty is low, for all the other cases should be 32 bits. */
#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
typedef uint32_t uintDiff;
#else
typedef uint32_t uintDiff;
#endif
// Arduino identifier library - https://github.com/ricaun
#include "uniqueID.h"

#include <string.h>
#include "duco_hash.h"

String get_DUCOID() {
  String ID = "DUCOID";
  char buff[4];
  for (size_t i = 0; i < 8; i++) {
    sprintf(buff, "%02X", (uint8_t)UniqueID8[i]);
    ID += buff;
  }
  return ID;
}

String DUCOID = "";

void setup() {
  // Prepare built-in led pin as output
  pinMode(LED_BUILTIN, OUTPUT);
  DUCOID = get_DUCOID();
  // Open serial port
  Serial.begin(115200);
  Serial.setTimeout(10000);
  while (!Serial)
    ;  // For Arduino Leonardo or any board with the ATmega32U4
  Serial.flush();
}

static inline uint8_t lowercase_hex_nibble(uint8_t x) {
  uint8_t b = x >> 6;
  return ((x & 0xf) | (b << 3)) + b;
}

void lowercase_hex_to_words(char const * hexDigest, uint32_t * digestWords) {
  for (uint8_t i = 0, word = 0; word < (SHA1_HASH_LEN / 4); word++, i += 8) {
    uint8_t b0 = (lowercase_hex_nibble(hexDigest[i]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 1]);
    uint8_t b1 = (lowercase_hex_nibble(hexDigest[i + 2]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 3]);
    uint8_t b2 = (lowercase_hex_nibble(hexDigest[i + 4]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 5]);
    uint8_t b3 = (lowercase_hex_nibble(hexDigest[i + 6]) << 4)
               | lowercase_hex_nibble(hexDigest[i + 7]);

    digestWords[word] = ((uint32_t)b0 << 24)
                      | ((uint32_t)b1 << 16)
                      | ((uint32_t)b2 << 8)
                      | (uint32_t)b3;
  }
}

#if defined(__AVR__)
static inline void increment_nonce_ascii(char *nonceStr, uint8_t *nonceLen) {
  for (int8_t i = *nonceLen - 1; i >= 0; --i) {
    if (nonceStr[i] != '9') {
      nonceStr[i]++;
      return;
    }
    nonceStr[i] = '0';
  }

  for (uint8_t i = *nonceLen; i > 0; --i) {
    nonceStr[i] = nonceStr[i - 1];
  }

  nonceStr[0] = '1';
  (*nonceLen)++;
  nonceStr[*nonceLen] = 0;
}
#endif

// DUCO-S1A hasher
uintDiff ducos1a(char const * prevBlockHash, char const * targetBlockHash, uintDiff difficulty) {
  #if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
    // If the difficulty is too high for AVR architecture then return 0
    if (difficulty > 655) return 0;
  #endif

  uint32_t targetWords[SHA1_HASH_LEN / 4];
  lowercase_hex_to_words(targetBlockHash, targetWords);

  uintDiff const maxNonce = difficulty * 100 + 1;
  return ducos1a_mine(prevBlockHash, targetWords, maxNonce);
}

uintDiff ducos1a_mine(char const * prevBlockHash, uint32_t const * targetWords, uintDiff maxNonce) {
  static duco_hash_state_t hash;
  duco_hash_init(&hash, prevBlockHash);

#if defined(__AVR__)
  // AVR path caps difficulty at 655, so max nonce is 65501 (5 digits).
  char nonceStr[5 + 1] = "0";
  uint8_t nonceLen = 1;
  uint16_t maxNonceAvr = (uint16_t)maxNonce;
#else
  char nonceStr[10 + 1];
#endif
  for (
#if defined(__AVR__)
      uint16_t nonce = 0; nonce < maxNonceAvr; nonce++
#else
      uintDiff nonce = 0; nonce < maxNonce; nonce++
#endif
  ) {
#if defined(__AVR__)
    if (duco_hash_try_nonce(&hash, nonceStr, nonceLen, targetWords)) {
      return nonce;
    }
#else
    ultoa(nonce, nonceStr, 10);
    if (duco_hash_try_nonce(&hash, nonceStr, strlen(nonceStr), targetWords)) {
      return nonce;
    }
#endif

#if defined(__AVR__)
    increment_nonce_ascii(nonceStr, &nonceLen);
#endif
  }

  return 0;
}

void loop() {
  // Wait for serial data
  if (Serial.available() <= 0) {
    return;
  }

  // Reserve 1 extra byte for comma separator (and later zero)
  char lastBlockHash[40 + 1];
  char newBlockHash[40 + 1];

  // Read last block hash
  if (Serial.readBytesUntil(',', lastBlockHash, 41) != 40) {
    return;
  }
  lastBlockHash[40] = 0;

  // Read expected hash
  if (Serial.readBytesUntil(',', newBlockHash, 41) != 40) {
    return;
  }
  newBlockHash[40] = 0;

  // Read difficulty
  uintDiff difficulty = strtoul(Serial.readStringUntil(',').c_str(), NULL, 10);
  // Clearing the receive buffer reading one job.
  while (Serial.available()) Serial.read();
  // Turn off the built-in led
  #if defined(ARDUINO_ARCH_AVR)
      PORTB = PORTB | B00100000;
  #else
      digitalWrite(LED_BUILTIN, LOW);
  #endif

  // Start time measurement
  uint32_t startTime = micros();

  // Call DUCO-S1A hasher
  uintDiff ducos1result = ducos1a(lastBlockHash, newBlockHash, difficulty);

  // Calculate elapsed time
  uint32_t elapsedTime = micros() - startTime;

  // Turn on the built-in led
  #if defined(ARDUINO_ARCH_AVR)
      PORTB = PORTB & B11011111;
  #else
      digitalWrite(LED_BUILTIN, HIGH);
  #endif

  // Clearing the receive buffer before sending the result.
  while (Serial.available()) Serial.read();

  // Send result back to the program with share time
  Serial.print(String(ducos1result, 2) 
               + SEP_TOKEN
               + String(elapsedTime, 2) 
               + SEP_TOKEN
               + String(DUCOID) 
               + END_TOKEN);
}

#pragma once
#include <Arduino.h>

#ifndef DUINO_MINER_BAUD
#define DUINO_MINER_BAUD 115200u
#endif
#ifndef DUINO_MINER_SERIAL_TIMEOUT_MS
#define DUINO_MINER_SERIAL_TIMEOUT_MS 2000u
#endif

#define DUINO_HASH_HEX_LEN 40u
#define DUINO_ERR_RESPONSE "ERR\n"

#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
typedef uint32_t duino_uint_diff_t;
#define DUINO_MAX_SAFE_DIFF 655u
#else
typedef uint32_t duino_uint_diff_t;
#define DUINO_MAX_SAFE_DIFF 100000u
#endif

#if (defined(__AVR_ATmega328P__) || defined(__AVR_ATmega328__) \
     || defined(__AVR_ATmega168__) || defined(__AVR_ATmega168P__)) \
    && (LED_BUILTIN == 13)
#define DUINO_LED_MINING_PORTB
#endif

static inline void duino_led_mining_on(void) {
#if defined(DUINO_LED_MINING_PORTB)
  PORTB |= (uint8_t)(1 << 5);
#else
  digitalWrite(LED_BUILTIN, HIGH);
#endif
}
static inline void duino_led_mining_off(void) {
#if defined(DUINO_LED_MINING_PORTB)
  PORTB &= (uint8_t)~(1 << 5);
#else
  digitalWrite(LED_BUILTIN, LOW);
#endif
}

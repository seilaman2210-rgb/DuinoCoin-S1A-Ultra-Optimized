#pragma once
#include <Arduino.h>
#include "duino_miner_config.h"

#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
#include <avr/wdt.h>
#define DUINO_WDT_RESET() wdt_reset()
#else
#define DUINO_WDT_RESET() ((void)0)
#endif

#pragma GCC optimize ("-Ofast")

static inline void duino_serial_flush_read(void) {
  while (Serial.available() > 0) { DUINO_WDT_RESET(); (void)Serial.read(); }
}
static inline void duino_send_err_and_flush(void) {
  duino_serial_flush_read();
  Serial.print(DUINO_ERR_RESPONSE);
}
static inline bool duino_wait_serial_byte(uint32_t timeout_ms) {
  uint32_t start_ms = millis();
  while (Serial.available() <= 0) {
    DUINO_WDT_RESET();
    if ((uint32_t)(millis() - start_ms) >= timeout_ms) return false;
    delay(1);
  }
  return true;
}
static inline bool duino_read_char_with_timeout(char* out_char) {
  if (!duino_wait_serial_byte(DUINO_MINER_SERIAL_TIMEOUT_MS)) return false;
  int c = Serial.read();
  if (c < 0) return false;
  *out_char = (char)c;
  return true;
}
static inline bool duino_is_lower_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}
static inline bool duino_read_hash_field_until_comma(char* out_hash, uint8_t hex_len) {
  char c = '\0';
  for (uint8_t i = 0; i < hex_len; i++) {
    if (!duino_read_char_with_timeout(&c) || !duino_is_lower_hex_char(c)) return false;
    out_hash[i] = c;
  }
  out_hash[hex_len] = '\0';
  if (!duino_read_char_with_timeout(&c)) return false;
  return c == ',';
}
static inline bool duino_read_difficulty_until_comma(duino_uint_diff_t* out_diff) {
  uint32_t v = 0u; uint8_t digits = 0; char c = '\0';
  for (;;) {
    if (!duino_read_char_with_timeout(&c)) return false;
    if (c == ',') break;
    if ((uint8_t)c >= '0' && (uint8_t)c <= '9') {
      uint8_t d = (uint8_t)c - (uint8_t)'0';
      if (v > (0xFFFFFFFFu - d) / 10u) return false;
      v = v * 10u + d;
      if (++digits > 9u) return false;
    } else return false;
  }
  if (digits == 0u) return false;
  *out_diff = (duino_uint_diff_t)v;
  return true;
}
static inline bool duino_discard_job_tail(void) {
  char c = '\0';
  if (!duino_read_char_with_timeout(&c) || c != '0') return false;
  if (!duino_read_char_with_timeout(&c)) return false;
  if (c == '\r') { if (!duino_read_char_with_timeout(&c)) return false; }
  return c == '\n';
}

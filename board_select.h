#ifndef BOARD_SELECT_H
#define BOARD_SELECT_H

// Select board profile by ESP-IDF target macro from Arduino core.
// Supports Wi-Fi capable ESP32 variants used by this project.

#if defined(FORCE_BOARD_PROFILE_PRODINO_ESP32_ETH)
#include "boards/board_profile_prodino_esp32_eth.h"
#elif defined(FORCE_BOARD_PROFILE_WAVESHARE_ESP32_P4_ETH)
#include "boards/board_profile_waveshare_esp32_p4_eth.h"
#elif defined(CONFIG_IDF_TARGET_ESP32)
#include "boards/board_profile_esp32.h"
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
#include "boards/board_profile_esp32s2.h"
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
#include "boards/board_profile_esp32s3.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C2)
#include "boards/board_profile_esp32c2.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
#include "boards/board_profile_esp32c3.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
#include "boards/board_profile_esp32c6.h"
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
#error "ESP32-H2 has no Wi-Fi. This project requires Wi-Fi + MQTT."
#elif defined(CONFIG_IDF_TARGET_ESP32P4)
#include "boards/board_profile_waveshare_esp32_p4_eth.h"
#else
// Fallback to classic ESP32 profile.
#include "boards/board_profile_esp32.h"
#endif

#endif

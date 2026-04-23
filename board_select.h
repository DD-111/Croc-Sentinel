#ifndef BOARD_SELECT_H
#define BOARD_SELECT_H

// Select board profile by ESP-IDF target macro from Arduino core.
// You can force a specific profile (e.g. for a custom ETH-equipped board)
// by defining one of the FORCE_BOARD_PROFILE_* macros in the build flags.

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
// ESP32-P4's stock Arduino core ships without Wi-Fi; all P4 boards here are
// assumed to be the Waveshare ETH variant. Provide FORCE_BOARD_PROFILE_* if
// your P4 carrier has a different PHY.
#include "boards/board_profile_waveshare_esp32_p4_eth.h"
#else
#warning "Unknown IDF target — falling back to classic ESP32 profile."
#include "boards/board_profile_esp32.h"
#endif

// Every profile must define these. Surfaced as a hard compile-time error if
// a new profile is added without the required fields.
#ifndef BOARD_PROFILE_NAME
#error "board profile missing BOARD_PROFILE_NAME"
#endif
#ifndef BOARD_DEFAULT_NETIF_MODE
#error "board profile missing BOARD_DEFAULT_NETIF_MODE (1=Wi-Fi 2=Ethernet 3=Auto)"
#endif
#ifndef BOARD_HAS_ETH
#define BOARD_HAS_ETH 0
#endif
#ifndef BOARD_BOOT_GPIO
#define BOARD_BOOT_GPIO (-1)
#endif

#endif

#ifndef BOARD_PROFILE_WAVESHARE_ESP32_P4_ETH_H
#define BOARD_PROFILE_WAVESHARE_ESP32_P4_ETH_H

#define BOARD_PROFILE_NAME "waveshare_esp32_p4_eth"
#define BOARD_HAS_ETH 1
// ESP32-P4 has no WiFi radio in the stock Arduino core — keep ETHERNET only.
#define BOARD_DEFAULT_NETIF_MODE 2
#define BOARD_DEFAULT_SIREN_GPIO 25
#define BOARD_DEFAULT_TRIGGER_GPIO 33
#define BOARD_DEFAULT_STATUS_LED_GPIO 2
#define BOARD_HAS_VBAT_ADC 0

// Placeholder PHY defaults for P4 Ethernet board.
// Adjust pins/PHY according to the exact Waveshare revision.
#define BOARD_ETH_PHY_TYPE ETH_PHY_RTL8201
#define BOARD_ETH_PHY_ADDR 1
#define BOARD_ETH_MDC_PIN 31
#define BOARD_ETH_MDIO_PIN 52
#define BOARD_ETH_POWER_PIN -1
#define BOARD_ETH_CLK_MODE ETH_CLOCK_GPIO0_IN

#endif

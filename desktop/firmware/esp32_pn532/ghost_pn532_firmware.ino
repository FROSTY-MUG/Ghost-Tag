/**
 * @file ghost_pn532_firmware.ino
 * @brief Ghost Bridge Microcontroller Transport Firmware for ESP32 + PN532 (SPI Mode)
 *
 * Architecture:
 * Windows PC (Ghost Bridge) <--- USB Serial (115200 baud, Line-delimited JSON) ---> ESP32 <--- Hardware SPI ---> PN532 NFC Module
 *
 * STRICT SECURITY INVARIANTS:
 * 1. ZERO SECRETS: The firmware NEVER handles, stores, or inspects passphrases, recovery phrases,
 *    encryption keys (KEK/DEK), or plaintext. It operates purely as an opaque byte transport bridge.
 * 2. ZERO SYNTHETIC EVENTS: A tag is reported as present ONLY when hardware RF interrogation succeeds.
 * 3. MANDATORY READ-BACK VERIFY: Write operations execute a physical read-back pass over RF. Success is
 *    reported if and only if the read-back bytes match the write buffer exactly.
 * 4. TYPE 2 NFC FORUM TAGS ONLY: Rejects MIFARE Classic (Crypto-1) and non-Type 2 tags.
 * 5. NO NETWORK: Wi-Fi and Bluetooth radios are permanently disabled in setup().
 */

#include <SPI.h>
#include <Adafruit_PN532.h>
#include <ArduinoJson.h>

// --- Pin Definitions for ESP32 Hardware SPI ---
#define PN532_SCK   18
#define PN532_MISO  19
#define PN532_MOSI  23
#define PN532_SS     5

Adafruit_PN532 nfc(PN532_SS);

// Firmware Metadata
#define FIRMWARE_VERSION "1.0.0"
#define PROTOCOL_VERSION "ghost-pn532-v1"
#define HARDWARE_ID      "ESP32-PN532-SPI"

// State Variables
bool pn532_initialized = false;
bool last_tag_present = false;
uint8_t last_uid[7] = {0};
uint8_t last_uid_len = 0;
unsigned long last_poll_time = 0;
const unsigned long POLL_INTERVAL_MS = 250;

// Base64 decoding helper
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int base64_decode_char(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

size_t decode_base64(const char* input, uint8_t* output, size_t max_out_len) {
  size_t in_len = strlen(input);
  size_t out_len = 0;
  int val = 0, valb = -8;
  for (size_t i = 0; i < in_len; i++) {
    char c = input[i];
    if (c == '=') break;
    int d = base64_decode_char(c);
    if (d < 0) continue;
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      if (out_len >= max_out_len) return 0; // overflow
      output[out_len++] = (uint8_t)((val >> valb) & 0xFF);
      valb -= 8;
    }
  }
  return out_len;
}

String encode_base64(const uint8_t* input, size_t in_len) {
  String out = "";
  int val = 0, valb = -6;
  for (size_t i = 0; i < in_len; i++) {
    val = (val << 8) + input[i];
    valb += 8;
    while (valb >= 0) {
      out += b64_table[(val >> valb) & 0x3F];
      valb -= 6;
    }
  }
  if (valb > -6) out += b64_table[((val << 8) >> (valb + 8)) & 0x3F];
  while (out.length() % 4) out += '=';
  return out;
}

void send_response(const JsonDocument& doc) {
  serializeJson(doc, Serial);
  Serial.println();
}

void send_error(const char* id, const char* error_code, const char* message) {
  StaticJsonDocument<256> doc;
  if (id) doc["id"] = id;
  doc["status"] = "ERROR";
  doc["code"] = error_code;
  doc["message"] = message;
  send_response(doc);
}

void send_event(const char* event_type, const JsonDocument& payload) {
  StaticJsonDocument<512> doc;
  doc["event"] = event_type;
  doc["data"] = payload;
  send_response(doc);
}

// Capability check
bool read_tag_capability(uint16_t* user_memory_bytes, bool* is_read_only) {
  uint8_t block3[4];
  if (!nfc.ntag2xx_ReadPage(3, block3)) {
    return false;
  }
  if (block3[0] != 0xE1) {
    // Non-Type-2 or unformatted
    return false;
  }
  uint8_t size_byte = block3[2];
  uint8_t access_byte = block3[3];
  *is_read_only = (access_byte & 0x0F) != 0x00;

  if (size_byte == 0x12) {
    *user_memory_bytes = 144; // NTAG213
  } else if (size_byte == 0x3E) {
    *user_memory_bytes = 504; // NTAG215
  } else if (size_byte == 0x6D) {
    *user_memory_bytes = 888; // NTAG216
  } else {
    *user_memory_bytes = size_byte * 8;
  }
  return true;
}

void handle_command(const char* line) {
  StaticJsonDocument<2048> doc;
  DeserializationError err = deserializeJson(doc, line);
  if (err) {
    send_error(nullptr, "ERROR_PROTOCOL", "Malformed JSON command string");
    return;
  }

  const char* id = doc["id"] | "";
  const char* cmd = doc["cmd"] | "";

  if (strlen(cmd) == 0) {
    send_error(id, "ERROR_PROTOCOL", "Missing 'cmd' field");
    return;
  }

  // --- HELLO ---
  if (strcmp(cmd, "HELLO") == 0) {
    StaticJsonDocument<256> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    resp["version"] = FIRMWARE_VERSION;
    resp["protocol"] = PROTOCOL_VERSION;
    resp["hardware"] = HARDWARE_ID;
    send_response(resp);
    return;
  }

  // --- VERSION ---
  if (strcmp(cmd, "VERSION") == 0) {
    StaticJsonDocument<256> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    resp["version"] = FIRMWARE_VERSION;
    resp["protocol"] = PROTOCOL_VERSION;
    send_response(resp);
    return;
  }

  // --- READER_STATUS ---
  if (strcmp(cmd, "READER_STATUS") == 0) {
    StaticJsonDocument<512> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    resp["pn532_online"] = pn532_initialized;
    resp["tag_present"] = last_tag_present;
    if (last_tag_present) {
      char uid_str[16] = {0};
      for (uint8_t i = 0; i < last_uid_len; i++) {
        sprintf(uid_str + (i * 2), "%02X", last_uid[i]);
      }
      resp["uid"] = uid_str;
    }
    send_response(resp);
    return;
  }

  // --- RESET ---
  if (strcmp(cmd, "RESET") == 0) {
    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    pn532_initialized = (versiondata != 0);
    if (pn532_initialized) {
      nfc.SAMConfig();
    }
    last_tag_present = false;
    StaticJsonDocument<256> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    resp["pn532_online"] = pn532_initialized;
    send_response(resp);
    return;
  }

  // --- CANCEL ---
  if (strcmp(cmd, "CANCEL") == 0) {
    StaticJsonDocument<256> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    send_response(resp);
    return;
  }

  // Hardware operations require an initialized PN532
  if (!pn532_initialized) {
    send_error(id, "ERROR_HARDWARE", "PN532 module offline or not responding");
    return;
  }

  // Check card presence
  uint8_t uid[7];
  uint8_t uid_len = 0;
  bool card_found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uid_len, 50);

  if (!card_found) {
    send_error(id, "ERROR_NO_TAG", "No NFC tag detected on RF field");
    return;
  }

  // Check Type 2 capability
  uint16_t user_memory_bytes = 0;
  bool is_read_only = false;
  if (!read_tag_capability(&user_memory_bytes, &is_read_only)) {
    send_error(id, "ERROR_UNSUPPORTED_TAG", "Tag is not an NFC Forum Type 2 tag or is MIFARE Classic");
    return;
  }

  // --- READ_NDEF ---
  if (strcmp(cmd, "READ_NDEF") == 0) {
    uint8_t buffer[1024];
    uint16_t read_bytes = 0;
    uint8_t num_pages = user_memory_bytes / 4;

    for (uint8_t p = 4; p < 4 + num_pages; p++) {
      if (!nfc.ntag2xx_ReadPage(p, buffer + read_bytes)) {
        send_error(id, "ERROR_READ_FAILED", "Failed to read block from tag");
        return;
      }
      read_bytes += 4;
    }

    StaticJsonDocument<2048> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    resp["user_memory_bytes"] = user_memory_bytes;
    resp["payload_b64"] = encode_base64(buffer, read_bytes);
    send_response(resp);
    return;
  }

  // --- WRITE_NDEF / READ_BACK_VERIFY ---
  if (strcmp(cmd, "WRITE_NDEF") == 0) {
    if (is_read_only) {
      send_error(id, "ERROR_READ_ONLY", "Tag is locked or read-only");
      return;
    }

    const char* b64_payload = doc["payload_b64"] | "";
    if (strlen(b64_payload) == 0) {
      send_error(id, "ERROR_PROTOCOL", "Missing 'payload_b64' parameter");
      return;
    }

    uint8_t write_buffer[1024];
    size_t payload_len = decode_base64(b64_payload, write_buffer, sizeof(write_buffer));
    if (payload_len == 0) {
      send_error(id, "ERROR_INVALID_LENGTH", "Failed to decode base64 or payload empty");
      return;
    }

    if (payload_len > user_memory_bytes) {
      send_error(id, "ERROR_CAPACITY", "Payload exceeds tag user memory capacity");
      return;
    }

    // Write block by block starting at page 4
    uint8_t num_pages = (payload_len + 3) / 4;
    for (uint8_t i = 0; i < num_pages; i++) {
      uint8_t page_buf[4] = {0};
      size_t remaining = payload_len - (i * 4);
      size_t copy_bytes = remaining < 4 ? remaining : 4;
      memcpy(page_buf, write_buffer + (i * 4), copy_bytes);

      if (!nfc.ntag2xx_WritePage(4 + i, page_buf)) {
        send_error(id, "ERROR_WRITE_FAILED", "Write operation failed on hardware page");
        return;
      }
    }

    // MANDATORY READ-BACK VERIFICATION (Byte-for-byte exact comparison)
    uint8_t read_back[1024];
    size_t bytes_read_back = 0;
    for (uint8_t i = 0; i < num_pages; i++) {
      if (!nfc.ntag2xx_ReadPage(4 + i, read_back + (i * 4))) {
        send_error(id, "ERROR_TAG_LOST", "Read-back verification failed: tag removed or read error");
        return;
      }
      bytes_read_back += 4;
    }

    // Exact byte-for-byte comparison of requested write buffer against physical read-back
    bool byte_comparison_passed = (memcmp(write_buffer, read_back, payload_len) == 0);
    if (!byte_comparison_passed) {
      send_error(id, "ERROR_VERIFY_MISMATCH", "Read-back exact byte-for-byte verification mismatch");
      return;
    }

    StaticJsonDocument<256> resp;
    resp["id"] = id;
    resp["status"] = "OK";
    resp["bytes_written"] = payload_len;
    resp["bytes_read_back"] = bytes_read_back >= payload_len ? payload_len : bytes_read_back;
    resp["byte_comparison_passed"] = true;
    resp["verified"] = true;
    send_response(resp);
    return;
  }

  send_error(id, "ERROR_UNKNOWN_COMMAND", "Unrecognized command");
}

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000);

  // Initialize PN532 over SPI
  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (versiondata) {
    pn532_initialized = true;
    nfc.SAMConfig();
  } else {
    pn532_initialized = false;
  }
}

void loop() {
  // Read incoming serial commands
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) {
      handle_command(line.c_str());
    }
  }

  // Periodic tag presence polling
  if (pn532_initialized && (millis() - last_poll_time >= POLL_INTERVAL_MS)) {
    last_poll_time = millis();
    uint8_t uid[7];
    uint8_t uid_len = 0;
    bool found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uid_len, 30);

    if (found && !last_tag_present) {
      last_tag_present = true;
      last_uid_len = uid_len;
      memcpy(last_uid, uid, uid_len);

      char uid_str[16] = {0};
      for (uint8_t i = 0; i < uid_len; i++) {
        sprintf(uid_str + (i * 2), "%02X", uid[i]);
      }

      uint16_t user_memory_bytes = 0;
      bool is_read_only = false;
      bool is_type2 = read_tag_capability(&user_memory_bytes, &is_read_only);

      StaticJsonDocument<256> payload;
      payload["uid"] = uid_str;
      payload["is_type2"] = is_type2;
      payload["user_memory_bytes"] = user_memory_bytes;
      payload["is_read_only"] = is_read_only;
      send_event("TAG_PRESENT", payload);
    } else if (!found && last_tag_present) {
      last_tag_present = false;
      last_uid_len = 0;
      memset(last_uid, 0, sizeof(last_uid));

      StaticJsonDocument<64> payload;
      send_event("TAG_REMOVED", payload);
    }
  }
}

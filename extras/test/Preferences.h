/*
 * Stand-in for the ESP32 Preferences library, for the host tests. The
 * namespaces live in Preferences::flash(), which outlives the Preferences
 * objects as NVS outlives a reset, and which the tests can read and alter.
 */

#pragma once

#include <stdint.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

class Preferences {
 public:
  using Namespace = std::map<std::string, std::vector<uint8_t>>;

  static std::map<std::string, Namespace> &flash() {
    static std::map<std::string, Namespace> f;
    return f;
  }

  bool begin(const char *name, bool readOnly = false, const char *partition = nullptr) {
    (void)readOnly;
    (void)partition;
    if (strlen(name) > 15) return false;
    ns_ = &flash()[name];
    return true;
  }
  void end() { ns_ = nullptr; }

  bool clear() {
    if (!ns_) return false;
    ns_->clear();
    return true;
  }
  bool remove(const char *key) { return ns_ && ns_->erase(key) == 1; }
  bool isKey(const char *key) { return ns_ && ns_->count(key) == 1; }

  size_t putBytes(const char *key, const void *value, size_t len) {
    if (!ns_) return 0;
    const uint8_t *p = static_cast<const uint8_t *>(value);
    (*ns_)[key].assign(p, p + len);
    return len;
  }
  size_t putUInt(const char *key, uint32_t value) { return putBytes(key, &value, sizeof(value)); }
  uint32_t getUInt(const char *key, uint32_t defaultValue = 0) {
    uint32_t v;
    return getBytes(key, &v, sizeof(v)) == sizeof(v) ? v : defaultValue;
  }

  size_t getBytesLength(const char *key) {
    if (!ns_ || !ns_->count(key)) return 0;
    return (*ns_)[key].size();
  }
  size_t getBytes(const char *key, void *buf, size_t maxLen) {
    if (!ns_ || !ns_->count(key)) return 0;
    const std::vector<uint8_t> &v = (*ns_)[key];
    if (v.size() > maxLen) return 0;
    memcpy(buf, v.data(), v.size());
    return v.size();
  }

 private:
  Namespace *ns_ = nullptr;
};

# Changelog

## 1.0.4
No changes from 1.0.3. This version exists to be the official public release version.

## 1.0.3

### Patches
* Fix performance issue caused by always clearing the OpenSSL error stack
* Correctly clear OpenSSL error stack in failed signature verification

### Maintenance
* Make coverage fail if OpenSSL error stack isn't clean
* Consolidate version information to single location
* Improve docs

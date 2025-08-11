# Performance

Encryption and decryption speed

## 

SwiftPQHPKE's encryption and decryption performance was measured on a MacBook Pro 2024, Apple M3 chip.

The time to create a ``SwiftPQHPKE/Sender`` and ``SwiftPQHPKE/Recipient`` instance in base mode is shown in the table below,
depending on the KEM type - units are microseconds.

| KEM        | Create Sender | Create Recipient |
|-----------:|--------------:|-----------------:|
| ML512      | 107 uSec      | 104 uSec         |
| ML768      | 124 uSec      | 150 uSec         |
| ML1024     | 176 uSec      | 213 uSec         |

The encryption and decryption speed in base mode, once the `Sender` or `Recipient` instance is created,
is shown in the table below, depending on the AEAD type - units are megabytes / second.

| AEAD       | Encryption speed | Decryption speed |
|-----------:|-----------------:|-----------------:|
| AESGCM128  | 6000 MB/Sec      | 6000 MB/Sec      |
| AESGCM256  | 5600 MB/Sec      | 5400 MB/Sec      |
| CHACHAPOLY |  780 MB/Sec      |  790 MB/Sec      |

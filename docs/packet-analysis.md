# Packet Analysis

## Overview
The Packet Analysis module provides Deep Packet Inspection (DPI) capabilities by integrating `tshark` and `capinfos`. It allows analysts to upload PCAP/PCAPNG files, validates them securely, and extracts protocol hierarchies, endpoints, conversations, and granular packet dissections.

## Architecture and Components

### File Upload and Validation
When a PCAP file is uploaded, the system performs strict validation to prevent malicious uploads and ensure data integrity:
- **Extension & Size limits**: Restricts uploads to `.pcap` and `.pcapng` files and enforces a maximum size limit (e.g., 50MB, mode `0o750` for storage in `instance/pcap_uploads/`).
- **Magic Bytes Validation**: Verifies the file header against known PCAP/PCAPNG magic numbers (e.g., `\xa1\xb2\xc3\xd4`, `\x0a\x0d\x0d\x0a`).
- **SHA-256 Deduplication**: Calculates the file's SHA-256 hash during streaming. If an identical file has already been analyzed, the system returns the existing analysis to save processing time unless forced to reanalyze.
- **Probe Test**: Runs a quick `tshark -r <file> -c 1` probe to ensure the capture is readable and not corrupt.

### Metadata and Statistics Extraction
- **Capinfos**: Used to quickly extract metadata such as packet count, capture duration, earliest/latest packet times, and encapsulation type (`capinfos -a -e -c -u -d -E`).
- **TShark Analytics**: 
  - **Protocol Hierarchy**: Extracted using `tshark -q -z io,phs` to calculate frame and byte percentages per protocol layer.
  - **Conversations**: Extracted using `tshark -q -z conv,ip` (and `conv,tcp`) to find the top communicating endpoints.
  - **Endpoints**: Extracted using `tshark -q -z endpoints,ip`.

### Display Filter Security
When querying specific packets via Wireshark display filters, the input is strictly validated:
- Checked against a safe character regex whitelist.
- Checked for forbidden shell tokens (`;`, `$`, backticks).
- Dry-run tested against a 24-byte empty PCAP header to validate Wireshark syntax without exposing the system to injection vulnerabilities.

### Packet Dissection
For deep packet inspection, the module fetches paginated packet listings and detailed per-packet data:
- Detailed JSON dissection trees are fetched using `tshark -T json`.
- Raw hex dumps are fetched using `tshark -x`.

## External Dependencies
- **Binaries**: `/usr/bin/tshark`, `/usr/bin/capinfos`

## Storage
- Uploaded files are securely stored in `instance/pcap_uploads/` with restricted permissions (mode `0o750`).

## API Endpoints
- `POST /packet-analysis/api/upload` - Securely uploads and enqueues PCAP analysis.
- `GET /packet-analysis/api/analyses/<id>` - Retrieves analysis metadata.
- `GET /packet-analysis/api/analyses/<id>/protocols` - Protocol hierarchy stats.
- `GET /packet-analysis/api/analyses/<id>/conversations` - Top conversations.
- `GET /packet-analysis/api/analyses/<id>/packets` - Paginated packet listing (supports `display_filter`).
- `GET /packet-analysis/api/analyses/<id>/packets/<num>` - Deep JSON dissection and hex dump for a specific packet.

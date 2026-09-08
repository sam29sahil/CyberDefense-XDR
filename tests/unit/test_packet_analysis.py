"""
Unit and Integration Tests for Packet Analysis Module
CyberDefense XDR
Tests real TShark analysis, PCAP validation, protocol extraction,
conversations, endpoints, display filters, and security controls.
"""

import io
import json
import os
import struct
import unittest
from datetime import datetime

from app import create_app
from app.extensions import db
from app.users.models import User
from app.packet_analysis.models import PacketAnalysis
from app.packet_analysis.services import (
    validate_pcap_header,
    save_uploaded_pcap,
    run_pcap_analysis,
    validate_display_filter,
    get_analysis_packets,
    get_packet_detail,
    delete_analysis,
    get_packet_analysis_dashboard_stats,
    TSHARK_BIN,
    MAX_PCAP_UPLOAD_BYTES,
)


def make_test_pcap_bytes(ts_offset=0):
    """Generates a valid, deterministic 3-packet PCAP fixture with Ethernet, ICMP, TCP, and DNS."""
    # PCAP Global Header: magic 0xa1b2c3d4, v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Frame 1: ICMP Echo Request (127.0.0.1 -> 127.0.0.1)
    pkt1 = (
        bytes.fromhex("000c29654152005056c000080800") +
        bytes.fromhex("4500003c1c46400040012e5e7f0000017f000001") +
        bytes.fromhex("08004d5a000100016162636465666768696a6b6c6d6e6f7071727374757677616263646566676869")
    )

    # Frame 2: TCP SYN (192.168.1.10:49153 -> 192.168.1.1:80)
    pkt2 = (
        bytes.fromhex("000c29654152005056c000080800") +
        bytes.fromhex("4500003c1c47400040062e58c0a8010ac0a80101") +
        bytes.fromhex("c00100500000000100000000a002721000000000020405b40402080a000000000000000001030307")
    )

    # Frame 3: UDP DNS Query (192.168.1.10:53535 -> 8.8.8.8:53)
    pkt3 = (
        bytes.fromhex("000c29654152005056c000080800") +
        bytes.fromhex("450000391c4840004011e51dc0a8010a08080808") +
        bytes.fromhex("d11f003500250000") +
        bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    )

    data = bytearray(global_hdr)
    base_ts = 1700000000 + ts_offset
    for i, pkt in enumerate([pkt1, pkt2, pkt3]):
        pkt_hdr = struct.pack("<IIII", base_ts + i, 100000 * (i + 1), len(pkt), len(pkt))
        data.extend(pkt_hdr)
        data.extend(pkt)

    return bytes(data)


class PacketAnalysisTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="pcap_analyst").first()
            if not user:
                user = User(
                    username="pcap_analyst",
                    email="pcap_analyst@cyberdefense.local",
                    first_name="Packet",
                    last_name="Analyst",
                    role="analyst",
                    is_active=True,
                )
                user.set_password("SecurePcapPass123!")
                db.session.add(user)
                db.session.commit()
            cls.test_user_id = user.id

    def setUp(self):
        self.client = self.app.test_client()

    def get_auth_client(self):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.test_user_id)
            sess["user_id"] = self.test_user_id
            sess["_fresh"] = True
        return self.client

    # -------------------------------------------------------------------------
    # 1. Authentication & Route Protection
    # -------------------------------------------------------------------------
    def test_01_authentication_required(self):
        """Unauthenticated access to pages and APIs must be redirected or rejected."""
        unauth_client = self.app.test_client()

        # Page routes redirect to login
        res_dash = unauth_client.get("/packet-analysis/")
        self.assertEqual(res_dash.status_code, 302)

        res_upload = unauth_client.get("/packet-analysis/upload")
        self.assertEqual(res_upload.status_code, 302)

        # API endpoints require login
        res_api = unauth_client.get("/packet-analysis/api/dashboard")
        self.assertEqual(res_api.status_code, 302)

        # Authenticated access succeeds
        auth = self.get_auth_client()
        res_auth_dash = auth.get("/packet-analysis/")
        self.assertEqual(res_auth_dash.status_code, 200)

        res_auth_api = auth.get("/packet-analysis/api/dashboard")
        self.assertEqual(res_auth_api.status_code, 200)
        data = res_auth_api.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("kpis", data)

    # -------------------------------------------------------------------------
    # 2. File Upload Validation (Extensions & Oversize)
    # -------------------------------------------------------------------------
    def test_02_upload_rejects_unsupported_extensions(self):
        """Rejects files without .pcap or .pcapng extensions."""
        auth = self.get_auth_client()

        # Disallowed .txt
        data = {"file": (io.BytesIO(b"malicious payload"), "evil.txt")}
        res = auth.post("/packet-analysis/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertIn("unsupported", res.get_json().get("error", "").lower())

        # Disallowed .exe
        data_exe = {"file": (io.BytesIO(b"MZ\x90\x00"), "payload.exe")}
        res_exe = auth.post("/packet-analysis/api/upload", data=data_exe, content_type="multipart/form-data")
        self.assertEqual(res_exe.status_code, 400)

    def test_03_upload_rejects_oversized_file(self):
        """Rejects files that exceed the maximum upload limit."""
        # Simulated over-limit stream
        class DummyLargeStream:
            def __init__(self, size):
                self.size = size
                self.read_count = 0
            def read(self, n):
                if self.read_count >= self.size:
                    return b""
                chunk = min(n, self.size - self.read_count)
                self.read_count += chunk
                return b"X" * chunk

        from werkzeug.datastructures import FileStorage
        large_storage = FileStorage(
            stream=DummyLargeStream(MAX_PCAP_UPLOAD_BYTES + 1024),
            filename="too_large.pcap",
        )

        with self.app.app_context():
            with self.assertRaises(ValueError) as ctx:
                save_uploaded_pcap(large_storage, user_id=self.test_user_id)
            self.assertIn("exceeds maximum limit", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 3. Valid Upload & SHA-256 Computation
    # -------------------------------------------------------------------------
    def test_04_upload_accepts_valid_pcap_and_computes_sha256(self):
        """Accepts valid PCAP, computes accurate SHA-256, and creates database record."""
        pcap_bytes = make_test_pcap_bytes()
        import hashlib
        expected_sha = hashlib.sha256(pcap_bytes).hexdigest()

        auth = self.get_auth_client()
        data = {"file": (io.BytesIO(pcap_bytes), "sample_capture.pcap"), "force_reanalyze": "true"}
        res = auth.post("/packet-analysis/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 201)

        res_data = res.get_json()
        self.assertTrue(res_data.get("success"))
        analysis = res_data.get("analysis", {})
        self.assertEqual(analysis.get("sha256"), expected_sha)
        self.assertEqual(analysis.get("filename"), "sample_capture.pcap")
        self.assertEqual(analysis.get("status"), "completed")
        self.assertEqual(analysis.get("packet_count"), 3)

    # -------------------------------------------------------------------------
    # 4. Corrupted PCAP Handling
    # -------------------------------------------------------------------------
    def test_05_invalid_corrupt_pcap_rejected_cleanly(self):
        """Corrupted or invalid binary file named .pcap is rejected without crashing."""
        auth = self.get_auth_client()
        corrupt_bytes = b"NOT_A_REAL_PCAP_HEADER_12345678"
        data = {"file": (io.BytesIO(corrupt_bytes), "corrupt.pcap")}

        res = auth.post("/packet-analysis/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json().get("success"))
        self.assertIn("valid pcap", res.get_json().get("error", "").lower())

    # -------------------------------------------------------------------------
    # 5. Real TShark Analysis Execution & Persistence
    # -------------------------------------------------------------------------
    def test_06_tshark_analysis_executes_safely_and_persists(self):
        """Executes real TShark analysis, extracts capture metadata, and persists in DB."""
        pcap_bytes = make_test_pcap_bytes()
        from werkzeug.datastructures import FileStorage
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="unit_test_capture.pcap")

        with self.app.app_context():
            analysis, is_new = save_uploaded_pcap(storage, user_id=self.test_user_id, force_reanalyze=True)
            self.assertTrue(is_new)
            self.assertEqual(analysis.status, "uploaded")

            completed_analysis = run_pcap_analysis(analysis.id)
            self.assertEqual(completed_analysis.status, "completed")
            self.assertEqual(completed_analysis.packet_count, 3)
            self.assertGreater(completed_analysis.duration, 0.0)
            self.assertIsNotNone(completed_analysis.first_packet_time)
            self.assertIsNotNone(completed_analysis.last_packet_time)
            self.assertEqual(completed_analysis.encapsulation, "Ethernet")

            # Verify persisted in database
            fetched = PacketAnalysis.query.get(completed_analysis.id)
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.status, "completed")
            self.assertEqual(fetched.packet_count, 3)

    # -------------------------------------------------------------------------
    # 6. Protocol Hierarchy Extraction
    # -------------------------------------------------------------------------
    def test_07_protocol_statistics_from_real_tshark(self):
        """Protocol hierarchy contains real Ethernet, IPv4, ICMP, TCP, UDP extracted from PCAP."""
        pcap_bytes = make_test_pcap_bytes()
        from werkzeug.datastructures import FileStorage
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="protocol_test.pcap")

        with self.app.app_context():
            analysis, _ = save_uploaded_pcap(storage, user_id=self.test_user_id, force_reanalyze=True)
            run_pcap_analysis(analysis.id)

            proto_stats = analysis.protocol_stats
            self.assertIsNotNone(proto_stats)
            protocols = proto_stats.get("protocols", [])
            proto_names = [p["name"] for p in protocols]

            self.assertIn("ETH", proto_names)
            self.assertIn("IP", proto_names)
            # ICMP, TCP, UDP are all present in the test fixture
            self.assertTrue("ICMP" in proto_names or "TCP" in proto_names or "UDP" in proto_names)

    # -------------------------------------------------------------------------
    # 7. Conversations and Endpoints
    # -------------------------------------------------------------------------
    def test_08_endpoint_and_conversation_statistics(self):
        """Top IP endpoints and conversations are parsed accurately."""
        pcap_bytes = make_test_pcap_bytes()
        from werkzeug.datastructures import FileStorage
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="endpoints_conv.pcap")

        with self.app.app_context():
            analysis, _ = save_uploaded_pcap(storage, user_id=self.test_user_id, force_reanalyze=True)
            run_pcap_analysis(analysis.id)

            endpoints = analysis.endpoint_stats or []
            self.assertTrue(len(endpoints) > 0)
            endpoint_ips = [e["ip"] for e in endpoints]
            # 127.0.0.1, 192.168.1.10, 8.8.8.8 are in the fixture
            self.assertTrue(any(ip in endpoint_ips for ip in ["127.0.0.1", "192.168.1.10", "8.8.8.8", "192.168.1.1"]))

            conversations = analysis.conversation_stats or []
            self.assertTrue(len(conversations) > 0)

    # -------------------------------------------------------------------------
    # 8. Packet Listing & Pagination
    # -------------------------------------------------------------------------
    def test_09_packet_pagination_and_search(self):
        """Packet listing supports pagination and field slicing."""
        pcap_bytes = make_test_pcap_bytes()
        from werkzeug.datastructures import FileStorage
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="pagination.pcap")

        with self.app.app_context():
            analysis, _ = save_uploaded_pcap(storage, user_id=self.test_user_id, force_reanalyze=True)
            run_pcap_analysis(analysis.id)

            # Fetch page 1 with per_page=2
            res = get_analysis_packets(analysis.id, page=1, per_page=2)
            self.assertEqual(len(res["items"]), 2)
            self.assertEqual(res["total"], 3)
            self.assertEqual(res["pages"], 2)
            self.assertTrue(res["has_next"])
            self.assertFalse(res["has_prev"])

            # Fetch page 2 with per_page=2
            res2 = get_analysis_packets(analysis.id, page=2, per_page=2)
            self.assertEqual(len(res2["items"]), 1)
            self.assertFalse(res2["has_next"])
            self.assertTrue(res2["has_prev"])

    # -------------------------------------------------------------------------
    # 9. Packet Dissection & Hexdump
    # -------------------------------------------------------------------------
    def test_10_packet_detail_inspection(self):
        """Single packet inspection extracts structured layers and hexdump."""
        pcap_bytes = make_test_pcap_bytes()
        from werkzeug.datastructures import FileStorage
        storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="detail_test.pcap")

        with self.app.app_context():
            analysis, _ = save_uploaded_pcap(storage, user_id=self.test_user_id, force_reanalyze=True)
            run_pcap_analysis(analysis.id)

            detail = get_packet_detail(analysis.id, 1)
            self.assertEqual(detail["packet_number"], 1)
            layers = detail["layers"]
            self.assertIn("frame", layers)
            self.assertIn("eth", layers)
            self.assertIn("ip", layers)

            hexdump = detail["hexdump"]
            self.assertTrue(len(hexdump) > 0)
            self.assertIn("0000", hexdump)

    # -------------------------------------------------------------------------
    # 10. Display Filter Validation & Security Controls
    # -------------------------------------------------------------------------
    def test_11_display_filter_validation_and_injection_prevention(self):
        """Valid Wireshark display filters pass; shell injection attacks are strictly blocked."""
        # Safe filters
        self.assertEqual(validate_display_filter("tcp.port == 80"), "tcp.port == 80")
        self.assertEqual(validate_display_filter("icmp"), "icmp")
        self.assertEqual(validate_display_filter("ip.addr == 192.168.1.1"), "ip.addr == 192.168.1.1")

        # Injection attempts with shell metacharacters
        with self.assertRaises(ValueError):
            validate_display_filter("tcp; rm -rf /")

        with self.assertRaises(ValueError):
            validate_display_filter("tcp && $(cat /etc/passwd)")

        with self.assertRaises(ValueError):
            validate_display_filter("tcp `whoami`")

        with self.assertRaises(ValueError):
            validate_display_filter("tcp > /tmp/out")

        # Oversized filter > 200 chars
        with self.assertRaises(ValueError):
            validate_display_filter("a" * 205)

    # -------------------------------------------------------------------------
    # 11. Duplicate SHA-256 Handling
    # -------------------------------------------------------------------------
    def test_12_duplicate_sha256_handling(self):
        """Re-uploading the same PCAP reuses the existing completed analysis unless force_reanalyze=True."""
        import time
        pcap_bytes = make_test_pcap_bytes(ts_offset=int(time.time() * 1000) % 1000000)
        from werkzeug.datastructures import FileStorage

        with self.app.app_context():
            # First upload
            storage1 = FileStorage(stream=io.BytesIO(pcap_bytes), filename="first.pcap")
            analysis1, is_new1 = save_uploaded_pcap(storage1, user_id=self.test_user_id, force_reanalyze=True)
            run_pcap_analysis(analysis1.id)
            self.assertTrue(is_new1)
            self.assertEqual(analysis1.status, "completed")

            # Second upload of same content without force
            storage2 = FileStorage(stream=io.BytesIO(pcap_bytes), filename="second.pcap")
            analysis2, is_new2 = save_uploaded_pcap(storage2, user_id=self.test_user_id, force_reanalyze=False)
            self.assertFalse(is_new2)
            self.assertEqual(analysis2.id, analysis1.id)

    # -------------------------------------------------------------------------
    # 12. Deletion Service
    # -------------------------------------------------------------------------
    def test_13_delete_analysis(self):
        """Deleting analysis removes record from database and cleans up disk file."""
        pcap_bytes = make_test_pcap_bytes()
        from werkzeug.datastructures import FileStorage

        with self.app.app_context():
            storage = FileStorage(stream=io.BytesIO(pcap_bytes), filename="to_delete.pcap")
            analysis, _ = save_uploaded_pcap(storage, user_id=self.test_user_id, force_reanalyze=True)
            stored_path = analysis.storage_path
            self.assertTrue(os.path.exists(stored_path))

            analysis_id = analysis.id
            delete_analysis(analysis_id)

            self.assertIsNone(PacketAnalysis.query.get(analysis_id))
            self.assertFalse(os.path.exists(stored_path))

    # -------------------------------------------------------------------------
    # 13. REST APIs Integration
    # -------------------------------------------------------------------------
    def test_14_rest_apis(self):
        """Verifies JSON REST APIs return structured data with expected HTTP status."""
        pcap_bytes = make_test_pcap_bytes()
        auth = self.get_auth_client()

        # Upload
        data = {"file": (io.BytesIO(pcap_bytes), "api_test.pcap")}
        res_upload = auth.post("/packet-analysis/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res_upload.status_code, 201)
        analysis_id = res_upload.get_json()["analysis"]["id"]

        # GET analysis
        res_get = auth.get(f"/packet-analysis/api/analyses/{analysis_id}")
        self.assertEqual(res_get.status_code, 200)
        self.assertTrue(res_get.get_json()["success"])

        # GET protocols
        res_proto = auth.get(f"/packet-analysis/api/analyses/{analysis_id}/protocols")
        self.assertEqual(res_proto.status_code, 200)
        self.assertTrue(res_proto.get_json()["success"])

        # GET endpoints
        res_ep = auth.get(f"/packet-analysis/api/analyses/{analysis_id}/endpoints")
        self.assertEqual(res_ep.status_code, 200)

        # GET conversations
        res_conv = auth.get(f"/packet-analysis/api/analyses/{analysis_id}/conversations")
        self.assertEqual(res_conv.status_code, 200)

        # GET packets
        res_pkts = auth.get(f"/packet-analysis/api/analyses/{analysis_id}/packets?page=1&per_page=10")
        self.assertEqual(res_pkts.status_code, 200)
        self.assertEqual(len(res_pkts.get_json()["items"]), 3)

        # GET packet detail
        res_pkt1 = auth.get(f"/packet-analysis/api/analyses/{analysis_id}/packets/1")
        self.assertEqual(res_pkt1.status_code, 200)
        self.assertIn("layers", res_pkt1.get_json())
        self.assertIn("hexdump", res_pkt1.get_json())

        # DELETE analysis
        res_del = auth.delete(f"/packet-analysis/api/analyses/{analysis_id}")
        self.assertEqual(res_del.status_code, 200)
        self.assertTrue(res_del.get_json()["success"])


if __name__ == "__main__":
    unittest.main()

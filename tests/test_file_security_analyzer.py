import pytest
from unittest.mock import patch, MagicMock, mock_open
import os
import json
from src.file_security_analyzer import FileSecurityAnalyzer

class TestFileSecurityAnalyzer:
    def setup_method(self):
        self.config = {
            "virustotal_api_key": "dummy_api_key",
            "yara_rules_path": "dummy_rules.yara"
        }
        self.analyzer = FileSecurityAnalyzer(config_path="dummy_config.json")

    @patch('builtins.open', new_callable=mock_open, read_data=json.dumps({"virustotal_api_key": "dummy_api_key"}))
    def test_load_config(self, mock_file):
        config = self.analyzer._load_config("dummy_config.json")
        assert config["virustotal_api_key"] == "dummy_api_key"
        mock_file.assert_called_once_with("dummy_config.json", "r")

    @patch('yara.compile')
    def test_load_yara_rules(self, mock_compile):
        mock_compile.return_value = MagicMock()
        analyzer = FileSecurityAnalyzer(config_path="dummy_config.json")
        assert analyzer.yara_rules is not None
        mock_compile.assert_called_once_with("dummy_rules.yara")

    @patch('os.path.exists')
    @patch('os.path.getsize')
    @patch('file_security_analyzer.FileSecurityAnalyzer.calculate_file_hashes')
    @patch('file_security_analyzer.FileSecurityAnalyzer.check_malware_database_async')
    @patch('file_security_analyzer.FileSecurityAnalyzer._detect_file_type')
    @patch('file_security_analyzer.FileSecurityAnalyzer.advanced_signature_check')
    @patch('file_security_analyzer.FileSecurityAnalyzer.detect_anomalous_patterns')
    async def test_analyze_file(self, mock_detect_anomalies, mock_signature_check, mock_detect_file_type, mock_check_malware, mock_calculate_hashes, mock_getsize, mock_exists):
        mock_exists.return_value = True
        mock_getsize.return_value = 1234
        mock_calculate_hashes.return_value = {"sha256": "dummy_sha256"}
        mock_check_malware.return_value = {"positives": 0}
        mock_detect_file_type.return_value = "application/x-executable"
        mock_signature_check.return_value = {"yara_matches": [], "known_malware": False}
        mock_detect_anomalies.return_value = []

        result = await self.analyzer.analyze_file("dummy_file.exe")
        assert result["file_path"] == "dummy_file.exe"
        assert result["file_size"] == 1234
        assert result["file_type"] == "application/x-executable"
        assert result["file_hash"]["sha256"] == "dummy_sha256"

    @patch('file_security_analyzer.FileSecurityAnalyzer._detect_file_type')
    def test_detect_file_type(self, mock_detect_file_type):
        mock_detect_file_type.return_value = "text/plain"
        result = self.analyzer._detect_file_type("dummy_file.txt")
        assert result == "text/plain"

    @patch('builtins.open', new_callable=mock_open, read_data=b'\x00' * 1024)
    def test_detect_anomalous_patterns(self, mock_file):
        anomalies = self.analyzer.detect_anomalous_patterns("dummy_file.txt")
        assert "Длинная последовательность нулевых байтов" in anomalies

    @patch('file_security_analyzer.FileSecurityAnalyzer.check_malware_database_async')
    async def test_check_malware_database_async(self, mock_check_malware):
        mock_check_malware.return_value = {"positives": 1}
        result = await self.analyzer.check_malware_database_async("dummy_sha256")
        assert result["positives"] == 1

    def test_calculate_file_hashes(self):
        with patch('builtins.open', mock_open(read_data=b'Test data')):
            hashes = self.analyzer.calculate_file_hashes("dummy_file.txt")
            assert "md5" in hashes
            assert "sha1" in hashes
            assert "sha256" in hashes

    def test_assess_file_risk(self):
        analysis_data = {
            "virus_total_report": {"positives": 6},
            "signature_check": {"known_malware": True, "yara_matches": []},
            "file_type": "application/x-executable"
        }
        risk = self.analyzer._assess_file_risk(analysis_data)
        assert risk == "Critical"
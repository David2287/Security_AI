import pytest
from unittest.mock import patch, MagicMock
from src.security_ai_consultant import SecurityAIConsultant

class TestSecurityAIConsultant:
    def setup_method(self):
        self.consultant = SecurityAIConsultant()

    def test_filter_response(self):
        response = "This is a test of encryption and malware."
        filtered = self.consultant.filter_response(response)
        assert filtered == "encryption malware"

    def test_preprocess_question(self):
        question = "What is the best encryption method?"
        processed = self.consultant.preprocess_question(question)
        assert processed == "what is the best encryption method"

    @patch('security_analyzers.AutoTokenizer')
    @patch('security_analyzers.AutoModelForSequenceClassification')
    def test_generate_response(self, mock_model, mock_tokenizer):
        # Настройка мока для токенизатора и модели
        mock_tokenizer.return_value.encode.return_value = MagicMock()
        mock_model.return_value.generate.return_value = MagicMock()
        mock_tokenizer.return_value.decode.return_value = "Answer: Use AES for encryption."

        question = "What encryption should I use?"
        response = self.consultant.generate_response(question)

        assert response == "Use AES for encryption."

    def test_post_process_response(self):
        response = "This is a short answer"
        processed_response = self.consultant.post_process_response(response)
        assert processed_response.endswith('.')
        assert len(processed_response.split()) >= 20

        short_response = "Short"
        processed_short_response = self.consultant.post_process_response(short_response)
        assert "Для получения более подробной информации" in processed_short_response

    def test_analyze_file(self):
        # Здесь мы можем протестировать метод analyze_file, если у нас есть реализация file_analyzer
        # Для этого теста мы можем использовать mock
        self.consultant.file_analyzer = MagicMock()
        self.consultant.file_analyzer.analyze_file.return_value = {"result": "success"}

        result = self.consultant.analyze_file("dummy_path.txt")
        assert result == {"result": "success"}

    def test_preprocess_analysis_data(self):
        analysis_data = {
            "file_path": "dummy_path.txt",
            "file_type": "text",
            "file_size": 1234,
            "file_hash": {"md5": "dummy_md5", "sha256": "dummy_sha256"},
            "virus_total_report": {"positives": 1, "total": 5, "scan_date": "2023-01-01"},
            "signature_check": {"yara_matches": ["rule1", "rule2"]},
            "risk_assessment": "Low"
        }
        processed_data = self.consultant._preprocess_analysis_data(analysis_data)
        assert "File Path: dummy_path.txt" in processed_data
        assert "File Type: text" in processed_data
        assert "File Size: 1234 bytes" in processed_data
        assert "Hashes: MD5=dummy_md5, SHA256=dummy_sha256" in processed_data
        assert "VirusTotal Positives: 1/5" in processed_data
        assert "YARA Matches: rule1, rule2" in processed_data
        assert "Overall Risk Assessment: Low" in processed_data
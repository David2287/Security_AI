import pytest
from unittest.mock import patch, MagicMock
from src.network_security_analyzer import EnhancedSecurityAnalyzer


class TestEnhancedSecurityAnalyzer:
    def setup_method(self):
        self.shodan_api_key = "dummy_shodan_api_key"
        self.virustotal_api_key = "dummy_virustotal_api_key"
        self.analyzer = EnhancedSecurityAnalyzer(shodan_api_key=self.shodan_api_key,
                                                 virustotal_api_key=self.virustotal_api_key)

    @patch('shodan.Shodan')
    def test_initialization_with_shodan(self, mock_shodan):
        analyzer = EnhancedSecurityAnalyzer(shodan_api_key=self.shodan_api_key)
        assert analyzer.shodan_client is not None
        mock_shodan.assert_called_once_with(self.shodan_api_key)

    @patch('shodan.Shodan')
    def test_network_reputation_check_with_shodan(self, mock_shodan):
        mock_shodan_instance = mock_shodan.return_value
        mock_shodan_instance.host.return_value = {
            'ports': [80, 443],
            'hostnames': ['example.com'],
            'vulns': ['CVE-2021-1234']
        }

        result = self.analyzer.network_reputation_check("8.8.8.8")
        assert result['ip'] == "8.8.8.8"
        assert result['is_malicious'] is True
        assert 'shodan' in result['reputation_sources']
        assert result['reputation_sources']['shodan']['open_ports'] == [80, 443]

    @patch('requests.get')
    def test_check_virustotal_reputation(self, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'detected_urls': [],
            'detected_communicating_samples': [],
            'undetected_communicating_samples': [],
        }
        mock_requests.return_value = mock_response

        result = self.analyzer._check_virustotal_reputation("8.8.8.8")
        assert result['detected_urls'] == 0
        assert result['malicious_reputation'] is False

    @patch('requests.get')
    def test_get_ip_geolocation(self, mock_requests):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'country_name': 'United States',
            'city': 'Mountain View',
            'region': 'California',
            'org': 'Google LLC',
            'timezone': 'America/Los_Angeles'
        }
        mock_requests.return_value = mock_response

        result = self.analyzer._get_ip_geolocation("8.8.8.8")
        assert result['country'] == 'United States'
        assert result['city'] == 'Mountain View'

    @patch('nmap.PortScanner')
    @patch('socket.gethostbyname')
    def test_vulnerability_scan(self, mock_gethostbyname, mock_nmap):
        mock_gethostbyname.return_value = "8.8.8.8"
        mock_nmap_instance = mock_nmap.return_value
        mock_nmap_instance.all_hosts.return_value = ["8.8.8.8"]
        mock_nmap_instance.scan.return_value = None
        mock_nmap_instance["8.8.8.8"].all_protocols.return_value = ['tcp']
        mock_nmap_instance["8.8.8.8"]['tcp'] = {
            80: {'name': 'http', 'product': 'Apache', 'version': '2.4', 'state': 'open'}}

        vulnerabilities = self.analyzer.vulnerability_scan("example.com")
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0]['service'] == 'http'

    @patch('ssl.get_server_certificate')
    @patch('OpenSSL.crypto.load_certificate')
    def test_check_ssl_vulnerabilities(self, mock_load_certificate, mock_get_server_certificate):
        mock_get_server_certificate.return_value = "dummy_cert"
        mock_load_certificate.return_value.get_notAfter.return_value = b'20230101000000Z'

        vulnerabilities = self.analyzer._check_ssl_vulnerabilities("8.8.8.8", 443)
        assert len(vulnerabilities) == 0  # Assuming the certificate is valid

    @patch('ssl.get_server_certificate')
    def test_check_ssl_vulnerabilities_error(self, mock_get_server_certificate):
        # Устанавливаем side_effect для генерации исключения
        mock_get_server_certificate.side_effect = Exception("SSL Error")

        vulnerabilities = self.analyzer._check_ssl_vulnerabilities("8.8.8.8", 443)

        # Проверяем, что метод возвращает информацию об ошибке
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]['type'] == 'SSL Error'
        assert vulnerabilities[0]['issue'] == "SSL Error"
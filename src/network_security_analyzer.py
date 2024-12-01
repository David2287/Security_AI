import requests
import shodan
import socket
import ssl
import nmap
from datetime import datetime
import OpenSSL.crypto
from typing import Dict, Any, List


class EnhancedSecurityAnalyzer:
    """
    A class that provides enhanced network security analysis.
    """

    def __init__(self, shodan_api_key: str = None, virustotal_api_key: str = None):
        """
        Initialize the EnhancedSecurityAnalyzer object.

        Args:
            shodan_api_key (str, optional): The Shodan API key.
            virustotal_api_key (str, optional): The VirusTotal API key.
        """
        self.shodan_api_key = shodan_api_key
        self.virustotal_api_key = virustotal_api_key

        # Initialize clients for external services
        self.shodan_client = shodan.Shodan(shodan_api_key) if shodan_api_key else None

    def network_reputation_check(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform a network reputation check.

        Args:
            ip_address (str): The IP address to check.

        Returns:
            Dict[str, Any]: A dictionary containing the check results.
        """
        reputation_result = {
            'ip': ip_address,
            'is_malicious': False,
            'reputation_sources': {}
        }

        try:
            # Check through Shodan
            if self.shodan_client:
                shodan_info = self.shodan_client.host(ip_address)
                reputation_result['reputation_sources']['shodan'] = {
                    'open_ports': shodan_info.get('ports', []),
                    'hostnames': shodan_info.get('hostnames', []),
                    'vulns': shodan_info.get('vulns', [])
                }

                # Evaluate reputation based on the number of vulnerabilities
                reputation_result['is_malicious'] = len(shodan_info.get('vulns', [])) > 0

            # Check through VirusTotal
            vt_result = self._check_virustotal_reputation(ip_address)
            reputation_result['reputation_sources']['virustotal'] = vt_result

            # Additional reputation sources
            reputation_result['reputation_sources']['geolocation'] = self._get_ip_geolocation(ip_address)

            return reputation_result

        except Exception as e:
            return {
                'error': str(e),
                'details': 'Failed to retrieve reputation information'
            }

    def _check_virustotal_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check the reputation of an IP address through VirusTotal.

        Args:
            ip_address (str): The IP address to check.

        Returns:
            Dict[str, Any]: A dictionary containing the check results.
        """
        if not self.virustotal_api_key:
            return {'error': 'VirusTotal API key not provided'}

        url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': self.virustotal_api_key, 'ip': ip_address}

        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                return {
                    'detected_urls': len(data.get('detected_urls', [])),
                    'detected_communicating_samples': len(data.get('detected_communicating_samples', [])),
                    'undetected_communicating_samples': len(data.get('undetected_communicating_samples', [])),
                    'malicious_reputation': data.get('detected_urls', []) > 0
                }
            return {'error': 'VirusTotal API request failed'}
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def _get_ip_geolocation(ip_address: str) -> Dict[str, Any]:
        """
        Get the geolocation of an IP address.

        Args:
            ip_address (str): The IP address to get geolocation for.

        Returns:
            Dict[str, Any]: A dictionary containing geolocation information.
        """
        try:
            response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
            return {
                'country': response.get('country_name'),
                'city': response.get('city'),
                'region': response.get('region'),
                'org': response.get('org'),
                'timezone': response.get('timezone')
            }
        except Exception:
            return {'error': 'Geolocation lookup failed'}

    def vulnerability_scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform a comprehensive vulnerability scan.

        Args:
            target (str): The target for scanning (IP or domain).

        Returns:
            List[Dict[str, Any]]: A list of discovered vulnerabilities.
        """
        global host
        vulnerabilities = []

        # Resolve domain if a domain is provided
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            ip_address = target

        # Port and service scanning
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments='-sV -sC -O')

        for host in nm.all_hosts():
            # Scan ports
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]

                    # Check SSL/TLS
                    if service.get('name') in ['https', 'ssl', 'tls']:
                        ssl_vulnerabilities = self._check_ssl_vulnerabilities(ip_address, port)
                        vulnerabilities.extend(ssl_vulnerabilities)

                    vulnerabilities.append({
                        'port': port,
                        'service': service.get('name', 'Unknown'),
                        'product': service.get('product', 'Unknown'),
                        'version': service.get('version', 'Unknown'),
                        'state': service.get('state', 'Unknown')
                    })

        # Check operating system vulnerabilities
        os_detection = nm[host].get('osmatch', [])
        for os in os_detection:
            vulnerabilities.append({
                'type': 'OS Vulnerability',
                'name': os.get('name'),
                'accuracy': os.get('accuracy')
            })

        return vulnerabilities

    @staticmethod
    def _check_ssl_vulnerabilities(host: str, port: int) -> List[Dict[str, Any]]:
        """
        Check for SSL/TLS vulnerabilities.

        Args:
            host (str): The host to check.
            port (int): The port to check.

        Returns:
            List[Dict[str, Any]]: A list of SSL vulnerabilities.
        """
        ssl_vulnerabilities = []

        try:
            # Check certificate
            cert = ssl.get_server_certificate((host, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            # Check expiration date
            expiration_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%S%z')
            if expiration_date < datetime.now():
                ssl_vulnerabilities.append({
                    'type': 'SSL Certificate',
                    'issue': 'Certificate has expired',
                    'expiration_date': expiration_date
                })

            # Check for weak ciphers
            weak_ciphers = ['RC4', '3DES', 'NULL', 'EXP']
            for cipher in weak_ciphers:
                if cipher in ssl.get_server_certificate((host, port)):
                    ssl_vulnerabilities.append({
                        'type': 'SSL Cipher',
                        'issue': f'Weak cipher {cipher} is supported'
                    })

        except Exception as e:
            ssl_vulnerabilities.append({
                'type': 'SSL Error',
                'issue': str(e)
            })

        return ssl_vulnerabilities


import os
import hashlib
import magic
import yara
import logging
import json
import aiohttp
from typing import Dict, Any, List, Optional


class FileSecurityAnalyzer:
    """
    Улучшенный класс для анализа безопасности файлов.
    Поддерживает типизацию, асинхронные вызовы, конфигурацию и расширяемость.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Инициализация анализатора безопасности.

        Args:
            config_path (Optional[str]): Путь к файлу конфигурации (JSON).
        """
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        self.config = self._load_config(config_path)

        # Настройка зависимостей
        self.virustotal_api_key = self.config.get("virustotal_api_key", "")
        self.yara_rules_path = self.config.get("yara_rules_path", None)
        self.yara_rules = self._load_yara_rules()

    def _setup_logging(self):
        """Настройка логирования."""
        handler = logging.FileHandler("file_security_analyzer.log")
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Загружает конфигурацию из JSON файла."""
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as file:
                    return json.load(file)
            except Exception as e:
                self.logger.error(f"Не удалось загрузить конфигурацию: {e}")
        return {}

    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Загружает правила YARA."""
        if self.yara_rules_path:
            try:
                return yara.compile(self.yara_rules_path)
            except Exception as e:
                self.logger.error(f"Не удалось загрузить правила YARA: {e}")
        return None

    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Асинхронный анализ файла.

        Args:
            file_path (str): Путь к файлу.

        Returns:
            Dict[str, Any]: Результаты анализа.
        """
        if not os.path.exists(file_path):
            return {"error": f"Файл не найден: {file_path}"}

        try:
            file_hashes = self.calculate_file_hashes(file_path)
            virus_total_report = await self.check_malware_database_async(file_hashes.get("sha256"))

            analysis_result = {
                "file_path": file_path,
                "file_type": self._detect_file_type(file_path),
                "file_size": os.path.getsize(file_path),
                "file_hash": file_hashes,
                "virus_total_report": virus_total_report,
                "signature_check": self.advanced_signature_check(file_path),
                "anomalies": self.detect_anomalous_patterns(file_path),
                "risk_assessment": None,
            }

            analysis_result["risk_assessment"] = self._assess_file_risk(analysis_result)
            return analysis_result

        except Exception as e:
            self.logger.error(f"Ошибка анализа файла: {e}")
            return {"error": str(e), "file_path": file_path}

    def _detect_file_type(self, file_path: str) -> str:
        """Определяет MIME-тип файла."""
        try:
            return magic.from_file(file_path, mime=True)
        except Exception as e:
            self.logger.warning(f"Не удалось определить тип файла: {e}")
            return "unknown"

    def calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Рассчитывает хэши файла."""
        hashes = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)

            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
        except IOError as e:
            self.logger.error(f"Ошибка вычисления хэшей: {e}")
            return {}

    async def check_malware_database_async(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Асинхронная проверка хэша в базе данных VirusTotal."""
        if not self.virustotal_api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"7087802d26df295bd85105126241d3eb2ea9014a76841d06d4958d000101b13f": self.virustotal_api_key}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        self.logger.warning(f"VirusTotal API вернул код {response.status}")
                        return None
        except Exception as e:
            self.logger.error(f"Ошибка запроса к VirusTotal: {e}")
            return None

    def advanced_signature_check(self, file_path: str) -> Dict[str, Any]:
        """Проверяет файл на соответствие правилам YARA."""
        results = {"yara_matches": [], "known_malware": False}

        if self.yara_rules:
            try:
                matches = self.yara_rules.match(file_path)
                results["yara_matches"] = [match.rule for match in matches]
                results["known_malware"] = len(matches) > 0
            except Exception as e:
                self.logger.error(f"Ошибка проверки YARA: {e}")

        return results

    def detect_anomalous_patterns(self, file_path: str) -> List[str]:
        """Обнаруживает аномальные паттерны в файле."""
        anomalies = []
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                if b"\x00" * 10 in content:
                    anomalies.append("Длинная последовательность нулевых байтов")
                if len(content) > 10 * 1024 * 1024:  # 10 MB
                    anomalies.append("Необычно большой файл")
        except Exception as e:
            self.logger.error(f"Ошибка обнаружения аномалий: {e}")

        return anomalies

    @staticmethod
    def _assess_file_risk(analysis_data: Dict[str, Any]) -> str:
        """Оценивает уровень риска файла."""
        risk_score = 0

        if analysis_data.get("virus_total_report", {}).get("positives", 0) > 5:
            risk_score += 3

        if analysis_data.get("signature_check", {}).get("known_malware", False):
            risk_score += 4

        if len(analysis_data.get("signature_check", {}).get("yara_matches", [])) > 0:
            risk_score += 2

        if analysis_data.get("file_type") in ["application/x-executable", "application/x-sharedlib"]:
            risk_score += 1

        if risk_score == 0:
            return "Low"
        elif risk_score <= 2:
            return "Medium"
        elif risk_score <= 4:
            return "High"
        else:
            return "Critical"

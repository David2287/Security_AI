from transformers import AutoModelForSequenceClassification, AutoTokenizer
from typing import Dict, Any, Coroutine
import re

class SecurityAIConsultant:
    """
    Класс, использующий предварительно обученную языковую модель для ответа на вопросы, связанные с безопасностью.
    """

    def __init__(self):
        """
        Инициализация объекта SecurityAIConsultant.
        """
        # Использование специализированной модели для кибербезопасности
        self.model_name: str = "gpt2"
        # Загрузка предварительно обученной модели, ориентированной на безопасность
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
        self.file_analyzer = ()

        # Параметры генерации
        self.generation_config: Dict[str, Any] = {
            'top_p': 0.92,  # Вероятностное обрезание для выборки токенов
            'top_k': 50,  # Ограничение по числу возможных токенов
            'temperature': 0.7,  # Регулировка случайности генерации
            'typical_p': 0.95,  # Типичный порог вероятности
            'min_p': 0.05,  # Минимальный порог вероятности
            'repetition_penalty': 1.2,  # Штраф за повторения
            'max_length': 150,  # Максимальная длина ответа
            'min_length': 50,  # Минимальная длина ответа
        }

        # Разрешённая лексика для профессиональных ответов
        self.allowed_vocabulary: set = {
            'hash', 'encryption', 'authentication', 'authorization', 'vulnerability',
            'breach', 'incident', 'malware', 'firewall', 'protocol', 'algorithm',
            'certificate', 'signature', 'log', 'audit', 'compliance', 'security',
            'verification', 'validation', 'integrity', 'confidentiality',
            'MD5', 'SHA1', 'SHA256', 'SHA512', 'checksum', 'digest', 'collision',
            'salt', 'hash table', 'rainbow table',
            'timestamp', 'event', 'alert', 'warning', 'error', 'critical',
            'source', 'destination', 'IP address', 'port', 'protocol',
            'implement', 'analyze', 'verify', 'investigate', 'recommend',
            'identify', 'resolve', 'mitigate', 'monitor', 'assess', 'evaluate', 'report', 'document', 'review', 'examine'
        }

    def filter_response(self, text: str) -> str:
        """
        Фильтрация ответа для использования только разрешённой лексики и поддержания профессионального тона.
        """
        words = text.split()
        filtered_words = [word for word in words if word.lower() in self.allowed_vocabulary]
        return ' '.join(filtered_words)

    @staticmethod
    def preprocess_question(question: str) -> str:
        """
        Предварительная обработка входного вопроса.
        """
        question = re.sub(r'[^\w\s]', '', question)  # Удаление всех символов, кроме букв и пробелов
        return question.lower().strip()  # Приведение к нижнему регистру и удаление лишних пробелов

    def generate_response(self, question: str) -> str:
        """
        Генерация ответа на заданный вопрос.
        """
        try:
            processed_question = self.preprocess_question(question)
            prompt = f"As a cybersecurity expert, answer the following question: {processed_question}\n\nAnswer:"
            inputs = self.tokenizer.encode(prompt, return_tensors='pt')

            outputs = self.model.generate(
                inputs,
                **self.generation_config,
                pad_token_id=self.tokenizer.eos_token_id,
            )

            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            response = response.split("Answer:")[1].strip()  # Извлечение фактического ответа
            response = self.post_process_response(response)

            return response

        except Exception as e:
            return f"Ошибка при генерации ответа: {str(e)}"

    @staticmethod
    def post_process_response(response: str) -> str:
        """
        Постобработка ответа для завершения предложений и добавления дополнительной информации при необходимости.
        """
        if not response.endswith(('.', '!', '?')):
            response += '.'  # Добавление точки, если предложение не закончено

        if len(response.split()) < 20:  # Если ответ слишком короткий
            response += " Для получения более подробной информации, пожалуйста, обратитесь к руководству по кибербезопасности или проконсультируйтесь с профессионалом в этой области."

        return response

    def analyze_file(self, file_path: str) -> Coroutine[Any, Any, dict[str, Any]]:
        """
        Делегируйте задачу анализа файлов FileSecurityAnalyzer.

        Аргументы:
            file_path (str): Путь к файлу для анализа.

        Возврат:
            Dict[str, Any]: результаты анализа FileSecurityAnalyzer.
        """
        return self.file_analyzer.analyze_file(file_path)

    @staticmethod
    def _preprocess_analysis_data(analysis_data: Dict[str, Any]) -> str:
        """
        Подготовьте данные анализа для генерации текста, преобразовав их в структурированную строку.

        Аргументы:
            анализ_данных (Dict[str, Any]): данные анализа файла.

        Возврат:
            str: предварительно обработанная строка, подходящая для ввода модели.
        """
        lines = [f"File Path: {analysis_data.get('file_path', 'Unknown')}",
                 f"File Type: {analysis_data.get('file_type', 'Unknown')}",
                 f"File Size: {analysis_data.get('file_size', 'Unknown')} bytes"]
        hashes = analysis_data.get('file_hash', {})
        lines.append(f"Hashes: MD5={hashes.get('md5', 'N/A')}, SHA256={hashes.get('sha256', 'N/A')}")

        if analysis_data.get('virus_total_report'):
            vt_report = analysis_data['virus_total_report']
            lines.append(f"VirusTotal Positives: {vt_report.get('positives', 0)}/{vt_report.get('total', 0)}")
            lines.append(f"VirusTotal Scan Date: {vt_report.get('scan_date', 'N/A')}")

        yara_matches = analysis_data.get('signature_check', {}).get('yara_matches', [])
        lines.append(f"YARA Matches: {', '.join(yara_matches) if yara_matches else 'None'}")

        lines.append(f"Overall Risk Assessment: {analysis_data.get('risk_assessment', 'Unknown')}")
        return "\n".join(lines)
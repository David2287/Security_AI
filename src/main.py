import os
import logging
import asyncio
import yaml
from typing import Dict, Any
from dotenv import load_dotenv

# Импорт собственных классов
from src.file_security_analyzer import FileSecurityAnalyzer
from src.security_ai_consultant import SecurityAIConsultant
from src.network_security_analyzer import EnhancedSecurityAnalyzer
from models.trained_models.model_trainer import ModelTrainer


class SecurityAIApplication:
    def __init__(self, config_path: str = '../config/config.yaml'):
        """
        Инициализация приложения с загрузкой конфигурации.

        Args:
            config_path (str): Путь к файлу конфигурации.
        """
        # Загрузка переменных окружения
        load_dotenv()

        # Загрузка конфигурации
        self.config = self._load_configuration(config_path)

        # Настройка логирования
        self._setup_logging()

        # Инициализация компонентов безопасности
        self.security_ai = SecurityAIConsultant(self.config)
        self.file_analyzer = FileSecurityAnalyzer(self.config)
        self.network_analyzer = EnhancedSecurityAnalyzer(self.config)
        self.model_trainer = ModelTrainer(self.config)

    def _load_configuration(self, config_path: str) -> Dict[str, Any]:
        """
        Загрузка конфигурации из YAML файла.

        Args:
            config_path (str): Путь к файлу конфигурации.

        Returns:
            Dict[str, Any]: Словарь с конфигурацией.
        """
        try:
            with open(config_path, 'r') as config_file:
                return yaml.safe_load(config_file)
        except FileNotFoundError:
            logging.error(f"Файл конфигурации не найден: {config_path}")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"Ошибка парсинга конфигурации: {e}")
            return {}

    def _setup_logging(self):
        """Настройка системы логирования."""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_file = log_config.get('file', '../logs/security_ai.log')

        # Создание директории для логов, если она не существует
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    async def interactive_mode(self):
        """
        Интерактивный режим работы приложения.
        """
        while True:
            try:
                command = input("\nВведите команду (help для справки): ").strip().lower()

                if command == 'exit':
                    break
                elif command == 'help':
                    self._print_help_menu()
                elif command == 'question':
                    await self._handle_question_command()
                elif command == 'file':
                    await self._handle_file_command()
                elif command == 'network':
                    await self._handle_network_command()
                elif command == 'train':
                    await self._handle_train_command()
                else:
                    print("Неизвестная команда. Введите 'help' для справки.")

            except KeyboardInterrupt:
                print("\nОперация прервана пользователем.")
                break
            except Exception as e:
                logging.error(f"Ошибка в интерактивном режиме: {e}")
                print(f"Произошла ошибка: {e}")

    def _print_help_menu(self):
        """Вывод справочного меню."""
        help_text = """
        Доступные команды:
        - question: Задать вопрос по безопасности
        - file:     Анализ файла
        - network:  Анализ сети
        - train:    Обучение модели
        - exit:     Выход из приложения
        """
        print(help_text)

    async def _handle_question_command(self):
        """Обработка команды вопроса."""
        question = input("Введите вопрос по безопасности: ")
        response = self.security_ai.generate_response(question)
        print(f"\n🤖 Ответ: {response}")

    async def _handle_file_command(self):
        """Обработка команды анализа файла."""
        file_path = input("Введите путь к файлу: ")
        if os.path.exists(file_path):
            analysis = await self.file_analyzer.analyze_file(file_path)
            print(f"\n📂 Результат анализа: {analysis}")
        else:
            print("Файл не найден.")

    async def _handle_network_command(self):
        """Обработка команды анализа сети."""
        target = input("Введите IP или домен: ")
        reputation = self.network_analyzer.network_reputation_check(target)
        vulnerabilities = self.network_analyzer.vulnerability_scan(target)

        print(f"\n🌐 Репутация сети: {reputation}")
        print(f"\n🚨 Уязвимости: {vulnerabilities}")

    async def _handle_train_command(self):
        """Обработка команды обучения модели."""
        dataset_path = input("Введите путь к набору данных: ")
        self.model_trainer.train_model(dataset_path)


def main():
    """Точка входа в приложение."""
    try:
        app = SecurityAIApplication()
        asyncio.run(app.interactive_mode())
    except Exception as e:
        logging.critical(f"Критическая ошибка: {e}", exc_info=True)
        print(f"Критическая ошибка: {e}")


if __name__ == "__main__":
    main()
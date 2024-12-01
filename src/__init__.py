"""
Инициализация пакета security_ai.

Этот модуль содержит основные классы и функции для анализа безопасности.
"""

from src.security_ai_consultant import SecurityAIConsultant
from src.file_security_analyzer import FileSecurityAnalyzer
from src.network_security_analyzer import EnhancedSecurityAnalyzer
from models.trained_models.model_trainer import ModelTrainer

__all__ = [
    'SecurityAIConsultant',
    'FileSecurityAnalyzer',
    'EnhancedSecurityAnalyzer',
    'ModelTrainer'
]

# Версия пакета
__version__ = "0.1.0"
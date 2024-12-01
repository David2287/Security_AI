import pytest
import pandas as pd
import numpy as np
import os
from datasets import Dataset
from transformers import RobertaForSequenceClassification, RobertaTokenizer

# Импортируем ваш класс ModelTrainer
from models.trained_models.model_trainer import ModelTrainer

@pytest.fixture
def sample_data_directory(tmpdir):
    """Создает временную директорию с тестовыми CSV-файлами"""
    # Создаем временную директорию
    data_dir = tmpdir.mkdir("test_data")

    # Создаем несколько тестовых CSV-файлов
    for i in range(2):
        # Создаем DataFrame со случайными данными
        df = pd.DataFrame({
            'payload_byte_1': np.random.randint(0, 255, 100),
            'payload_byte_2': np.random.randint(0, 255, 100),
            'ttl': np.random.randint(0, 255, 100),
            'total_len': np.random.randint(50, 1500, 100),
            'protocol': np.random.choice([0, 1, 2], 100),
            'label': np.random.choice([0, 1], 100)
        })

        # Сохраняем CSV
        file_path = os.path.join(data_dir, f'test_chunk_{i}.csv')
        df.to_csv(file_path, index=False)

    return str(data_dir)


@pytest.fixture
def model_trainer():
    """Создает экземпляр ModelTrainer для тестирования"""
    return ModelTrainer(model_name="roberta-base", num_labels=2)


def test_load_datasets_in_chunks(model_trainer, sample_data_directory):
    """Тестирование загрузки данных"""
    # Загружаем данные
    combined_df = model_trainer.load_datasets_in_chunks(sample_data_directory)

    # Проверяем, что DataFrame не пустой
    assert not combined_df.empty

    # Проверяем количество колонок
    expected_columns = ['payload_byte_1', 'payload_byte_2', 'ttl', 'total_len', 'protocol', 'label']
    assert all(col in combined_df.columns for col in expected_columns)


def test_prepare_data(model_trainer, sample_data_directory):
    """Тестирование подготовки данных"""
    # Загружаем данные
    combined_df = model_trainer.load_datasets_in_chunks(sample_data_directory)

    # Подготавливаем данные
    train_dataset, test_dataset = model_trainer.prepare_data(combined_df)

    # Проверяем типы возвращаемых объектов
    assert isinstance(train_dataset, Dataset)
    assert isinstance(test_dataset, Dataset)

    # Проверяем, что данные разделены корректно
    assert len(train_dataset) + len(test_dataset) == len(combined_df)
    assert abs(len(train_dataset) / len(combined_df) - 0.8) < 0.01  # Проверка соотношения 80/20


def test_tokenize_function(model_trainer):
    """Тестирование функции токенизации"""
    # Создаем тестовый пример
    test_examples = {
        'text': ['This is a test sentence', 'Another test sentence']
    }

    # Токенизируем
    tokenized = model_trainer.tokenize_function(test_examples)

    # Проверяем структуру токенизированных данных
    assert 'input_ids' in tokenized
    assert 'attention_mask' in tokenized
    assert len(tokenized['input_ids']) == len(test_examples['text'])


def test_model_initialization(model_trainer):
    """Тестирование инициализации модели"""
    # Проверяем, что модель и токенизатор созданы
    assert isinstance(model_trainer.model, RobertaForSequenceClassification)
    assert isinstance(model_trainer.tokenizer, RobertaTokenizer)

    # Проверяем количество меток
    assert model_trainer.model.config.num_labels == 2


def test_error_handling(model_trainer):
    """Тестирование обработки ошибок"""
    # Проверка обработки несуществующей директории
    with pytest.raises(ValueError):
        model_trainer.load_datasets_in_chunks("C:/Users/ADMIN/Documents/AI_Gen2/Data_Files_Chunks/")


# Интеграционный тест (может занять много времени)
def test_full_training_process(model_trainer, sample_data_directory):
    """Тестирование полного процесса обучения"""
    try:
        model_trainer.train_model(sample_data_directory)
    except Exception as e:
        pytest.fail(f"Обучение модели завершилось ошибкой: {str(e)}")


# Дополнительные параметризованные тесты
@pytest.mark.parametrize("model_name", [
    "roberta-base",
    "roberta-large"
])
def test_different_model_initializations(model_name):
    """Тестирование инициализации с разными моделями"""
    trainer = ModelTrainer(model_name=model_name, num_labels=2)
    assert isinstance(trainer.model, RobertaForSequenceClassification)
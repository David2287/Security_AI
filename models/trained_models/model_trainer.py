from transformers import RobertaForSequenceClassification, RobertaTokenizer, Trainer, TrainingArguments
from sklearn.model_selection import train_test_split
from datasets import Dataset
import pandas as pd
import os

class ModelTrainer:
    def __init__(self, model_name: str, num_labels: int):
        self.model_name = model_name
        self.num_labels = num_labels
        self.tokenizer = RobertaTokenizer.from_pretrained(model_name)
        self.model = RobertaForSequenceClassification.from_pretrained(model_name, num_labels=num_labels)
        directory_path = 'C:/Users/ADMIN/PycharmProjects/Security_AI/database'

    @staticmethod
    def load_datasets_in_chunks(directory_path: str, chunksize: int = 10 ** 6) -> pd.DataFrame:
        combined_df = pd.DataFrame()

        # Проверка существования директории
        if not os.path.exists(directory_path):
            raise ValueError(f"Directory not found: {directory_path}")

        # Проверка, что это директория
        if not os.path.isdir(directory_path):
            raise ValueError(f"Specified path is not a directory: {directory_path}")

        # Получаем список файлов
        files = os.listdir(directory_path)

        # Проверка наличия CSV-файлов
        csv_files = [f for f in files if f.endswith('.csv')]

        if not csv_files:
            raise ValueError(f"No CSV files found in directory: {directory_path}")

        # Загрузка файлов
        for file_name in csv_files:
            file_path = os.path.join(directory_path, file_name)
            try:
                for chunk in pd.read_csv(file_path, chunksize=chunksize):
                    combined_df = pd.concat([combined_df, chunk], ignore_index=True)
            except Exception as e:
                print(f"Error loading file {file_path}: {str(e)}")

        # Окончательная проверка данных
        if combined_df.empty:
            raise ValueError("No data could be loaded from the specified directory")

        return combined_df

    @staticmethod
    def prepare_data(df: pd.DataFrame) -> (Dataset, Dataset):
        # Преобразуем данные в текстовый формат для токенизация
        df['text'] = df.apply(lambda row: ' '.join(row[:-1].astype(str)), axis=1)  # Объединяем все признаки в одну строку
        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
        return Dataset.from_pandas(train_df), Dataset.from_pandas(test_df)

    def tokenize_function(self, examples):
        return self.tokenizer(examples["text"], padding="max_length", truncation=True)

    def train_model(self, directory_path: str):
        combined_df = self.load_datasets_in_chunks(directory_path)

        train_dataset, test_dataset = self.prepare_data(combined_df)

        train_dataset = train_dataset.map(self.tokenize_function, batched=True)
        test_dataset = test_dataset.map(self.tokenize_function, batched=True)

        train_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
        test_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])

        training_args = TrainingArguments(
            output_dir="./results",
            evaluation_strategy="epoch",
            learning_rate=2e-5,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            num_train_epochs=3,
            weight_decay=0.01,
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=test_dataset,
        )

        trainer.train()
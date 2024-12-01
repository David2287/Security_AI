# Security_AI
![Логотип проекта](ai-hub-svgrepo-com.svg)

## Цель работы:

Обеспечение информационной безопасности в компьютерной сети за счет использования алгоритмов машиного обучения.

## Содержание

- [Описание](#описание)
- [Основные библиотеки и технологии](#сновные библиотеки и технологии)
- [Данные базы](#данные базы)
- [Использование](#использование)
- [Примеры](#примеры)
- [Тестирование](#тестирование)
- [Установка](#установка)

## Описание

В данном проекте была разработана мини-модель искусственного интеллекта (ИИ), предназначенная для оказания помощи сотрудникам информационной безопасности. С учетом увеличения числа киберугроз, необходимость в эффективных инструментах анализа и реагирования становится все более актуальной. Проект направлен на автоматизацию процессов анализа сетевого трафика, проверки хешей файлов, анализа файлов на наличие вредоносного кода и выполнения сетевой безопасности.
Проект реализован на языке программирования Python, который является одним из самых популярных языков для разработки приложений в области машинного обучения и анализа данных благодаря своей простоте и мощным библиотекам.

## Основные библиотеки и технологии

*	**Transformers**: библиотека от Hugging Face, используемая для работы с предобученными языковыми моделями, такими как BERT и RoBERTa. Она позволяет легко интегрировать модели для обработки естественного языка (NLP).

*	**Pandas**: библиотека для работы с данными, предоставляющая удобные структуры данных и инструменты для анализа.

*	**Scikit-learn**: библиотека для машинного обучения, использующаяся для разделения данных на обучающие и тестовые наборы, а также для других операций, связанных с подготовкой данных.

* **Requests**: библиотека для выполнения HTTP-запросов, используемая для взаимодействия с внешними API, такими как VirusTotal и Shodan.

*	**Nmap**: инструмент для сетевого сканирования, используемый для анализа открытых портов и служб на целевых машинах.

*	**Shodan**: поисковая система для интернета вещей (IoT), позволяющая находить устройства и их уязвимости.

### В проекте используются два основных набора данных:

*	**Payload_data_CICIDS2017.csv**: этот набор данных содержит информацию о сетевом трафике, включая байты полезной нагрузки, TTL (Time to Live), общую длину пакета, протокол и метку (label), указывающую на тип трафика (например, нормальный или атакующий). Данные из этого набора используются для обучения модели, которая будет классифицировать сетевой трафик и выявлять потенциальные угрозы.


## Данные базы
![График данных базы](info/img.png)


## Использование

### Интерактивный режим:

После запуска приложения вы перейдете в интерактивный режим, где сможете вводить команды.
Для получения справки по доступным командам введите help.
Доступные команды:

#### 1) question: Задать вопрос по безопасности.
Вводите вопрос, связанный с безопасностью, и получайте ответ от AI-консультанта по безопасности.

#### 2) file: Выполнить анализ файла.
Укажите путь к файлу, и программа выполнит его анализ, предоставляя результаты, такие как наличие вредоносного кода или уязвимостей.

#### 3) network: Провести анализ сети.
Вводите IP-адрес или доменное имя для проверки репутации сети и сканирования на уязвимости. Программа предоставит информацию о репутации и возможных уязвимостях.

#### 4) train: Обучить модель на основе предоставленного набора данных.
Укажите путь к набору данных, и программа обучит модель на основе предоставленных данных. Это может быть полезно для улучшения алгоритмов безопасности.
(Изначально программа имеет набор данных для обучения и может предоставить определенный вид реализации данного набора данных)

#### 5) exit: Выйти из приложения.

## Тестирование 

В файлах программы уже имеются набор тестов для проверки работы классов и их функций

## Установка

Инструкции по установке проекта. Например:



# Security_AI(ENG)
![Логотип проекта](ai-hub-svgrepo-com.svg)

## The purpose of the work:

Ensuring information security in a computer network through the use of machine learning algorithms.

## Content

- [Description](#description)
- [Basic libraries and Technologies](#new libraries and technologies)
- [Database data](#database data)
- [Usage](#usage)
- [Examples](#examples)
- [Testing](#testing)
- [Installation](#installation)

## Description

In this project, a mini-model of artificial intelligence (AI) was developed, designed to assist information security personnel. With the increasing number of cyber threats, the need for effective analysis and response tools is becoming increasingly urgent. The project aims to automate the processes of analyzing network traffic, checking file hashes, analyzing files for malicious code and performing network security.
The project is implemented in the Python programming language, which is one of the most popular languages for developing applications in the field of machine learning and data analysis due to its simplicity and powerful libraries.

## Basic libraries and technologies

* **Transformers**: A library from Hugging Face used to work with pre-trained language models such as BERT and RoBERTa. It makes it easy to integrate natural language processing (NLP) models.

* **Pandas**: a library for working with data, providing convenient data structures and tools for analysis.

* **Scikit-learn**: A library for machine learning used to divide data into training and test sets, as well as for other operations related to data preparation.

* **Requests**: A library for executing HTTP requests used to interact with external APIs such as VirusTotal and Shodan.

* **Nmap**: A network scanning tool used to analyze open ports and services on target machines.

* **Shodan**: A search engine for the Internet of Things (IoT) that allows you to find devices and their vulnerabilities.

### The project uses two main data sets:

* **Payload_data_CICIDS2017.csv**: This dataset contains information about network traffic, including payload bytes, TTL (Time to Live), total packet length, protocol, and a label indicating the type of traffic (for example, normal or attacking). The data from this set is used to train a model that will classify network traffic and identify potential threats.


## Database
![График данных базы](info/img.png)


## Usage

### Interactive mode:

After launching the application, you will switch to interactive mode, where you can enter commands.
To get help on the available commands, type help.
Available commands:

####1) question: Ask a security question.
Enter a security-related question and get an answer from an AI security consultant.

####2) file: Perform file analysis.
Specify the path to the file, and the program will analyze it, providing results such as the presence of malicious code or vulnerabilities.

####3) network: Perform network analysis.
Enter an IP address or domain name to check the network's reputation and scan for vulnerabilities. The program will provide information about reputation and possible vulnerabilities.

####4) train: Train the model based on the provided dataset.
Specify the path to the dataset, and the program will train the model based on the provided data. This can be useful for improving security algorithms.
(Initially, the program has a data set for training and can provide a certain type of implementation of this data set)

####5) exit: Exit the application.

## Testing 

The program files already contain a set of tests to check the operation of classes and their functions
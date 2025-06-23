
# 🚀 Smart_Web

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://www.python.org/)  
[![Flask](https://img.shields.io/badge/Flask-3.1.0-lightgrey?logo=flask)](https://flask.palletsprojects.com/)  
[![License](https://img.shields.io/github/license/your-username/Smart_Web)](LICENSE)  
[![OpenAI](https://img.shields.io/badge/OpenAI-API-green?logo=openai)](https://platform.openai.com/)

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=30&pause=1000&color=FF5733&width=600&lines=Welcome+to+Smart_Web!;AI-powered+Task+Analysis;Built+with+Flask+and+OpenAI" alt="Typing SVG" />
</p>

> **Smart_Web** is a lightweight AI-powered task analysis platform built with Flask.  
> It leverages the DeepSeek model and OpenAI API to help users evaluate and gain insights into structured tasks.

---

## 📖 Project Overview

University life today is much more than just studying. Balancing internships, exams, research projects, competitions, clubs, hobbies, and travel brings both freedom and pressure. When tasks accumulate, confusion and overwhelm often follow.

To address this, our team developed a scalable task management system as part of a database project. Featuring AI-powered analysis, cloud-hosted database, and email reminders, it’s already proven effective in managing class notifications more smoothly than chaotic chat groups.

In this AI-driven age, embracing and mastering AI tools is key to unlocking our potential and navigating the future with confidence.


## ✨ Features

- 🧠 Analyze tasks using DeepSeek (1.5b) or OpenAI models  
- 🔐 User authentication & task management  
- 📊 Visualized result outputs  
- 💌 Email support (Flask-Mail integration)  
- 🌐 Lightweight local web interface  



## 📚 Table of Contents

- [Configuration](#-configuration)  
- [Installation](#-installation)  
- [Running the Code](#-running-the-code)  
- [Deployment](#-deployment)  
- [Troubleshooting](#-troubleshooting)  
- [Demonstration](#-demonstration)  
- [Contributing](#-contributing)  
- [License](#-license)  
- [Acknowledgments](#-acknowledgments)  



## 📦 Configuration

| Component         | Version  |
|-------------------|----------|
| Python            | 3.12     |
| deepseek-r1       | 1.5b     |
| Flask             | 3.1.0    |
| Flask-SQLAlchemy  | 3.1.1    |
| Flask-Mail        | 0.10.0   |
| OpenAI            | 1.64.0   |



## ⚙️ Installation

**Method 1: Using requirements.txt**

```bash
pip install -r requirements.txt
````

**Method 2: Install dependencies individually**

```bash
pip install Flask
pip install Flask-SQLAlchemy
pip install Flask-Mail
pip install openai
pip install python-dotenv
pip install psycopg2
pip install requests
```



## ▶️ Running the Code

Start the local server:

```bash
python app.py
```

Open your browser and visit:
[http://127.0.0.1:5000](http://127.0.0.1:5000)



## 🚀 Deployment

For production use, consider:

* Using a WSGI server such as **Gunicorn**:

  ```bash
  gunicorn app:app
  ```

* Securing environment variables (`SECRET_KEY`, `MAIL_PASSWORD`, etc.)

* Deploying with services like **Render**, **Railway**, **Fly.io**, or using **Docker**



## 🐞 Troubleshooting

### PostgreSQL GSSAPI Error

```text
sqlalchemy.exc.OperationalError: received invalid response to GSSAPI negotiation
```

Fix: disable GSSAPI encryption in your database URI

```python
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://<username>:<password>@<host>:5432/<dbname>?gssencmode=disable"
)
```



### iFlytek SSL API Error

```text
SSLError: EOF occurred in violation of protocol (_ssl.c:1010)
```

Try disabling VPN or switching to a stable network.



### Generic PostgreSQL Connection Issue

Test network connectivity via PowerShell:

```powershell
Test-NetConnection -ComputerName aws-0-ap-southeast-1.pooler.supabase.com -Port 5432
```

Make sure:

* Network access is allowed
* Password contains ASCII characters only
* VPNs or proxies are disabled if needed



## 🖼️ Demonstration

<img src="https://github.com/user-attachments/assets/aeb31598-9d86-4689-89a6-e1602719eaa6" width="600" alt="Demo1" />  
<img src="https://github.com/user-attachments/assets/821d15e5-3278-4da0-ba94-7a53f39658d2" width="600" alt="Demo2" />  
<img src="https://github.com/user-attachments/assets/211ebb59-37f3-409b-a44b-963b8558b4ee" width="600" alt="Demo3" />  
<img src="https://github.com/user-attachments/assets/6793254c-5bb0-4432-9d51-89676aed0443" width="600" alt="Demo4" />  





## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to the branch (`git push origin feature-name`)
5. Open a Pull Request



## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

* [DeepSeek](https://github.com/deepseek-ai)
* [OpenAI](https://openai.com)
* [Flask](https://flask.palletsprojects.com/)
* [Supabase](https://supabase.com)
* [iFlytek Spark](https://xinghuo.xfyun.cn/)

**Special thanks to my teammates for their collaboration and support:**

* Yue Guo
* Bo Yang

Without your effort, this project would not have been possible! 💪



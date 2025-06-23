
# 🚀 Smart_Web

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.0-lightgrey?logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/github/license/your-username/Smart_Web)](LICENSE)
[![OpenAI](https://img.shields.io/badge/OpenAI-API-green?logo=openai)](https://platform.openai.com/)

> **Smart_Web** is a lightweight AI-powered task analysis platform built with Flask.  
> It leverages the DeepSeek model and OpenAI API to help users evaluate and gain insights into structured tasks.

---

## ✨ Features

- 🧠 Analyze tasks using DeepSeek (1.5b) or OpenAI models
- 🔐 User authentication & task management
- 📊 Visualized result outputs
- 💌 Email support (Flask-Mail integration)
- 🌐 Lightweight local web interface

---

## 📚 Table of Contents

- [📦 Configuration](#-configuration)
- [⚙️ Installation](#️-installation)
- [▶️ Running the Code](#️-running-the-code)
- [🚀 Deployment](#-deployment)
- [🐞 Troubleshooting](#-troubleshooting)
- [🖼️ Demonstration](#️-demonstration)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

---

## 📦 Configuration

- Python 3.12
- `deepseek-r1:1.5b`
- Flask 3.1.0
- Flask-SQLAlchemy 3.1.1
- Flask-Mail 0.10.0
- OpenAI 1.64.0

---

## ⚙️ Installation

Install dependencies:

```bash
pip install Flask
pip install Flask-SQLAlchemy
pip install Flask-Mail
pip install openai
````

---

## ▶️ Running the Code

Start the server locally:

```bash
python app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## 🚀 Deployment

For production environments, you may consider:

* Using a WSGI server like **Gunicorn**:

  ```bash
  gunicorn app:app
  ```
* Setting environment variables securely (`SECRET_KEY`, `MAIL_PASSWORD`, etc.)
* Deploying via services like **Render**, **Railway**, **Fly.io**, or **Docker**

---

## 🐞 Troubleshooting

### ❗ PostgreSQL GSSAPI Error

```bash
sqlalchemy.exc.OperationalError: received invalid response to GSSAPI negotiation
```

✅ Add this config in `app.py`:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://<username>:<password>@<host>:5432/<dbname>?gssencmode=disable"
)
```

---

### ❗ iFlytek SSL API Error

```bash
SSLError: EOF occurred in violation of protocol (_ssl.c:1010)
```

✅ Try disabling VPN or switching to a stable network.

---

### ❗ Generic PostgreSQL Connection Error

✅ Check network using PowerShell:

```powershell
Test-NetConnection -ComputerName aws-0-ap-southeast-1.pooler.supabase.com -Port 5432
```

Ensure:

* Network access is open
* Password uses only ASCII characters
* VPNs and proxies are disabled if needed

---

## 🖼️ Demonstration

<img src="https://github.com/user-attachments/assets/aeb31598-9d86-4689-89a6-e1602719eaa6" width="600" />
<img src="https://github.com/user-attachments/assets/821d15e5-3278-4da0-ba94-7a53f39658d2" width="600" />
<img src="https://github.com/user-attachments/assets/211ebb59-37f3-409b-a44b-963b8558b4ee" width="600" />
<img src="https://github.com/user-attachments/assets/6793254c-5bb0-4432-9d51-89676aed0443" width="600" />

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to the branch (`git push origin feature-name`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

* [DeepSeek](https://github.com/deepseek-ai)
* [OpenAI](https://openai.com)
* [Flask](https://flask.palletsprojects.com/)
* [Supabase](https://supabase.com)
* [iFlytek Spark](https://xinghuo.xfyun.cn/)

```


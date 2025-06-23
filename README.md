# Smart_Web

## _This is a convenient website, which helping us analysis tasks recorded using AI (deepseek)_


## Contents
- [Configuration](#Configuration)
- [Installation](#Installation)
- [Code-Running](#Code-Running)
- [Troubleshooting](#Troubleshooting)

## Demonstrate
![image](https://github.com/user-attachments/assets/aeb31598-9d86-4689-89a6-e1602719eaa6)

![image](https://github.com/user-attachments/assets/821d15e5-3278-4da0-ba94-7a53f39658d2)

![image](https://github.com/user-attachments/assets/211ebb59-37f3-409b-a44b-963b8558b4ee)

![image](https://github.com/user-attachments/assets/6793254c-5bb0-4432-9d51-89676aed0443)


## Configuration
* python 3.12
* deepseek-r1:1.5b
* Flask 3.1.0
* Flask-SQLAlchemy 3.1.1
* Flask-Mail 0.10.0
* openai 1.64.0


## Installation
* Download dependencies


    pip install Flask
  
    pip install Flask-SQLAchemy
    
    pip install Flask-Mail
    
    pip install openai
  

## Code-Running
Run the program & visit <http://127.0.0a.1:5000/>


    python app.py


## Troubleshooting
* **error**: sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) connection to server at "aws-0-ap-southeast-1.pooler.supabase.com" (52.77.146.31), port 5432 failed: received invalid response to GSSAPI negotiation: S  
  **method**: add following config in app.py then you solve this problem successfully!

```
    app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://postgres.fopmwefhfaqniynceqio:lon2mONTsm0oFBY8"
    "@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres"
    "?gssencmode=disable"
)
```
* **error**: when using the function of analysing by AI， you meet the error of “Error during analysis: 调用讯飞星火 X1 HTTP API 失败: HTTPSConnectionPool(host='spark-api-open.xf-yun.com', port=443): Max retries exceeded with url: /v2/chat/completions (Caused by SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1010)'))) ”.  
  **method**: <mark>close the VPN or switch other stable networks<mark>
  
* **error**: sqlalchemy.exc.OperationalError: (psycopg2.OperationalError)  *Simply an error*  
  **method**: Check if your host can ping the database.Run the test.py or use the terminal command `Test-NetConnection -ComputerName aws-0-ap-southeast-1.pooler.supabase.com -Port 5432` to check.If can, check if the URL in the code is correct, you can change the database password to only contain ASCII characters and then reconfigure.If not, try switching networks, such as changing to a personal hotspot, while disabling VPNs and other proxies.

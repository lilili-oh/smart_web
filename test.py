import os
import psycopg2

# 假设你的 .env 文件在当前目录，并使用 python-dotenv 加载
# 如果你没有安装 python-dotenv，可以 pip install python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
    db_url = os.getenv('DATABASE_URL')
    if not db_url:
        raise ValueError("DATABASE_URL not found in .env or environment variables.")
except ImportError:
    print("python-dotenv not installed. Trying to get DATABASE_URL directly from os.environ.")
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("DATABASE_URL environment variable not set. Please set it or ensure your .env file is loaded.")
        # 如果没有通过环境变量设置，直接写死测试用
        # db_url = 'postgresql://postgres:OaMa01plU6yV01Sh@db.fopmwefhfaqniynceqio.supabase.co:5432/postgres?client_encoding=UTF8'


print(f"尝试连接的 DATABASE_URL: {db_url}")

# **核心诊断：打印连接字符串的字节表示**
# 这会显示连接字符串中是否存在非 UTF-8 编码的字节
print(f"DATABASE_URL 的字节表示: {db_url.encode('utf-8', errors='backslashreplace')}")

conn = None # 初始化 conn 变量，防止在 finally 块中出现 NameError

try:
    # **这里是关键的修复：实际建立数据库连接**
    conn = psycopg2.connect(db_url)
    print("成功连接到 PostgreSQL 数据库！")

    # 如果连接成功，可以尝试执行一些简单的查询
    cur = conn.cursor()
    cur.execute("SELECT version();")
    print(f"PostgreSQL 版本: {cur.fetchone()[0]}")
    cur.close()

except psycopg2.OperationalError as e:
    print(f"PostgreSQL 操作错误: {e}")
    # 如果错误依然是 UnicodeDecodeError，请检查上面的字节输出
except UnicodeDecodeError as e:
    print(f"捕获到 UnicodeDecodeError: {e}")
    print("这表明连接字符串或数据库在解码时仍有问题。")
    print("请仔细检查 DATABASE_URL 的字节表示，查找任何异常的 '\\x..' 序列。")
except Exception as e:
    print(f"发生未知错误: {e}")
    print(f"错误类型: {type(e)}")
finally:
    # 确保无论连接是否成功，都尝试关闭连接（如果它被定义了）
    if conn:
        conn.close()
        print("连接已关闭。")
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import re
import requests
import json
import logging
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['XFYUN_SPARK_X1_API_KEY'] = os.environ.get('XFYUN_SPARK_X1_API_KEY')
app.config['XFYUN_SPARK_X1_HTTP_URL'] = "https://spark-api-open.xf-yun.com/v2/chat/completions" # X1 的固定 URL
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,       # 连接池中保持的连接数，可以根据并发用户量调整
    'max_overflow': 20,    # 允许超过 pool_size 的额外连接数，处理短期高峰
    'pool_recycle': 3600,  # 连接在池中保持打开的最大秒数（1小时），防止数据库超时断开
    'pool_pre_ping': True, # 每次从池中取出连接时，先测试其可用性
    'pool_timeout': 30     # 获取连接的超时时间（秒）
}
print(f"DEBUG: DATABASE_URL being used: {app.config['SQLALCHEMY_DATABASE_URI']}")

# 调试信息打印
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
# logger.info(f"DEBUG: Loaded XFYUN_SPARK_X1_API_KEY: {app.config['XFYUN_SPARK_X1_API_KEY']}")

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Models

class SparkX1Client:
    def __init__(self, api_key, http_url):
        # 注意：X1 的 API key 已经是 'Bearer YOUR_KEY' 这种格式
        self.API_KEY = api_key
        self.HTTP_URL = http_url

    # 类似 X1_http.py 中的 get_answer
    def get_spark_response(self, prompt_text):
        full_response = ""  # 存储返回结果
        is_first_content = True  # 首帧标识

        try:
            # 初始化请求体
            headers = {
                'Authorization': self.API_KEY, # X1 的鉴权方式
                'content-type': "application/json"
            }
            body = {
                "model": "x1",  # X1 模型名
                "user": "flask_app_user", # 可以是任意用户标识
                "messages": [{"role": "user", "content": prompt_text}], #
                "stream": True, # 流式响应
                # "tools": [ # 如果需要工具调用，可以保留，否则移除
                #     {
                #         "type": "web_search",
                #         "web_search": {
                #             "enable": True,
                #             "search_mode":"deep"
                #         }
                #     }
                # ]
            }

            response = requests.post(url=self.HTTP_URL, json=body, headers=headers, stream=True, timeout=90) # 增加超时时间
            response.raise_for_status() # 检查 HTTP 错误状态码

            for chunks in response.iter_lines(): #
                # 打印返回的每帧内容 (仅用于调试，生产环境可移除)
                # print(chunks)
                if chunks and b'[DONE]' not in chunks: #
                    try:
                        # 讯飞星火流式响应的格式是 'data: {json}'
                        data_line = chunks.decode('utf-8').strip()
                        if data_line.startswith('data:'): #
                            data_org = data_line[5:].strip() #
                            chunk = json.loads(data_org) #
                            
                            # 检查 API 响应的错误码，X1_http.py 示例中没有，但一般建议加
                            if 'code' in chunk.get('header', {}) and chunk['header']['code'] != 0:
                                error_msg = f"Spark X1 API 调用失败，错误码: {chunk['header']['code']}, 详情: {chunk['header']['message']}"
                                logger.error(error_msg)
                                return json.dumps({"error": error_msg})

                            text = chunk['choices'][0]['delta'] #

                            # 判断思维链状态并输出 (X1_http.py 中的逻辑)
                            if 'reasoning_content' in text and text['reasoning_content']: #
                                logger.info(f"思维链内容: {text['reasoning_content']}")
                                # 如果你想把思维链内容也保存到结果，可以加到 full_response
                                # full_response += text['reasoning_content']

                            # 判断最终结果状态并输出 (X1_http.py 中的逻辑)
                            if 'content' in text and text['content']: #
                                content = text['content'] #
                                if is_first_content: #
                                    logger.info("\n*******************以上为思维链内容，模型回复内容如下********************\n")
                                    is_first_content = False #
                                full_response += content #
                    except json.JSONDecodeError as e:
                        logger.error(f"解析讯飞星火流式响应时 JSON 错误: {e}, 原始行: {chunks.decode('utf-8')}")
                        return json.dumps({"error": f"解析流式响应 JSON 错误: {str(e)}"})
                    except KeyError as e:
                        logger.error(f"讯飞星火响应结构不符合预期: {e}, 原始 chunk: {chunk}")
                        return json.dumps({"error": f"讯飞星火响应结构错误: {str(e)}"})
            return full_response

        except requests.exceptions.RequestException as e:
            logger.error(f"调用讯飞星火 X1 HTTP API 失败: {e}")
            return json.dumps({"error": f"调用讯飞星火 X1 HTTP API 失败: {str(e)}"})
        except Exception as e:
            logger.error(f"调用讯飞星火 X1 时发生未知异常: {e}")
            return json.dumps({"error": f"调用讯飞星火 X1 时发生未知异常: {str(e)}"})

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(20), nullable=True)  # Changed to nullable
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=True)  # Changed to nullable
    data = db.relationship('UserData',back_populates='user')
    is_admin = db.Column(db.Boolean, default=False)
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


class UserData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    deadline = db.Column(db.DateTime, nullable=True)  # New field
    ai_analysis = db.Column(db.Text, nullable=True)   # New field
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User',back_populates='data')

    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=True)  # 关联团队
    team = db.relationship('Team', backref='tasks')
    team_editable = db.Column(db.Boolean, default=False)

    # 新增字段：表示任务是否完成，默认为 False
    is_completed = db.Column(db.Boolean, default=False, nullable=False)
    # 新增字段：任务完成时间，默认为 None
    completed_at = db.Column(db.DateTime, nullable=True)

    def get_time_remaining(self):
        if not self.deadline:
            return None
        now = datetime.utcnow()
        if now > self.deadline:
            return "Overdue"
        time_left = self.deadline - now
        days = time_left.days
        hours = time_left.seconds // 3600
        minutes = (time_left.seconds % 3600) // 60
        return f"{days}d {hours}h {minutes}m"

    def analyze_with_ai(self):
        api_key = app.config['XFYUN_SPARK_X1_API_KEY']
        spark_http_url = app.config['XFYUN_SPARK_X1_HTTP_URL']

        if not all([api_key, spark_http_url]):
            error_msg = "讯飞星火 X1 API 凭据或 URL 未配置。请检查 .env 文件和 app.py 配置。"
            logger.error(error_msg)
            return {"error": error_msg}
        
        try:
            logger.info(f"Starting AI analysis for task: {self.title} using Spark X1 HTTP API")

            # 构建提示词
            prompt = f"""
            请分析以下任务并提供详细建议，请以JSON格式返回：

            任务标题: {self.title}
            任务描述: {self.content}
            截止日期: {self.deadline.strftime('%Y-%m-%d %H:%M') if self.deadline else '未设置'}

            请提供以下分析，并以JSON格式返回：
            {{
                "complexity": "任务复杂度（简单/中等/复杂）",
                "steps": ["步骤1", "步骤2", "步骤3"],
                "estimated_time": "预计所需时间",
                "priority": "优先级（高/中/低）",
                "challenges": ["挑战1", "挑战2"],
                "solutions": ["解决方案1", "解决方案2"]
            }}
            注意：请直接返回JSON格式的结果，不要包含其他内容。
            """

            # 创建讯飞星火 X1 HTTP 客户端实例
            spark_client = SparkX1Client(api_key, spark_http_url)

            # 获取星火大模型的响应
            response_str = spark_client.get_spark_response(prompt)

            logger.info(f"Spark X1 原始响应: {response_str}")

            if not response_str:
                error_msg = "讯飞星火 X1 没有返回任何输出"
                logger.error(error_msg)
                return {"error": error_msg}

            try:
                # 尝试从输出中提取 JSON 部分 (保留原有逻辑，以防模型输出包含额外文本)
                json_match = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', response_str)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    json_match = re.search(r'(\{(?:[^{}]|(?:\{[^{}]*\}))*\})', response_str)
                    if json_match:
                        json_str = json_match.group(1)
                    else:
                        cleaned_output = re.sub(r'^.*?(\{|\[)', r'\1', response_str, flags=re.DOTALL)
                        cleaned_output = re.sub(r'(\}|\]).*$', r'\1', cleaned_output, flags=re.DOTALL)
                        if cleaned_output and (cleaned_output.startswith('{') or cleaned_output.startswith('[')):
                            json_str = cleaned_output
                        else:
                            raise json.JSONDecodeError("No valid JSON found in output", response_str, 0)

                json_str = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', json_str)

                analysis_json = json.loads(json_str)
                self.ai_analysis = json.dumps(analysis_json, ensure_ascii=False)
                db.session.commit()
                logger.info("AI analysis saved to database")
                return analysis_json
            except json.JSONDecodeError as e:
                error_msg = f"无法解析讯飞星火 X1 输出为 JSON: {str(e)}"
                logger.error(error_msg)
                logger.error(f"原始输出: {response_str}")
                self.ai_analysis = response_str
                db.session.commit()
                logger.info("AI analysis saved as text to database")
                return {"error": error_msg}

        except Exception as e:
            error_msg = f"AI 分析过程出错: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
        
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    members = db.relationship('User', secondary='team_members', backref='teams')
    password = db.Column(db.String(6), nullable=False)  # 6位数字密码，必填

class TeamMember(db.Model):
    __tablename__ = 'team_members'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), primary_key=True)
# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Input validation
        if not username or not email or not password:
            flash('所有字段均为必填字段。', 'danger')
            return render_template('register.html')

        if not validate_password(password):
            flash('密码必须至少包含8个字符，并且包含大写字母、小写字母和数字。', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('密码不匹配。', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('用户已存在。', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('电子邮件已被注册。', 'danger')
            return render_template('register.html')

        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('注册成功！请登录。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('注册发生出错。', 'danger')
            logging.error(f"注册时错误: {e}")
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)
            flash('登录成功！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码无效。', 'danger')

    return render_template('login.html')


#团队概况功能
@app.route('/summary')
@login_required
def summary():
    # Query all teams and eager load their members and tasks
    teams = Team.query.options(db.joinedload(Team.members), db.joinedload(Team.tasks)).all()
    return render_template('summary.html', teams=teams) # 渲染队伍页面


# 组队功能
@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if request.method == 'POST':
        team_name = request.form.get('team_name')
        description = request.form.get('description')
        password = request.form.get('password')  # 获取密码字段 ✅

        if not password or not password.isdigit() or len(password) != 6:
            flash('团队密码必须是6位数字。', 'danger')
            return render_template('team.html')

        # 创建新队伍
        team = Team(name=team_name, description=description, password=password)  # ✅ 增加密码字段
        db.session.add(team)
        db.session.commit()

        flash('团队创建成功！', 'success')
        return redirect(url_for('profile'))

    return render_template('team.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('您已登出。', 'info')
    return redirect(url_for('home'))

# 加入队伍功能
@app.route('/join_team/<int:team_id>', methods=['GET', 'POST'])
@login_required
def join_team(team_id):
    user = User.query.get_or_404(session['user_id'])
    team = Team.query.get_or_404(team_id)

    if team in user.teams:
        flash(f'你已经加入了团队 "{team.name}"。', 'info')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        input_password = request.form.get('password')
        if input_password != team.password:
            flash('密码错误，无法加入该团队。', 'danger')
            return redirect(url_for('join_team', team_id=team_id))

        user.teams.append(team)
        db.session.commit()
        flash(f'成功加入团队 "{team.name}"！', 'success')
        return redirect(url_for('profile'))

    return render_template('join_team.html', team=team)


# 离开队伍功能
@app.route('/leave_team/<int:team_id>')
@login_required
def leave_team(team_id):
    user = User.query.get_or_404(session['user_id'])
    team = Team.query.get_or_404(team_id)

    if team in user.teams:
        user.teams.remove(team)
        try:
            db.session.commit()
            flash(f'您已离开团队：{team.name}.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('离开队伍出错。', 'danger')
    else:
        flash('您不是此团队的成员。', 'warning')

    return redirect(url_for('profile'))

# master page
@app.route('/master', methods=['GET', 'POST'])
@admin_required
def master():
    users = User.query.all()
    return render_template('master.html', users=users)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash('请先登录！', 'danger')
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)

    # 1. 查询用户自己的任务
    # 这里的个人任务是指那些没有分配给任何团队，或者分配给了团队但 team_editable 为 False 的任务
    # 这样可以避免与团队任务重复
    user_own_tasks = UserData.query.filter(
        and_(
            UserData.user_id == user_id,
            or_(
                UserData.team_id == None,  # 个人任务，没有团队ID
                UserData.team_editable == False # 或者有团队ID，但不可由团队成员编辑（仍是个人任务性质）
            )
        )
    ).order_by(UserData.created_at.desc()).all()
    logger.info(f"User {user.username} (ID: {user_id}) has {len(user_own_tasks)} personal tasks.")

    # 2. 查询用户所属团队的任务（如果团队任务可编辑，并且用户是该团队成员）
    user_teams = user.teams # 获取用户所属的所有团队
    team_tasks = []
    
    if user_teams:
        team_ids = [team.id for team in user_teams]
        # 查找属于这些团队且 team_editable 为 True 的任务
        tasks_from_teams = UserData.query.filter(
            and_(
                UserData.team_id.in_(team_ids),
                UserData.team_editable == True
            )
        ).order_by(UserData.created_at.desc()).all()
        team_tasks.extend(tasks_from_teams)
    
    logger.info(f"User {user.username} (ID: {user_id}) is in {len(user_teams)} teams, and found {len(team_tasks)} editable team tasks.")

    # 3. 合并任务列表并去重
    # 使用集合进行去重，确保每个任务只出现一次
    all_tasks_dict = {}
    for task in user_own_tasks:
        all_tasks_dict[task.id] = task
    for task in team_tasks:
        all_tasks_dict[task.id] = task # 如果有重复，后面的会覆盖前面的，但通常团队任务和个人任务通过上述筛选是互斥的

    # 将字典的值转换为列表并按创建时间倒序排序
    user_data = sorted(all_tasks_dict.values(), key=lambda t: t.created_at, reverse=True)

    return render_template('dashboard.html', 
                           user=user, 
                           user_data=user_data,
                           user_teams=user_teams, 
                           team_tasks=team_tasks # 实际上dashboard.html只迭代 user_data
                          )

@app.route('/add_data', methods=['GET', 'POST'])
@login_required
def add_data():
    user = User.query.get_or_404(session['user_id'])
    teams = Team.query.all()

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        deadline_str = request.form.get('deadline')
        team_id = request.form.get('team_id')
        team_editable = 'team_editable' in request.form if team_id else False

        if not title or not content:
            flash('标题和内容为必填项。', 'danger')
            return render_template('add_data.html' ,user=user, teams=teams)

        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('截止时间格式无效。', 'danger')
                return render_template('add_data.html' ,user=user, teams=teams)

        new_data = UserData(
            title=title,
            content=content,
            deadline=deadline,
            user_id=session['user_id'],
            team_id=int(team_id) if team_id else None,
            team_editable=team_editable
        )

        try:
            db.session.add(new_data)
            db.session.commit()
            flash('任务添加成功！', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('添加任务时出错。', 'danger')
            return render_template('add_data.html' ,user=user, teams=teams)

    return render_template('add_data.html' ,user=user, teams=teams)

@app.route('/edit_data/<int:data_id>', methods=['GET', 'POST'])
@login_required
def edit_data(data_id):
    user = User.query.get_or_404(session['user_id'])
    data = UserData.query.get_or_404(data_id)
    teams = user.teams
    team_id = request.form.get('team_id')
    team_editable = bool(request.form.get('team_editable'))
    
    is_author = data.user_id == user.id
    is_team_member = data.team_id and any(team.id == data.team_id for team in user.teams)
    if not is_author and not (data.team_editable and is_team_member):
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        deadline_str = request.form.get('deadline')

        if not title or not content:
            flash('标题和内容为必填项。', 'danger')
            return render_template('edit_data.html', data=data,user=user, teams=teams)

        # Convert deadline string to datetime if provided
        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('截止日期格式无效。', 'danger')
                return render_template('edit_data.html', data=data,user=user, teams=teams)

        
        # 设置团队归属（仅允许用户加入的队伍）
        if team_id:
            team = Team.query.get(int(team_id))
            if team and team in user.teams:
                data.team = team
            else:
                data.team = None
        else:
            data.team = None

        # 设置是否允许团队编辑
        data.team_editable = team_editable

        data.title = title
        data.content = content
        data.deadline = deadline
        data.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            flash('任务更新成功！', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('更新任务时出错。', 'danger')
            return render_template('edit_data.html', data=data,user=user, teams=teams)

    return render_template('edit_data.html', data=data,user=user, teams=teams)

# add || update user_data
@app.route('/update_user/<int:user_id>', methods=['POST'])
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    user.username = request.form.get('username')
    user.email = request.form.get('email')
    password = request.form.get('password')

    if password:
        user.password = generate_password_hash(password)

    try:
        db.session.commit()
        flash('用户更新成功！', 'success')
    except Exception:
        db.session.rollback()
        flash('用户更新失败。', 'danger')

    return redirect(url_for('master'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('已成功删除用户！', 'success')
    except Exception:
        db.session.rollback()
        flash('删除用户失败。', 'danger')

    return redirect(url_for('master'))

@app.route('/delete_data/<int:data_id>')
@login_required
def delete_data(data_id):
    user = User.query.get_or_404(session['user_id'])
    data = UserData.query.get_or_404(data_id)
    
    is_author = data.user_id == user.id
    is_team_member = data.team_id and any(team.id == data.team_id for team in user.teams)
    if not is_author and not (data.team_editable and is_team_member):
        abort(403)

    try:
        db.session.delete(data)
        db.session.commit()
        flash('任务删除成功！', 'success')
    except Exception as e:
        db.session.rollback()
        flash('删除任务时出错。', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get_or_404(session['user_id'])
    teams = Team.query.all()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        selected_team_id = request.form.get('team_id')
        file = request.files.get('profile_picture')

        updated = False  # 追踪是否有改动

        # 修改 bio
        if bio != user.bio:
            user.bio = bio
            updated = True

        # 上传头像
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            user.profile_picture = filename
            updated = True

        # 加入队伍
        if selected_team_id:
            try:
                selected_team_id = int(selected_team_id)
                team = Team.query.get(selected_team_id)
                input_password = request.form.get('team_password', '')

                if team and team not in user.teams:
                    if input_password == team.password:
                        user.teams.append(team)
                        flash(f'成功加入团队：{team.name}', 'success')
                        updated = True
                    else:
                        flash('团队密码错误，无法加入。', 'danger')
                elif team in user.teams:
                    flash(f'你已经是团队“{team.name}”的成员。', 'info')
            except ValueError:
                flash('无效的团队选择。', 'danger')
        else:
            if 'team_id' in request.form:  # 用户点击了 Join 但没选队伍
                flash('请选择一个团队并输入密码以加入。', 'warning')

        # 提交变更
        try:
            db.session.commit()
            flash('个人信息更新成功！', 'success')
        except Exception as e:
            db.session.rollback()
            flash('个人信息更新失败。', 'danger')

        return redirect(url_for('profile'))

    return render_template('profile.html', user=user, teams=teams)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg = Message('Password Reset Request',
                         recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request then simply ignore this email.
'''
            mail.send(msg)
            
        flash('If an account exists with that email, you will receive a password reset link.', 'info')
        return redirect(url_for('login'))
        
    return render_template('reset_password_request.html')




@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not validate_password(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.', 'danger')
            return render_template('reset_password.html')
            
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')
            
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password)
        
        try:
            db.session.commit()
            flash('Your password has been reset!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while resetting your password.', 'danger')
            
    return render_template('reset_password.html')

@app.route('/analyze_task/<int:data_id>', methods=['POST'])
@login_required
def analyze_task(data_id):
    data = UserData.query.get_or_404(data_id)
    user = User.query.get_or_404(session['user_id'])
    
    if data.team_id:
        # 如果任务属于某个队伍，当前用户必须在队伍中
        if data.team not in user.teams:
            abort(403)
    else:
        # 非队伍任务，仅作者可分析
        if data.user_id != user.id:
            abort(403)

    
    analysis_result = data.analyze_with_ai()
    return jsonify(analysis_result)

@app.route('/complete_data/<int:data_id>', methods=['POST'])
@login_required
def complete_data(data_id):
    data = UserData.query.get_or_404(data_id)
    user = User.query.get_or_404(session['user_id'])

    # 使用一个标志来判断权限是否被拒绝
    permission_denied = False

    if data.team_id:
        # 如果任务属于某个队伍，当前用户必须在队伍中
        # 这里的 user.teams 不再需要 .all()，因为它已经是列表了
        if data.team not in user.teams:
            permission_denied = True
            logger.warning(f"权限被拒绝：用户 {user.id} (用户名：{user.username}) 尝试完成团队任务 {data_id} (团队 {data.team_id}) 但不在团队中。")
    else:
        # 非队伍任务，仅作者可完成
        if data.user_id != user.id:
            permission_denied = True
            logger.warning(f"权限被拒绝：用户 {user.id} (用户名：{user.username}) 尝试完成私人任务 {data_id} (创建者 {data.user_id}) 但不是创建者。")

    if permission_denied:
        # 如果权限被拒绝，直接返回 JSON 格式的错误信息和 403 状态码
        # 这是为了确保前端 AJAX 请求能够正确解析响应
        return jsonify({"success": False, "message": "您没有权限完成此任务。"}), 403

    try:
        data.is_completed = True
        data.completed_at = datetime.utcnow() # 记录完成时间
        db.session.commit()

        # 对于 AJAX 请求，通常不需要 flash 消息，因为前端会处理提示
        # flash('任务已成功标记为完成！', 'success') 

        logger.info(f"任务 {data_id} 被用户 {user.id} 标记为完成")
        return jsonify({"success": True, "message": "任务已成功标记为完成！"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"任务 {data_id} 被用户 {user.id} 标记为完成时发生错误: {e}")

        # 对于 AJAX 请求，通常不需要 flash 消息
        # flash('标记任务完成时发生错误。', 'danger') 

        return jsonify({"success": False, "message": f"标记任务完成时发生错误: {e}"}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)

if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()
        db.create_all()

    app.run(debug=True)# 修改代码后自动重启程序
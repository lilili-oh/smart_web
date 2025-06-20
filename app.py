from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, g, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import re
import requests
import json
import logging
from dotenv import load_dotenv
import os
from email.header import Header
from email.utils import formataddr
import traceback

load_dotenv()
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.163.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME').strip()
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD').strip()
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER').strip()
app.config['MAIL_DEFAULT_CHARSET'] = 'utf-8'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['XFYUN_SPARK_X1_API_KEY'] = os.environ.get('XFYUN_SPARK_X1_API_KEY')
app.config['XFYUN_SPARK_X1_HTTP_URL'] = "https://spark-api-open.xf-yun.com/v2/chat/completions" # X1 的固定 URL
app.config['UPLOAD_FOLDER'] = 'static/profile_pictures' # For profile pictures
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

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
    created_teams = db.relationship('Team', backref='creator', lazy=True, foreign_keys='Team.creator_id')
    # 添加 set_password 方法
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
    password = db.Column(db.String(255), nullable=False)  # 6位数字密码，必填
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class TeamMember(db.Model):
    __tablename__ = 'team_members'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), primary_key=True)
# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash('您需要登录才能访问此页面。', 'info')
            # 重定向到登录页面，并将当前尝试访问的 URL 作为 'next' 参数传递
            return redirect(url_for('login', next=request.url))
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
@app.route('/team_detail')
@login_required
def team_detail():
    # 获取当前用户加入的所有团队
    # 使用 join 加载 creator 信息，避免 N+1 查询问题
    teams = Team.query.join(TeamMember).filter(
        TeamMember.user_id == g.user.id
    ).options(
        db.joinedload(Team.creator), # 预加载团队创建者
        db.joinedload(Team.members), # 预加载团队成员的用户信息
        db.joinedload(Team.tasks) # 预加载团队任务
    ).all()

    return render_template('team_detail.html', teams=teams)


# 组队功能
@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if request.method == 'POST':
        team_name = request.form.get('team_name')
        description = request.form.get('description')
        password = request.form.get('password')  # 获取密码字段 ✅
        
         # 检查团队名称是否已存在
        if Team.query.filter_by(name=team_name).first():
            flash('团队名称已存在，请选择其他名称。', 'danger')
            return redirect(url_for('create_team'))
        
        if not password or not password.isdigit() or len(password) != 6:
            flash('团队密码必须是6位数字。', 'danger')
            return render_template('team.html')
    
        new_team = Team(
            name=team_name,
            description=description,
            password=generate_password_hash(password),
            # **核心修改：设置 creator_id 为当前登录用户的 ID**
            creator_id=g.user.id 
        )

        try:
            db.session.add(new_team)
            db.session.commit()

            # 将创建者自动加入到团队成员中
            g.user.teams.append(new_team)
            db.session.commit()

            flash(f'团队 "{team_name}" 创建成功并已加入！', 'success')
            return redirect(url_for('dashboard')) # 创建成功后重定向到团队概览页
        except Exception as e:
            db.session.rollback()
            flash(f'创建团队时发生错误: {e}', 'danger')
            return redirect(url_for('create_team'))

    return render_template('team.html')
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
        if not check_password_hash(team.password, input_password):
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

@app.route('/disband_team/<int:team_id>', methods=['POST'])
@login_required
def disband_team(team_id):
    team = Team.query.get_or_404(team_id)

    if g.user.id != team.creator_id:
        flash('您没有权限解散此团队。', 'danger')
        return redirect(url_for('team_detail'))

    try:
        TeamMember.query.filter_by(team_id=team.id).delete()
        UserData.query.filter_by(team_id=team.id).delete() # 根据需求决定是否删除任务
        db.session.delete(team)
        db.session.commit()
        flash(f'团队 "{team.name}" 已成功解散。', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'解散团队时发生错误: {e}', 'danger')
        logger.error(f"解散团队 {team_id} 时发生错误: {e}")
        return redirect(url_for('team_detail'))


@app.route('/kick_member/<int:team_id>/<int:member_id>', methods=['POST'])
@login_required
def kick_member(team_id, member_id):
    team = Team.query.get_or_404(team_id)
    member_to_kick = User.query.get_or_404(member_id)

    if g.user.id != team.creator_id:
        flash('您没有权限踢出此成员。', 'danger')
        return redirect(url_for('team_detail'))

    if g.user.id == member_to_kick.id:
        flash('您不能将自己踢出团队。', 'warning')
        return redirect(url_for('team_detail'))

    try:
        team_member_record = TeamMember.query.filter_by(team_id=team.id, user_id=member_to_kick.id).first()
        if team_member_record:
            db.session.delete(team_member_record)
            db.session.commit()
            flash(f'成员 "{member_to_kick.username}" 已成功从团队 "{team.name}" 中踢出。', 'success')
        else:
            flash(f'成员 "{member_to_kick.username}" 不在该团队中。', 'info')
        return redirect(url_for('team_detail'))
    except Exception as e:
        db.session.rollback()
        flash(f'踢出成员时发生错误: {e}', 'danger')
        logger.error(f"将用户 {member_id} 从团队 {team_id} 踢出时发生错误: {e}")
        return redirect(url_for('team_detail'))
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('您已登出。', 'info')
    return redirect(url_for('home'))
# master page
@app.route('/master', methods=['GET'])
@login_required
@admin_required
def master(): # 函数名从 admin_master 改为 master
    logger.info(f"管理员 {g.user.username} 访问管理员主页。")
    users = User.query.all()
    # 假设这里您想要加载成员和创建者，如您在提示中所示
    teams = Team.query.options(db.joinedload(Team.members), db.joinedload(Team.creator)).all() 
    all_users = User.query.order_by(User.username).all() # 用于添加成员下拉菜单
    return render_template('master.html', users=users, teams=teams, all_users=all_users)


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
                # UserData.team_editable == True
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
                    if check_password_hash(team.password, input_password):
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

# Helper for file uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Password Reset and Change ---
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                token = serializer.dumps(user.email, salt='reset-password')
                reset_url = url_for('reset_token', token=token, _external=True)

                subject = "任务管理系统 - 重置密码请求"
                html_body = render_template('reset_password_email.html', user=user, reset_url=reset_url)

                msg = Message(
                    subject=subject,
                    sender=('任务系统', app.config['MAIL_DEFAULT_SENDER']),  # ⚠️ 这里用 tuple
                    recipients=[user.email],
                    charset='utf-8'
                )
                msg.body = "请使用支持 HTML 的邮箱查看这封邮件。"
                msg.html = html_body

                current_app.logger.debug(repr(app.config['MAIL_USERNAME']))
                current_app.logger.debug(repr(app.config['MAIL_PASSWORD']))
                current_app.logger.debug(repr(app.config['MAIL_DEFAULT_SENDER']))

                mail.send(msg)

                flash('已发送密码重置邮件，请检查收件箱（包含垃圾邮件）。', 'info')
            except Exception as e:
                current_app.logger.error(f"Error sending password reset email: {e}")
                flash(f'发送邮件失败：{e}', 'danger')
        else:
            flash('若邮箱存在，已发送重置邮件，请检查收件箱（包含垃圾邮件）。', 'info')

    return render_template('reset_password_request.html')
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = None
    try:
        # max_age = 3600 (1 hour) for token validity
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except SignatureExpired:
        flash('重置密码链接已过期，请重新申请。', 'danger')
        return redirect(url_for('reset_password_request'))
    except BadTimeSignature:
        flash('重置密码链接无效，请检查或重新申请。', 'danger')
        return redirect(url_for('reset_password_request'))
    except Exception as e:
        current_app.logger.error(f"Error decoding reset token: {e}")
        flash('重置密码链接无效或已损坏。', 'danger')
        return redirect(url_for('reset_password_request'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('用户不存在或链接无效。', 'danger')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        # New password validation
        if not password or not confirm_password:
            flash('新密码和确认密码不能为空。', 'danger')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('两次输入的新密码不一致。', 'danger')
            return render_template('reset_password.html', token=token)
        
        # Password strength validation
        if len(password) < 8:
            flash('新密码长度必须至少为8个字符。', 'danger')
            return render_template('reset_password.html', token=token)
        if not re.search(r"\d", password):
            flash('新密码必须包含至少一个数字。', 'danger')
            return render_template('reset_password.html', token=token)
        if not re.search(r"[A-Z]", password):
            flash('新密码必须包含至少一个大写字母。', 'danger')
            return render_template('reset_password.html', token=token)
        if not re.search(r"[a-z]", password):
            flash('新密码必须包含至少一个小写字母。', 'danger')
            return render_template('reset_password.html', token=token)

        # Optional: Prevent reusing old password (if you want to disallow this)
        # if check_password_hash(user.password_hash, password):
        #     flash('新密码不能与旧密码相同。', 'danger')
        #     return render_template('reset_password.html', token=token)


        user.password = generate_password_hash(password)
        try:
            db.session.commit()
            flash('您的密码已成功重置！请使用新密码登录。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error resetting password for user {user.username}: {e}")
            flash('重置密码失败，请稍后再试。', 'danger')
            return render_template('reset_password.html', token=token)

    return render_template('reset_password.html', token=token)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = g.user # Get the current logged-in user

    if request.method == 'POST':
        old_password = request.form['old_password'].strip()
        new_password = request.form['new_password'].strip()
        confirm_new_password = request.form['confirm_new_password'].strip()

        # Validate old password
        if not check_password_hash(user.password, old_password):
            flash('当前密码不正确。', 'danger')
            return redirect(url_for('change_password'))
        
        # New password validation
        if not new_password or not confirm_new_password:
            flash('新密码和确认新密码不能为空。', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_new_password:
            flash('两次输入的新密码不一致。', 'danger')
            return redirect(url_for('change_password'))

        # Password strength validation (same as register/reset)
        if len(new_password) < 8:
            flash('新密码长度必须至少为8个字符。', 'danger')
            return redirect(url_for('change_password'))
        if not re.search(r"\d", new_password):
            flash('新密码必须包含至少一个数字。', 'danger')
            return redirect(url_for('change_password'))
        if not re.search(r"[A-Z]", new_password):
            flash('新密码必须包含至少一个大写字母。', 'danger')
            return redirect(url_for('change_password'))
        if not re.search(r"[a-z]", new_password):
            flash('新密码必须包含至少一个小写字母。', 'danger')
            return redirect(url_for('change_password'))
        
        # Prevent reusing old password
        if check_password_hash(user.password, new_password):
            flash('新密码不能与当前密码相同。', 'danger')
            return redirect(url_for('change_password'))

        user.password = generate_password_hash(new_password)
        try:
            db.session.commit()
            flash('您的密码已成功修改！', 'success')
            return redirect(url_for('profile')) # Redirect to profile or dashboard
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error changing password for user {user.username}: {e}")
            flash('修改密码失败，请稍后再试。', 'danger')
            return redirect(url_for('change_password'))

    return render_template('change_password.html') # Assuming you have this template

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


@app.route('/admin_update_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    user = User.query.get_or_404(user_id)

    # 从前端提交的隐藏字段中获取数据
    username = request.form['username_update'].strip() # Strip whitespace
    email = request.form['email_update'].strip()      # Strip whitespace
    password = request.form.get('password_update', '').strip() # Use .get() with default empty string and strip

    # --- 1. 数据校验 ---

    # 1.1 检查用户名是否重复 (排除当前用户自身)
    existing_user_with_username = User.query.filter(
        User.username == username,
        User.id != user_id
    ).first()
    if existing_user_with_username:
        flash(f'更新失败：用户名 "{username}" 已存在，请选择其他用户名。', 'danger')
        return redirect(url_for('master'))

    # 1.2 检查邮箱是否重复 (排除当前用户自身)
    existing_user_with_email = User.query.filter(
        User.email == email,
        User.id != user_id
    ).first()
    if existing_user_with_email:
        flash(f'更新失败：邮箱 "{email}" 已被注册，请选择其他邮箱。', 'danger')
        return redirect(url_for('master'))

    # 1.3 密码规范校验 (如果提供了新密码)
    if password:
        # 长度至少8位，包含数字，大小写字母
        # 1. 至少8个字符
        if len(password) < 8:
            flash('更新失败：新密码长度必须至少为8个字符。', 'danger')
            return redirect(url_for('master'))
        # 2. 包含至少一个数字
        if not re.search(r"\d", password):
            flash('更新失败：新密码必须包含至少一个数字。', 'danger')
            return redirect(url_for('master'))
        # 3. 包含至少一个大写字母
        if not re.search(r"[A-Z]", password):
            flash('更新失败：新密码必须包含至少一个大写字母。', 'danger')
            return redirect(url_for('master'))
        # 4. 包含至少一个小写字母
        if not re.search(r"[a-z]", password):
            flash('更新失败：新密码必须包含至少一个小写字母。', 'danger')
            return redirect(url_for('master'))

        # 如果新密码与旧密码相同，通常无需更新（可选）
        if check_password_hash(user.password, password): # Assuming user.password_hash stores the hashed password
            flash('更新失败：新密码不能与当前密码相同。', 'danger')
            return redirect(url_for('master'))

    # --- 2. 更新用户对象 ---
    # 只有通过所有校验后才进行更新
    user.username = username
    user.email = email
    
    if password: # 只有当提供了且通过校验的新密码时才更新密码
        user.password = generate_password_hash(password) # 确保你的User模型中存储的是password_hash字段

    try:
        db.session.commit() # 提交数据库更改
        flash(f'用户 {user.username} 数据更新成功！', 'success')
    except Exception as e:
        db.session.rollback() # 回滚事务，防止部分更新
        flash(f'用户数据更新失败：{str(e)}', 'danger') # 给出详细错误信息
    
    return redirect(url_for('master')) # 重定向回管理员中心页面


@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    logger.info(f"管理员 {g.user.username} (ID: {g.user.id}) 尝试删除用户ID: {user_id}。")
    user_to_delete = User.query.get(user_id)

    if not user_to_delete:
        flash('用户不存在。', 'danger')
        logger.warning(f"管理员尝试删除不存在的用户 (ID: {user_id})。")
        return redirect(url_for('master')) # 假设 'master' 是您的管理员仪表板路由
    
    if user_to_delete.id == g.user.id:
        flash('您不能删除您自己的账户！', 'danger')
        logger.warning(f"管理员 {g.user.username} (ID: {g.user.id}) 尝试删除自己的账户。")
        return redirect(url_for('master'))

    try:
        # 1. 删除用户创建的所有 UserData (旧的 Task 模型现在名为 UserData)
        # UserData.user_id 是 User 模型的外键，并且是 nullable=False，
        # 所以当用户被删除时，其所有相关 UserData 记录必须被删除。
        # 使用 synchronize_session='fetch' 可以确保 SQLAlchemy 在执行 DELETE 语句前，
        # 将受影响的对象加载到 session 中，以保持 session 的一致性。
        UserData.query.filter_by(user_id=user_to_delete.id).delete(synchronize_session='fetch')
        logger.info(f"已删除用户 {user_to_delete.username} (ID: {user_to_delete.id}) 创建的所有数据项。")

        # 2. 从所有团队中移除该用户作为成员
        # TeamMember 现在是一个独立的模型，直接从 TeamMember 表中删除与该用户相关的所有记录。
        TeamMember.query.filter_by(user_id=user_to_delete.id).delete(synchronize_session='fetch')
        logger.info(f"已移除用户 {user_to_delete.username} (ID: {user_to_delete.id}) 的所有团队成员关系。")

        # 3. 处理该用户创建的团队
        # Team.creator_id 是 nullable=False，所以用户创建的团队必须被删除。
        # 注意：这里使用 list() 来创建一个副本，以避免在遍历并删除集合时引发 RuntimeError。
        teams_created_by_user = list(user_to_delete.created_teams) 
        for team in teams_created_by_user:
            logger.info(f"正在处理用户 {user_to_delete.username} 创建的团队 '{team.name}' (ID: {team.id})。")
            
            # 3.1 删除这些团队关联的所有 UserData (旧的 Task 模型)
            # UserData.team_id 是 nullable=True，但通常团队内的任务会随着团队一起删除。
            UserData.query.filter_by(team_id=team.id).delete(synchronize_session='fetch')
            logger.info(f"已删除团队 '{team.name}' (ID: {team.id}) 的所有数据项。")
            
            # 3.2 删除这些团队的所有成员关系
            # 同样，直接从 TeamMember 表中删除与该团队相关的所有记录。
            TeamMember.query.filter_by(team_id=team.id).delete(synchronize_session='fetch')
            logger.info(f"已移除团队 '{team.name}' (ID: {team.id}) 的所有成员关系。")

            # 3.3 删除团队本身
            db.session.delete(team) # 删除团队对象
            logger.info(f"已删除团队 '{team.name}' (ID: {team.id})。")
        logger.info(f"已处理用户 {user_to_delete.username} (ID: {user_to_delete.id}) 创建的所有团队。")

        # 4. 最后删除用户本身
        db.session.delete(user_to_delete)
        db.session.commit() # 提交所有更改
        
        flash(f'用户 "{user_to_delete.username}" 及所有相关数据已成功删除。', 'success')
        logger.info(f"用户 {user_to_delete.username} (ID: {user_to_delete.id}) 及其所有相关数据删除成功并提交。")
    except Exception as e:
        db.session.rollback() # 如果发生任何错误，则回滚所有操作
        flash(f'删除用户时发生错误: {e}', 'danger')
        # 记录完整的错误堆栈信息，以便更好地调试
        logger.error(f"删除用户 {user_id} (名为 '{user_to_delete.username if user_to_delete else 'N/A'}') 时发生错误: {e}", exc_info=True)
    return redirect(url_for('master'))

# 管理员添加团队成员
@app.route('/admin_add_team_member/<int:team_id>', methods=['POST'])
@login_required
@admin_required
def admin_add_team_member(team_id):
    logger.info(f"--- [admin_add_team_member] 开始处理请求 ---")
    logger.info(f"接收到的目标团队ID: {team_id}")
    
    # --- 1. 验证团队是否存在 ---
    team = Team.query.get(team_id)
    if not team:
        flash('操作失败：所选团队不存在。', 'danger')
        logger.warning(f"[admin_add_team_member] 团队 (ID: {team_id}) 未找到。")
        return redirect(url_for('master')) # <-- 已更新
    logger.info(f"[admin_add_team_member] 团队 '{team.name}' (ID: {team.id}) 已加载。")

    # --- 2. 获取并验证要添加的用户ID ---
    user_id_str = request.form.get('user_id')
    
    if not user_id_str:
        flash('操作失败：请选择一个要添加的用户。', 'danger')
        logger.warning(f"[admin_add_team_member] 未选择用户添加到团队 {team.name} (ID: {team.id})。")
        return redirect(url_for('master')) # <-- 已更新

    try:
        user_id_to_add = int(user_id_str)
    except (ValueError, TypeError):
        flash('操作失败：用户ID格式不正确。', 'danger')
        logger.error(f"[admin_add_team_member] 用户ID格式错误: '{user_id_str}'。")
        return redirect(url_for('master')) # <-- 已更新

    user_to_add = User.query.get(user_id_to_add)
    if not user_to_add:
        flash('操作失败：所选用户不存在。', 'danger')
        logger.warning(f"[admin_add_team_member] 用户 (ID: {user_id_to_add}) 未找到。")
        return redirect(url_for('master')) # <-- 已更新
    logger.info(f"[admin_add_team_member] 用户 '{user_to_add.username}' (ID: {user_to_add.id}) 已加载。")
    
    # --- 3. 检查用户是否已在团队中 (利用 ORM 关系) ---
    if team in user_to_add.teams: 
        flash(f'操作失败：用户 "{user_to_add.username}" 已经存在于团队 "{team.name}" 中。', 'warning')
        logger.info(f"[admin_add_team_member] 用户 {user_to_add.username} (ID: {user_to_add.id}) 已是团队 {team.name} (ID: {team.id}) 的成员，跳过添加。")
        return redirect(url_for('master')) # <-- 已更新
    logger.info(f"[admin_add_team_member] 用户 {user_to_add.username} (ID: {user_to_add.id}) 尚未在团队 {team.name} 中。")

    # --- 4. 添加新的团队成员 (通过操作 ORM 关系) ---
    try:
        user_to_add.teams.append(team)
        logger.info(f"[admin_add_team_member] 团队 '{team.name}' (ID: {team.id}) 已添加到用户 '{user_to_add.username}' (ID: {user_to_add.id}) 的团队列表中。即将提交。")
        
        db.session.commit() # 提交事务到数据库

        flash(f'成功：用户 "{user_to_add.username}" 已加入团队 "{team.name}"。', 'success')
        logger.info(f"[admin_add_team_member] **成功提交！** 用户 {user_to_add.username} (ID: {user_to_add.id}) 已添加到团队 {team.name} (ID: {team.id})。")
        
        db.session.refresh(user_to_add) # 刷新 user_to_add 对象以反映最新数据库状态
        if team in user_to_add.teams:
            logger.info(f"[admin_add_team_member] **确认：** 数据库中已确认用户 {user_to_add.username} 属于团队 {team.name}。")
        else:
            logger.error(f"[admin_add_team_member] **警告：** 尽管提交成功，但刷新后未能确认用户在团队中！")

    except Exception as e:
        db.session.rollback() # 如果发生任何数据库错误，回滚事务以保持数据一致性
        flash(f'操作失败：将用户加入团队时发生数据库错误。详情: {e}', 'danger')
        logger.error(
            f"[admin_add_team_member] **数据库错误！** 将用户 {user_id_to_add} (名为 '{user_to_add.username}') 添加到团队 {team_id} (名为 '{team.name}') 时发生错误: {e}",
            exc_info=True # 记录完整的错误堆栈，这对于调试非常重要
        )
        logger.info(f"--- [admin_add_team_member] 请求处理结束，因错误回滚。 ---")
        return redirect(url_for('master')) # <-- 已更新

    logger.info(f"--- [admin_add_team_member] 请求处理成功结束。 ---")
    return redirect(url_for('master')) # <-- 已更新

@app.route('/admin_update_team/<int:team_id>', methods=['POST'])
@admin_required
def admin_update_team(team_id):
    team = Team.query.get_or_404(team_id)

    # Use the names from the hidden input fields in master.html
    name = request.form['name_update']
    description = request.form['description_update']
    password = request.form.get('password_update') # Use .get() for optional fields

    # Update the team object
    team.name = name
    team.description = description
    if password: # Only update password if a new one was provided
        team.password = generate_password_hash(password) # Assuming you use werkzeug.security

    db.session.commit()
    flash('团队更新成功！', 'success')
    return redirect(url_for('master')) # Or wherever you want to redirect
# !!! 修改点 3: 管理员解散/删除团队 (统一功能) !!!
# 移除原有的 delete_team_by_admin 路由和函数，所有相关调用都指向 admin_disband_team
@app.route('/admin_disband_team/<int:team_id>', methods=['POST'])
@login_required
@admin_required
def admin_disband_team(team_id):
    logger.info(f"管理员 {g.user.username} 尝试解散/删除团队ID: {team_id}。")
    team_to_disband = Team.query.get_or_404(team_id)
    if not team_to_disband:
        flash('团队不存在。', 'danger')
        logger.warning(f"管理员尝试解散/删除不存在的团队 (ID: {team_id})。")
        return redirect(url_for('master')) # <-- 已更新
    try:
        TeamMember.query.filter_by(team_id=team_to_disband.id).delete()
        UserData.query.filter_by(team_id=team_to_disband.id).delete() # 根据需求决定是否删除任务
        db.session.delete(team_to_disband)
        db.session.commit()
        flash(f'团队 "{team_to_disband.name}" 已成功解散。', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'解散团队时发生错误: {e}', 'danger')
        logger.error(f"解散团队 {team_id} 时发生错误: {e}")
    
    return redirect(url_for('master')) # <-- 已更新

# !!! 新增: 管理员踢出某个团队的成员 !!!
@app.route('/admin_remove_team_member/<int:team_id>/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_remove_team_member(team_id, user_id):
    logger.info(f"管理员 {g.user.username} 尝试将用户 {user_id} 从团队 {team_id} 中移除。")
    team = Team.query.get(team_id)
    user_to_remove = User.query.get(user_id)

    if not team:
        flash('团队不存在。', 'danger')
        logger.warning(f"尝试从不存在的团队 (ID: {team_id}) 移除成员。")
        return redirect(url_for('master'))
    
    if not user_to_remove:
        flash('用户不存在。', 'danger')
        logger.warning(f"尝试移除不存在的用户 (ID: {user_id})。")
        return redirect(url_for('master'))

    # 不允许将团队创建者移除（因为创建者通常有特殊权限或关联，应通过解散团队来处理）
    if user_to_remove.id == team.creator_id:
        flash(f'不能将团队创建者 ({user_to_remove.username}) 从团队中移除。如果需要解散团队，请使用解散团队功能。', 'warning')
        logger.warning(f"管理员 {g.user.username} 尝试将团队 {team.name} 的创建者 {user_to_remove.username} 移除。")
        return redirect(url_for('master')) # 或者重定向到 team_details 页面

    team_member = TeamMember.query.filter_by(team_id=team.id, user_id=user_to_remove.id).first()

    if not team_member:
        flash(f'用户 "{user_to_remove.username}" 不是团队 "{team.name}" 的成员。', 'warning')
        logger.warning(f"用户 {user_to_remove.username} (ID: {user_to_remove.id}) 不是团队 {team.name} (ID: {team.id}) 的成员，无法移除。")
        return redirect(url_for('master'))

    try:
        db.session.delete(team_member)
        db.session.commit()
        flash(f'用户 "{user_to_remove.username}" 已成功从团队 "{team.name}" 中移除。', 'success')
        logger.info(f"用户 {user_to_remove.username} (ID: {user_to_remove.id}) 已成功从团队 {team.name} (ID: {team.id}) 中移除。")
    except Exception as e:
        db.session.rollback()
        flash(f'移除团队成员时发生错误: {e}', 'danger')
        logger.error(f"移除用户 {user_to_remove.username} (ID: {user_to_remove.id}) 从团队 {team.name} (ID: {team.id}) 时发生错误: {e}", exc_info=True)
    
    return redirect(url_for('master')) # 或者重定向到 team_details 页面

# 提供一个API端点，获取所有用户，用于前端填充下拉菜单
@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.all()
    users_data = [{'id': user.id, 'username': user.username} for user in users]
    return jsonify(users_data)


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
    user_id = session.get('user_id') # 从 session 中获取用户ID

    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)
        
        if g.user is None:
            session.pop('user_id', None) # 清除无效的 user_id
            flash('您的账户可能已被删除或不存在，请重新登录。', 'warning')


if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()
        if not User.query.filter_by(is_admin=True).first():
            print("No admin user found. Creating a default admin user: admin@example.com / admin123")
            admin_user = User(username='admin', email='admin@example.com', password=generate_password_hash('admin123'), is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created. Please change the password!")
        db.create_all()

    app.run(debug=True)# 修改代码后自动重启程序
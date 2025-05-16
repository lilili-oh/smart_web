from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
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
import openai
import requests
import json
import logging
import time

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['OPENAI_API_KEY'] = 'your-openai-api-key'  # Replace with your actual API key

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
openai.api_key = app.config['OPENAI_API_KEY']

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ollama API 配置
OLLAMA_MODEL = "deepseek-r1:1.5b"  # 使用本地部署的模型
MAX_RETRIES = 3  # 最大重试次数
RETRY_DELAY = 2  # 重试延迟（秒）

def check_ollama_service():
    """检查 Ollama 服务是否可用"""
    try:
        import subprocess
        # 检查服务是否运行
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Ollama list 命令失败: {result.stderr}")
            return False
            
        # 检查模型是否已下载
        model_check = subprocess.run(['ollama', 'show', OLLAMA_MODEL], capture_output=True, text=True)
        if model_check.returncode != 0:
            logger.error(f"模型 {OLLAMA_MODEL} 未找到: {model_check.stderr}")
            return False
            
        logger.info(f"Ollama 服务正常，模型 {OLLAMA_MODEL} 可用")
        return True
    except Exception as e:
        logger.error(f"检查 Ollama 服务时出错: {str(e)}")
        return False

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
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
        try:
            # 首先检查 Ollama 服务是否可用
            if not check_ollama_service():
                return {"error": "Ollama 服务未运行或无法访问。请确保 Ollama 已启动并正在运行。"}

            logger.info(f"Starting AI analysis for task: {self.title}")

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

            # 使用 subprocess 直接调用 Ollama
            import subprocess
            import json
            import locale
            import re

            logger.info(f"Running Ollama with model: {OLLAMA_MODEL}")
            logger.info(f"Prompt: {prompt}")

            # 设置环境变量以使用 UTF-8 编码
            my_env = os.environ.copy()
            my_env["PYTHONIOENCODING"] = "utf-8"

            # 调用 Ollama
            result = subprocess.run(
                ['ollama', 'run', OLLAMA_MODEL, prompt],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=my_env,
                timeout=60  # 设置60秒超时
            )

            logger.info(f"Ollama return code: {result.returncode}")
            logger.info(f"Ollama stdout: {result.stdout}")
            logger.info(f"Ollama stderr: {result.stderr}")

            if result.returncode == 0:
                if not result.stdout:
                    error_msg = "Ollama 没有返回任何输出"
                    logger.error(error_msg)
                    return {"error": error_msg}

                try:
                    # 尝试从输出中提取 JSON 部分
                    # 首先尝试匹配 ```json 标记中的内容
                    json_match = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', result.stdout)
                    if json_match:
                        json_str = json_match.group(1)
                    else:
                        # 如果没有找到 ```json 标记，尝试匹配任何有效的 JSON 对象
                        # 使用更精确的正则表达式来匹配 JSON 对象
                        json_match = re.search(r'(\{(?:[^{}]|(?:\{[^{}]*\}))*\})', result.stdout)
                        if json_match:
                            json_str = json_match.group(1)
                        else:
                            # 如果仍然没有找到，尝试清理输出并查找 JSON
                            # 移除可能的非 JSON 文本
                            cleaned_output = re.sub(r'^.*?(\{|\[)', r'\1', result.stdout, flags=re.DOTALL)
                            cleaned_output = re.sub(r'(\}|\]).*$', r'\1', cleaned_output, flags=re.DOTALL)
                            if cleaned_output and (cleaned_output.startswith('{') or cleaned_output.startswith('[')):
                                json_str = cleaned_output
                            else:
                                raise json.JSONDecodeError("No valid JSON found in output", result.stdout, 0)

                    # 清理 JSON 字符串中可能的非 JSON 字符
                    json_str = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', json_str)

                    # 尝试解析 JSON
                    analysis_json = json.loads(json_str)
                    self.ai_analysis = json.dumps(analysis_json, ensure_ascii=False)
                    db.session.commit()
                    logger.info("AI analysis saved to database")
                    return analysis_json
                except json.JSONDecodeError as e:
                    error_msg = f"无法解析 Ollama 输出为 JSON: {str(e)}"
                    logger.error(error_msg)
                    logger.error(f"原始输出: {result.stdout}")
                    # 如果解析失败，保存原始文本
                    self.ai_analysis = result.stdout
                    db.session.commit()
                    logger.info("AI analysis saved as text to database")
                    return {"error": error_msg}
            else:
                error_msg = f"Ollama 运行失败: {result.stderr}"
                logger.error(error_msg)
                return {"error": error_msg}

        except subprocess.TimeoutExpired:
            error_msg = "Ollama 运行超时"
            logger.error(error_msg)
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
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if not validate_password(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration.', 'danger')
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
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


#任务总结功能
@app.route('/summary', methods=['GET', 'POST'])
@login_required
def summary():
    return render_template('summary.html')  # 渲染创建队伍页面


# 组队功能
@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if request.method == 'POST':
        team_name = request.form.get('team_name')
        description = request.form.get('description')
        
        # 创建新队伍
        team = Team(name=team_name, description=description)
        db.session.add(team)
        db.session.commit()
        
        flash('Team created successfully!', 'success')
        
        # 返回到用户的个人资料页面，显示新创建的队伍
        return redirect(url_for('profile'))  # 可以重定向到个人资料页面查看队伍

    return render_template('team.html')  # 渲染创建队伍页面
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# 加入队伍功能
@app.route('/join_team/<int:team_id>', methods=['GET', 'POST'])
@login_required
def join_team(team_id):
    # 获取当前登录的用户
    user = User.query.get_or_404(session['user_id'])
    team = Team.query.get_or_404(team_id)
    
    # 如果用户已经是队伍成员，则提示
    if team in user.teams:
        flash(f'You are already a member of the team "{team.name}".', 'info')
        return redirect(url_for('profile'))  # 可以重定向到个人资料页面

    # 将用户加入队伍
    user.teams.append(team)
    db.session.commit()
    flash(f'You have successfully joined the team "{team.name}".', 'success')
    
    return redirect(url_for('profile'))  # 可以重定向到个人资料页面

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
            flash(f'You have left the team {team.name}.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error leaving the team.', 'danger')
    else:
        flash('You are not a member of this team.', 'warning')

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
    user = User.query.get_or_404(session['user_id'])
    
    teams = user.teams
    tasks = user_data = UserData.query.filter(
        or_(
            UserData.user_id == user.id,
            and_(
                UserData.team_editable == True,
                UserData.team_id.in_([team.id for team in user.teams])
            )
        )
    ).order_by(UserData.created_at.desc()).all()

    return render_template('dashboard.html', user=user, user_data=tasks)

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
            flash('Title and content are required.', 'danger')
            return render_template('add_data.html' ,user=user, teams=teams)

        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid deadline format.', 'danger')
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
            flash('Data added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while adding data.', 'danger')
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
            flash('Title and content are required.', 'danger')
            return render_template('edit_data.html', data=data,user=user, teams=teams)

        # Convert deadline string to datetime if provided
        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid deadline format.', 'danger')
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
            flash('Data updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating data.', 'danger')
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
        flash('User updated successfully!', 'success')
    except Exception:
        db.session.rollback()
        flash('Update failed.', 'danger')

    return redirect(url_for('master'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception:
        db.session.rollback()
        flash('Delete failed.', 'danger')

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
        flash('Data deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting data.', 'danger')

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
                if team and team not in user.teams:
                    user.teams.append(team)
                    flash(f'Joined team: {team.name}', 'success')
                    updated = True
            except ValueError:
                flash('Invalid team selection.', 'danger')
        else:
            if 'team_id' in request.form:  # 用户点击了 Join 但没选队伍
                flash('Please select a team to join.', 'warning')

        # 提交变更
        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to update profile.', 'danger')

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

if __name__ == '__main__':
    with app.app_context():
        # Drop all tables
        #db.drop_all()
        # Create all tables
        db.create_all()

        # 👇 只运行一次，用于设置管理员用户
        admin = User.query.filter_by(username='yb').first()
        if admin:
            admin.is_admin = True
            db.session.commit()
            print(f"✅ 设置 {admin.username} 为管理员")
        else:
            print("❌ 没有找到用户 'yb'")

    app.run(debug=True)# 修改代码后自动重启程序
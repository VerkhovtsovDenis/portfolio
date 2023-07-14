from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, request, flash, redirect, session, abort
from sqlalchemy import select
from werkzeug.security import check_password_hash, generate_password_hash

from forms import LoginForm, RegisterForm
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from UserLogin import UserLogin

from sqlalchemy.orm import Session, QueryContext

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bf612bd68decb030446c2b93e9dc8095f95d8bd35d0f87c2'
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///dbase.db'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, пройдите авторизацию для доступа к странице.'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return UserLogin().fromDB(user_id, Users)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lastName = db.Column(db.String(30))
    firstName = db.Column(db.String(30))
    fatherName = db.Column(db.String(30))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    email = db.Column(db.String(30), unique=True, nullable=False)
    pwd = db.Column(db.String(500), nullable=False)


class UserRole(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__(self):
        return f'<userrole> {self.user_id}>'


class Roles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))

    def __repr__(self):
        return f'<roles {self.id}>'


class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    human_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))

    def __repr__(self):
        return f'<portfolio {self.id}>'


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    description = db.Column(db.Text)
    date_start = db.Column(db.DateTime)
    date_end = db.Column(db.DateTime)

    def __repr__(self):
        return f'<event {self.id}>'


class Competence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    skills_id = db.Column(db.Integer, db.ForeignKey('skills.id'))

    def __repr__(self):
        return f'<competence {self.id}>'


class Skills(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    description = db.Column(db.Text)

    def __repr__(self):
        return f'<skill {self.id}>'


menu = [
    {'name': 'Главная', 'url': '/'},
    {'name': 'Авторизация', 'url': '/login'},
    {'name': 'Регистрация', 'url': '/registration'},
    {'name': 'О сайте', 'url': '/about'}]


@app.route('/')
def index():
    return render_template('index.html', menu=menu)


@app.route('/about')
def about():
    return render_template('about.html', title="О сайте", menu=menu)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        if request.form['username']:
            flash('Сообщение отправлено', category='success')
        else:
            flash('Ошибка отправки', category='error')
    return render_template('contact.html', title="Обратная связь", menu=menu)

@app.route('/profile/<username>', methods=['POST', 'GET'])
@login_required
def profile(username):
    if username == current_user.get_user().email.split('@')[0]:
        return render_template('profile.html', title='Профиль', menu=menu, user=current_user.get_user())
    else:
        abort(401)

tables = {
    'Users':[],
    'Events':[]
}


def get_portfolio():
    tables['Users_and_Role'] = db.session.query(Users, Roles.name).join(UserRole, Users.id==UserRole.user_id).join(Roles, UserRole.role_id==Roles.id).all()

    for i in range(len(tables['Users_and_Role'])):
        user_id_ = tables['Users_and_Role'][i][0].id

        skills_ = db.session.query(Skills.name).join(Competence, Competence.skills_id == Skills.id).join(Event, Event.id == Competence.event_id).join(Portfolio, Portfolio.event_id==Event.id).filter(Portfolio.human_id==user_id_).all()
        tables['Users_and_Role'][i] = (*tables['Users_and_Role'][i], skills_, 'Изменить', 'Удалить')

    return tables['Users_and_Role']


@app.route('/admin/<username>')
def admin(username):
    if username == current_user.get_user().email.split('@')[0]:
        get_portfolio()
        return render_template('admin.html', title='Админ панель', menu=menu, user=current_user.get_user(), tables=tables)
    else:
        abort(401)

@app.route('/registration', methods=['POST', 'GET'])
def registration():
    form = RegisterForm()
    if 'userLogged' in session:
        return redirect(url_for('profile', username=session['userLogged']))
    elif form.validate_on_submit():
        try:
            hash = generate_password_hash(form.pwd.data)
            u = Users(lastName=form.lastName.data,
                      firstName=form.firstName.data,
                      fatherName=form.fatherName.data,
                      email=form.email.data,
                      pwd=hash)

            db.session.add(u)
            db.session.flush()
            db.session.commit()

            ur = UserRole(user_id=getUserByEmail(form.email.data).id, role_id=4)
            db.session.add(ur)
            db.session.flush()
            db.session.commit()

        except Exception as ex:
            db.session.rollback()

        return redirect(url_for('login'))
    return render_template('registration.html', title='Регистрация', menu=menu, form=form)

def getUserByEmail(input_email: str) -> Users:
    return Users.query.filter_by(email=input_email).first()

def getUserRole(user: Users):
    return UserRole.query.filter_by(user_id=user.id).first().role_id

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile', username=current_user.get_user().email.split('@')[0]))
    form = LoginForm()

    if form.validate_on_submit():
        user = getUserByEmail(form.email.data)
        if user and check_password_hash(user.pwd, form.pwd.data):
            userlogin = UserLogin().create(user)
            login_user(userlogin)

            role = getUserRole(user)

            if role == 1:
                return redirect(request.args.get('next') or url_for('admin', username=user.email.split('@')[0]))
            elif role == 2:
                return redirect(request.args.get('next') or url_for('profile', username=user.email.split('@')[0]))
            elif role == 3:
                return redirect(request.args.get('next') or url_for('profile', username=user.email.split('@')[0]))
            elif role == 4:
                return redirect(request.args.get('next') or url_for('profile', username=user.email.split('@')[0]))


        flash(f'Неверно указана почта или пароль.', category='error')

    return render_template('login.html', title='Авторизация', menu=menu, form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из аккаунта', category='success')
    return redirect(url_for('login'))


@app.errorhandler(404)
@app.errorhandler(401)
def pageNotFound(error):
    return render_template('page404.html', title='Страница не найдена', menu=menu), 404


with app.test_request_context():
    print(url_for('index'))
    print(url_for('about'))
    print(url_for('contact'))
    print(url_for('logout'))
    print(url_for('registration'))
    print(url_for('admin', username='denis'))
    print(url_for('profile', username='denis'))

if __name__ == '__main__':
    app.run(Debug=True)

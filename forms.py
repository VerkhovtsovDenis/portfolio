from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class LoginForm(FlaskForm):
    email = StringField('Email: ', validators=[Email()])
    pwd = PasswordField('Пароль: ', validators=[DataRequired(), Length(min=6, max=100)])
    remember = BooleanField('Запомнить', default=False)
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    lastName = StringField('Фамилия: ', validators=[Length(min=4, max=30, message='Фамилия должно быть от 4 до 30 символов')])
    firstName = StringField('Имя: ', validators=[Length(min=4, max=30, message='Имя должно быть от 4 до 30 символов')])
    fatherName = StringField('Отчество: ', validators=[Length(min=4, max=30, message='Отчество должно быть от 4 до 30 символов')])
    email = StringField('Email: ', validators=[Email()])
    pwd = PasswordField('Пароль: ', validators=[DataRequired(), Length(min=6, max=100)])
    pwd2 = PasswordField('Повтор пароля: ', validators=[DataRequired(), EqualTo('pwd', message='Пароли не совпадают'),
                                                        Length(min=6, max=100)])
    submit = SubmitField('Регистрация')

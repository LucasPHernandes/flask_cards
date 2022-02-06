import bcrypt
from flask import Flask, flash, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask('__name__')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'chavesecreta'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Definindo O Usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(100), nullable=False)

class flashCard(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    idUsername = db.Column(db.String(200), nullable=False)
    cardName = db.Column(db.String(100), nullable=False)
    cardContent = db.Column(db.String(250), nullable=False)

# Criando Formulário de Registro
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Registrar")

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()

        if existing_user_name:
            raise ValidationError('O nome de usuário já existe, Por favor escolha outro.')

# Criando Formulário de Login
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

class AddCard(FlaskForm):
    cardName = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Nome do Card"})

    cardContent = StringField(validators=[InputRequired(), Length(min=4, max=250)], render_kw={"placeholder": "Conteúdo do Card"})

    submit = SubmitField("Adicionar")


@app.route('/', methods=['POST', 'GET'])
def home():
    return render_template('home.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                user_id = int(current_user.id)
                return redirect(url_for('dashboard', user_id=user_id))
    return render_template('login.html', form=form)

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard/<user_id>', methods=['POST', 'GET'])
@login_required
def dashboard(user_id):
    user_id = user_id
    
    check_id = flashCard.query.get(current_user.id)

    cards = flashCard.query.filter_by(idUsername = check_id.id)
    # print(cards)
    if check_id.id == current_user.id:
        return render_template('dashboard.html', user_id=current_user.id, cards=cards)
    
    return render_template('dashboard.html', user_id=current_user.id)
        
        
    

@app.route('/adicionar/<user_id>', methods=['POST', 'GET'])
@login_required
def adicionarCard(user_id):
    form = AddCard()
    if form.validate_on_submit():
        # cardName = flashCard.query.filter_by(cardName = form.cardName.data)
        # if not cardName:
        new_card = flashCard(idUsername = current_user.id, cardName = form.cardName.data, cardContent = form.cardContent.data)
        db.session.add(new_card)
        db.session.commit()
    return render_template('addPage.html', form=form, user_id=current_user.id)


if __name__ == "__main__":
    app.run(debug=True)


# Criar um programa para criar FlashCards para ajudar nos estudos
# Ao clicar em um FlahsCard, o mesmo abrirá uma página com mais detalhes do mesmo [vai ser difícil fazer isso...]
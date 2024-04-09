from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

userlogin = Flask(__name__)

userlogin.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
userlogin.secret_key = 'minikaniko ni monico ang makina ni monica'
db = SQLAlchemy(userlogin)
userlogin.app_context().push()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

db.create_all()

@userlogin.route('/home') #here yung ichchange para magredirect sa mismong anes natin
def home():
    return render_template('index.html')

@userlogin.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            session['error'] = 'Username already exists.'
            return redirect('/signup')    
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/')
    error = session.pop('error', None)
    return render_template('signup.html', error=error)

@userlogin.route('/', methods=['GET','POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user.password):
                session['username'] = username
                return redirect('/home') 
            else:
                session['error'] = 'Invalid username or password.'
                return redirect('/')
        else:
            session['error'] = 'User not found. Create an account.'
            return redirect('/')
    error = session.pop('error', None)
    return render_template('login.html', error=error)

if __name__ == '__main__':
    userlogin.run(debug=True)

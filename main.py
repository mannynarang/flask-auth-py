from Tools.scripts.make_ctype import method
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CHEAT_SHEET_DOWNLOAD'] = '\CHEAT_SHEET_DOWNLOAD'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hash_salted = generate_password_hash(password=request.form['password'], method='pbkdf2:sha256', salt_length=8)

        new_user = User(email=request.form['email'],
                        password=hash_salted,
                        name=request.form['name'])

        db.session.add(new_user)

        db.session.commit()
        login_user(new_user)
        return render_template("secrets.html", name=request.form['name'])

    return render_template("register.html")


@login_manager.user_loader
def load_user(user_id):
    print(user_id)
    user = db.session.query(User).filter_by(id=int(user_id)).first()
    return user


@app.route('/login', methods=['POST', 'GET'])
def login():
    error = "Sucessful"
    if request.method == 'POST':
        request.form['email']
        request.form['password']

        user = db.session.query(User).filter_by(email=request.form['email']).first()
        # print(user.email)
        # print(check_password_hash(request.form['password'], user.password))
        if user is not None:
            if check_password_hash(user.password,request.form['password'] ):
                login_user(user)
                return redirect(url_for("secrets"))
        else:
            flash("Invalid user/password")

    return render_template("login.html",error=error, logged_in=current_user.is_authenticated)


@app.route('/secrets')
def secrets():
    return render_template("secrets.html",name=current_user.email,logged_in=current_user.is_authenticated)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
def download():
    return send_from_directory('static', 'files/cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=9002)

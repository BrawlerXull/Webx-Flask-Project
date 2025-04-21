from flask import Flask, render_template, flash, redirect, url_for, session, request
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['articles_db']

# -------------------- Forms --------------------
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

# -------------------- Auth Decorator --------------------
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('display_login'))
    return wrap

# -------------------- Routes --------------------
@app.route('/')
def display_index():
    return render_template('home.html')

@app.route('/about')
def display_about():
    return render_template('about.html')

@app.route('/articles')
def display_articles():
    articles = list(db.articles.find())
    return render_template('articles.html', articles=articles)

@app.route('/article/<string:id>/')
def display_article(id):
    article = db.articles.find_one({'_id': ObjectId(id)})
    return render_template('article.html', article=article)

@app.route('/register', methods=['GET', 'POST'])
def display_register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        db.users.insert_one({
            'name': form.name.data,
            'email': form.email.data,
            'username': form.username.data,
            'password': sha256_crypt.encrypt(str(form.password.data))
        })
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('display_index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def display_login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']
        user = db.users.find_one({'username': username})

        if user and sha256_crypt.verify(password_candidate, user['password']):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('display_dashboard'))
        else:
            error = 'Invalid credentials'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('display_login'))

@app.route('/dashboard')
@is_logged_in
def display_dashboard():
    articles = list(db.articles.find())
    return render_template('dashboard.html', articles=articles)

@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        db.articles.insert_one({
            'title': form.title.data,
            'body': form.body.data,
            'author': session['username']
        })
        flash('Article Created', 'success')
        return redirect(url_for('display_dashboard'))
    return render_template('add_article.html', form=form)

@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    article = db.articles.find_one({'_id': ObjectId(id)})
    form = ArticleForm(request.form, data=article)

    if request.method == 'POST' and form.validate():
        db.articles.update_one({'_id': ObjectId(id)}, {
            '$set': {
                'title': form.title.data,
                'body': form.body.data
            }
        })
        flash('Article Updated', 'success')
        return redirect(url_for('display_dashboard'))

    return render_template('edit_article.html', form=form)

@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    db.articles.delete_one({'_id': ObjectId(id)})
    flash('Article Deleted', 'success')
    return redirect(url_for('display_dashboard'))

# -------------------- Run App --------------------
if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)

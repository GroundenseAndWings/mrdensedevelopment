from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/developerhome')
def developerhome():
    return render_template('developerhome.html', user = current_user)

@auth.route('/developersignin', methods = ['GET', 'POST'])
def developersignin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username = username).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Login success.', category = 'success')
                login_user(user, remember = True)
            else:
                flash('Login failed.', category = 'error')
        else:
            flash('Login failed.', category = 'error')
    return render_template('developersignin.html', user = current_user)

@auth.route('/developersignout')
@login_required
def developersignout():
    logout_user()
    return redirect(url_for('auth.developersignin'))

@auth.route('/developergetstarted', methods = ['GET', 'POST'])
def developergetstarted():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        user = User.query.filter_by(username = username).first()
        user2 = User.query.filter_by(email = email).first()

        if user:
            flash('Username taken.', category = 'error')
        elif user2:
            flash('Email is in use.', category = 'error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(username) < 4:
            flash('Username must be greater than 3 characters.', category='error')
        elif password != password2:
            flash('Passwords do not match.', category='error')
        elif len(password) < 8:
            flash('Passwords must be atleast 8 characters.', category='error')
        else:
            new_user = User(email = email, username = username, password = generate_password_hash(password, method = 'sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember = True)
            flash('Account created.', category='success')

    return render_template('developergetstarted.html', user = current_user)
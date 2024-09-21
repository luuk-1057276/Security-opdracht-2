from flask import Flask, render_template, request, Blueprint, session, redirect, flash
from werkzeug.security import generate_password_hash
from models.model import *

#imports and setup for logging
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename='logs.log',
                    )

app = Flask(__name__)
auth = Blueprint('auth', __name__)




@auth.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        form_data = request.form
        parametersdict = {
            'mail': form_data['mail'],
            'password': form_data['password']
        }
        if not parametersdict['mail'] or not parametersdict['password'] or not parametersdict['mail'] and not \
                parametersdict['password']:
            
            #logging empty login fields
            logging.info('Empty login fields from IP: ' + request.environ.get('HTTP_X_REAL_IP', request.remote_addr))

            flash('gegevens zijn niet ingevult')
            return redirect('/login')

        user = UserLogin(parametersdict)
        if user is not None:

            #logging successful login
            logging.info('User with email: ' + parametersdict['mail'] + ' has logged in on IP: ' + request.environ.get('HTTP_X_REAL_IP', request.remote_addr))

            is_admin = check_is_admin(session['user_id'])
            session['is_admin'] = is_admin
            if is_admin is False:
                return redirect('/inquiry/research_list', 302)
            elif is_admin is True:
                return redirect('/admin', 302)
        else:

            #logging failed login
            logging.info('User with email: ' + parametersdict['mail'] + ' has failed to log in on IP: ' + request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
            flash('gegevens kloppen niet')
            
            return redirect('/login', 302)
    else:
        return render_template('auth/login.jinja')


@auth.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        form_data = request.form
        parametersdict = {
            'firstname': form_data['firstname'],
            'infix': form_data['infix'],
            'lastname': form_data['lastname'],

            #maakt een hash van een wachtwoord, en slaat deze uitendelijk op in de database
            'password': generate_password_hash(form_data['password']),
            
            'gender': form_data['gender'],
            'zipcode': form_data['zipcode'],
            'mail': form_data['mail'],
            'phonenumber': form_data['phonenumber'],
            'birthday': form_data['birthday'],
        }
        if parametersdict['gender'] == "":
            flash('er zijn 1 of meer verplichten velden niet ingevult')
            logging.info('Empty register fields from IP: ' + request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
            return redirect('/register')
        print(parametersdict.values())
        if not parametersdict['mail'] or not parametersdict['password'] or not parametersdict['mail'] and not \
                parametersdict['password']:
            flash('er zijn 1 of meer verplichten velden niet ingevult')
            logging.info('Empty register fields from IP: ' + request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
            return redirect('/register')
        user = checkUser(parametersdict)
        if user is not None:
            flash('gegevens bestaan al')
            return redirect('/register', 302)
        else:
            createUser(parametersdict)
            flash('gegevens zijn toegevoegd')
            logging.info('a new user has been created on the ip: ' + request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
            return redirect('/login', 302)
    else:
        return render_template('auth/register.jinja')


@auth.route("/logout")
def logout():
    session.clear()  # This clears all data in the session
    print('session clear')
    return redirect('/', 302)

from flask import Flask, render_template, request, Blueprint, session, redirect, flash
from models.model import *

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
            flash('gegevens zijn niet ingevult')
            return redirect('/login')

        user = UserLogin(parametersdict)
        # print("user")
        # print(user)
        if user is not None:
            print("gegevens kloppen")
            is_admin = check_is_admin(session['user_id'])
            session['is_admin'] = is_admin
            if is_admin is False:
                return redirect('/inquiry/research_list', 302)
            elif is_admin is True:
                return redirect('/admin', 302)
        else:
            print(user)
            print("gegevens kloppen niet")
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
            'password': form_data['password'],
            'gender': form_data['gender'],
            'zipcode': form_data['zipcode'],
            'mail': form_data['mail'],
            'phonenumber': form_data['phonenumber'],
            'birthday': form_data['birthday'],
        }
        if parametersdict['gender'] == "":
            flash('er zijn 1 of meer verplichten velden niet ingevult')
            return redirect('/register')
        print(parametersdict.values())
        if not parametersdict['mail'] or not parametersdict['password'] or not parametersdict['mail'] and not \
                parametersdict['password']:
            flash('er zijn 1 of meer verplichten velden niet ingevult')
            return redirect('/register')
        user = checkUser(parametersdict)
        if user is not None:
            flash('gegevens bestaan al')
            return redirect('/register', 302)
        else:
            createUser(parametersdict)
            flash('gegevens zijn toegevoegd')
            return redirect('/login', 302)
    else:
        return render_template('auth/register.jinja')


@auth.route("/logout")
def logout():
    session.clear()  # This clears all data in the session
    print('session clear')
    return redirect('/', 302)

from flask import request, session
import sqlite3
# from app import db


# class Company(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(50), nullable=False)
#     website = db.Column(db.String(255), nullable=False)
#     description = db.Column(db.String(500), nullable=False)  # warning over default varchar length
#     phonenumber = db.Column(db.Integer, nullable=False)
#     extradetails = db.Column(db.String(500), nullable=False)  # warning over default varchar length
#     mail = db.Column(db.String(120), unique=True, nullable=False)
#     user_id = db.Column(db.Integer, nullable=False)
#
#     def to_dict(self):
#         return { 'id': self.id, 'name': self.name, 'website': self.website, 'description': self.description, 'phonenumber': self.phonenumber, 'extradetails': self.extradetails, 'mail': self.mail, 'user_id': self.user_id }
#

def check_is_admin(user_id):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('SELECT is_admin FROM employees WHERE user_id = ? ',
                   (f"{user_id}",))
    value = cursor.fetchone()
    database.close()
    # print(value)
    if value is None:
        is_admin = False
    else:
        is_admin = True
    # print(is_admin)
    return is_admin


def getAllUsers():
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('SELECT * FROM user')
    rawUsers = cursor.fetchall()
    users = [dict(user) for user in rawUsers]
    database.close()
    return users


def UserLogin(data):
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('SELECT * FROM user WHERE mail = ? AND password = ? ',
                   (f"{data['mail']}", f"{data['password']}"))
    user = cursor.fetchone()
    database.close()
    # print("user: ")
    # print(user)
    if user is None:
        return None
    else:
        session['user_id'] = user['id']
        session['firstname'] = user['firstname']
        session['mail'] = user['mail']
        session['is_approved'] = user['is_approved']

    # print("session: ")
    # print(session)

    return user


def getOneUser(id):
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?',
                   (f"{id}",))
    user = cursor.fetchone()
    database.close()
    # print(user)
    return user


def checkUser(data):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('SELECT * FROM user WHERE mail = ? ',
                   (f"{data['mail']}",))
    user = cursor.fetchone()
    database.close()
    return user


def createUser(data):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute(
        'INSERT INTO user (firstname, infix, lastname, password, gender, zipcode, mail, phonenumber ,is_approved ,birthday) VALUES (?, ?, ?, ?, ?, ?, ?, ?, False, ?)',
        (f"{data['firstname']}", f"{data['infix']}", f"{data['lastname']}", f"{data['password']}", f"{data['gender']}",
         f"{data['zipcode']}", f"{data['mail']}", f"{data['phonenumber']}", f"{data['birthday']}",))
    database.commit()
    database.close()


def get_user_data():
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('SELECT * FROM user')
    user_list = cursor.fetchall()
    database.close()
    return user_list


def get_research_list():
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('''SELECT research.*, company.name, user.*
                    FROM research
                    LEFT JOIN company ON research.company_id = company.id
                    LEFT JOIN user ON research.field_expert_id = user.id
                    WHERE research.field_expert_id IS NULL
                     ''')
    researches = cursor.fetchall()
    database.close()
    return researches


def get_research_list_admin():
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('''SELECT research.*, company.name, user.*
                    FROM research
                    LEFT JOIN company ON research.company_id = company.id
                    LEFT JOIN user ON research.field_expert_id = user.id
                     ''')
    researches = cursor.fetchall()
    database.close()
    return researches


def get_rejected_research_list(id):
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('''SELECT research.*, company.name, user.*, status.status
                    FROM research
                    LEFT JOIN company ON research.company_id = company.id
                    LEFT JOIN user ON research.field_expert_id = user.id
                    LEFT JOIN status ON research.id = status.id
                    WHERE status.status = "afgekeurd"
                    AND research.field_expert_id = ?
                     ''' , (f"{id}",))
    researches = cursor.fetchall()
    database.close()
    return researches


def get_my_research_list():
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('''SELECT research.*, company.name, user.*, status.status
                    FROM research
                    LEFT JOIN company ON research.company_id = company.id
                    LEFT JOIN user ON research.field_expert_id = user.id
                    LEFT JOIN status ON research.id = status.id
                    WHERE status.status = "in afwachting" OR status.status = "goedgekeurd"
                    AND research.field_expert_id = ?
                   ''', (f"{session['user_id']}",))
    my_registered_researches_list = cursor.fetchall()
    database.close()
    return my_registered_researches_list


def get_user_count():
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('SELECT COUNT(*) FROM user')
    user_count = cursor.fetchone()
    database.close()
    return user_count


def get_research_count():
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('SELECT COUNT(*) FROM research')
    research_count = cursor.fetchone()
    database.close()
    return research_count


def research_sign_out(research_id):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('UPDATE research SET field_expert_id = NULL WHERE id = ?', (f"{research_id}",))
    cursor.execute('UPDATE status SET status = "nieuw" WHERE id = ?', (f"{research_id}",))
    database.commit()
    database.close()


def research_sign_up(research_id):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('UPDATE research SET field_expert_id = ? WHERE id = ?', (f"{session['user_id']}", f"{research_id}"))
    cursor.execute('UPDATE status SET status = "in afwachting" WHERE id = ?', (f"{research_id}",))
    database.commit()
    database.close()


def get_research_status():
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('SELECT * FROM status')
    research_status = cursor.fetchall()
    database.close()
    return research_status


def get_research_signup_requests():
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute('''SELECT research.*, status.status, user.firstname, user.infix, user.lastname, user.zipcode, user.gender, user.mail, user.phonenumber 
                   FROM research 
                   JOIN status ON research.id = status.id 
                   JOIN user ON research.field_expert_id = user.id''')
    research_signup_requests = cursor.fetchall()
    database.close()
    return research_signup_requests


def get_research_signup_requests_count():
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute('''SELECT COUNT(*) FROM research 
                   JOIN status ON research.id = status.id 
                   WHERE status.status = "in afwachting"''')
    research_signup_requests_count = cursor.fetchone()
    database.close()
    return research_signup_requests_count


def get_research_signup_request(id):
    database = sqlite3.connect("database/wp3.db")
    database.row_factory = sqlite3.Row
    cursor = database.cursor()
    cursor.execute(f'''SELECT research.*, status.status, user.firstname, user.infix, user.lastname, user.zipcode, user.gender, user.mail, user.phonenumber, company.name 
                   FROM research 
                   JOIN company ON research.company_id = company.id
                   JOIN status ON research.id = status.id 
                   JOIN user ON research.field_expert_id = user.id WHERE research.id = {id}''')
    research_signup_request = cursor.fetchall()
    database.close()
    return research_signup_request


def setOneUser(id):
    firstname = request.form.get('firstname')
    infix = request.form.get('infix')
    lastname = request.form.get('lastname')
    password = request.form.get('password')
    zipcode = request.form.get('zipcode')
    gender = request.form.get('gender')
    mail = request.form.get('mail')
    phonenumber = request.form.get('phonenumber')
    birthday = request.form.get('birthday')
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute("UPDATE user SET firstname = ?, infix = ?, lastname = ?, password = ?, zipcode = ?, gender = ?, mail = ?, phonenumber = ?, birthday = ? WHERE id = ?",
                   (firstname, infix, lastname, password, zipcode, gender, mail, phonenumber, birthday, id))
    database.commit()
    cursor.close()


def deleteUser(id):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute("DELETE FROM user WHERE id = ?", (id,))
    database.commit()
    cursor.close()


def change_research_signup_request(id, status):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute("UPDATE status SET status = ? WHERE id = ?", (status, id))
    database.commit()
    cursor.close()


def reset_research_user(research_id):
    database = sqlite3.connect("database/wp3.db")
    cursor = database.cursor()
    cursor.execute("UPDATE research SET field_expert_id = NULL WHERE id = ? AND field_expert_id = ?", (research_id,session["user_id"]))
    database.commit()
    cursor.close()

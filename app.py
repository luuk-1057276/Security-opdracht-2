from flask import Flask, redirect, url_for, render_template, request, session, request, Blueprint, jsonify
from models.SQLalchemy import db
from routes.admin import admin
from routes.api import api
from routes.auth import auth
from routes.inquiry import inquiry
import os
file_path = os.path.abspath(os.getcwd())+"/database/wp3.db"

app = Flask(__name__, template_folder='templates')
app.secret_key = 'wp3'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + file_path  # Use your SQLite database file path
db.init_app(app)

with app.app_context():
    db.create_all()
    
# get current path
print(os.path.dirname(os.path.abspath(__file__)))

app.register_blueprint(admin, url_prefix='/admin')
app.register_blueprint(api, url_prefix='/api')
app.register_blueprint(auth)
app.register_blueprint(inquiry, url_prefix='/inquiry')

# # ! debug mode staat aan maar werkt niet dus weghalen
# environ["FLASK_DEBUG"] = '1'


@app.route("/")
def index():
    return redirect(url_for('auth.login'))


@app.template_filter('add_line_breaks')
def add_line_breaks(text):
    return text.replace('\n', ' ')


@app.route("/my_account")
def my_account():
    return render_template("user/my_account.jinja")


if __name__ == "__main__":
    app.run(port=5000, debug=True)

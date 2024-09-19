from flask import Flask, render_template, request, Blueprint, session, redirect, flash
from models.model import *

app = Flask(__name__)
inquiry = Blueprint('inquiry', __name__)


@inquiry.route("/", methods=['POST', 'GET'])
def home():
    return render_template("temp_index.jinja")

@inquiry.route("/research_list", methods=["GET", "POST"])
def research_list():
    sign_up_research = request.form.get("research_sign_up")
    research_sign_up(sign_up_research)
    researches = get_research_list()
    return render_template("inquiry/research_list.jinja", researches=researches)

@inquiry.route("/my_registered_researches", methods=["GET", "POST"])
def my_registered_researches():
    my_registered_researches = get_my_research_list()
    sign_out_research = request.form.get("research_sign_out")
    if sign_out_research != None:
        research_sign_out(sign_out_research)
        return redirect("/inquiry/my_registered_researches")
    return render_template("inquiry/my_registered_researches.jinja", researches=my_registered_researches)


@inquiry.route("/rejected_researches", methods = ["GET", "POST"])
def rejected_researches():
    rejected_research_list = get_rejected_research_list(session["user_id"])
    reset_research_user_id = request.form.get("reset_research_user")
    if reset_research_user_id != None:
        reset_research_user(reset_research_user_id)
        return redirect("/inquiry/rejected_researches")
    return render_template("inquiry/rejected_researches.jinja", researches=rejected_research_list)

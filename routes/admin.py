from flask import Flask, render_template, request, Blueprint, session, redirect, flash, jsonify
from models.model import *

app = Flask(__name__)
admin = Blueprint('admin', __name__)

researches_to_approve = [
    {"id": 1,
     "title": "title1",
     "organisation": "organisation1",
     "type": "op locatie",
     "available_from": "20 februari",
     "available_until": "28 februari",
     "description": "een tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de websiteeen tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de website een tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de websiteeen tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de website",
     "target": "blinden"},
    {"id": 2,
     "title": "title2",
     "organisation": "organisation2",
     "type": "videobellen",
     "available_from": "10 november",
     "available_until": "15 november",
     "description": "een tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de website",
     "target": "doven"},
    {"id": 3,
     "title": "title3",
     "organisation": "organisation3",
     "type": "videobellen",
     "available_from": "1 maart",
     "available_until": "9 maart",
     "description": "een tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de website",
     "target": "dysexie"},
    {"id": 4,
     "title": "title4",
     "organisation": "organisation3",
     "type": "videobellen",
     "available_from": "1 maart",
     "available_until": "9 maart",
     "description": "een tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de website",
     "target": "blinden"},
    {"id": 5,
     "title": "title5",
     "organisation": "organisation3",
     "type": "videobellen",
     "available_from": "1 maart",
     "available_until": "9 maart",
     "description": "een tijdelijke beschrijving die gaat veranderen als we een database hebben. Heel deze lijst gaat weg als we een database hebben, maar voor nu heb ik een placeholder nodig om het mooie systeem te testen wat de onderzoeken laat zien op de website",
     "target": "doven"}]


research_count = get_research_count()
user_count = get_user_count()


#routes voor ajax
@admin.route("/update_dashboard", methods=["GET", "POST"])
def update_dashboard():
    research_count = get_research_count()
    user_count = get_user_count()
    research_signup_request_count = get_research_signup_requests_count()
    return jsonify({'research_count': research_count[0], 'user_count': user_count[0], 'research_signup_request_count': research_signup_request_count[0]})

@admin.route("/update_approve_research_requests", methods=["GET", "POST"])
def update_approve_research_requests():
    research_signup_requests = get_research_signup_requests()
    research_signup_requests_dicts = [dict(row) for row in research_signup_requests]
    print(research_signup_requests_dicts[0])
    return jsonify({'research_signup_requests': research_signup_requests_dicts})




@admin.route("/")
def admin_dashboard():
    research_signup_request_count = get_research_signup_requests_count()
    print(research_signup_request_count)
    return render_template("admin/admin_dashboard.jinja",user_count = user_count, research_count = research_count, research_signup_request_count = research_signup_request_count)


@admin.route("/list_of_users")
def users_overview():
    users = getAllUsers()
    for user in users:
        user['is_admin'] = check_is_admin(user['id'])
    return render_template("admin/list_of_users.jinja", users=users)


@admin.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    deleteUser(user_id)
    return redirect('/admin/list_of_users')


@admin.route("/edit_user/<int:user_id>", methods=('GET', 'POST'))
def update_user(user_id):
    if request.method == 'POST':
        setOneUser(user_id)
        flash('gebruiker is geupdate', 'success')
        return redirect('/admin/list_of_users')
    return render_template('admin/edit_user.jinja', user=getOneUser(user_id))


@admin.route("/register_requests")
def register_requests():
    # Johnty ga werken!!!
    # groetjes Johnty op Luuk zijn laptop
    return render_template("admin/register_requests.jinja")


@admin.route("/approve_research", methods=["GET", "POST"])
def approve_research():
    approved_research = request.form.get("approved_research")
    rejected_research = request.form.get("rejected_research")
    research_signup_request_count = get_research_signup_requests_count()
    return render_template("admin/approve_research.jinja", researches_to_approve=researches_to_approve, research_signup_request_count = research_signup_request_count)


@admin.route("/approve_research_requests", methods=["GET", "POST"])
def approve_research_requests():
    research_signup_requests = get_research_signup_requests()
    research_id = request.form.get("research_id")
    if research_id is not None:
        return redirect(f"/admin/approve_research_requests/{research_id}")
    return render_template("admin/approve_research_requests.jinja", research_signup_requests=research_signup_requests)

@admin.route("/approve_research_requests/<id>", methods=["GET", "POST"])
def approve_research_request(id):
    research_signup_request = get_research_signup_request(id)
    change_status = request.form.get("change_status")
    if change_status is not None:
        change_research_signup_request(id, change_status)
        return redirect("/admin/approve_research_requests")
    return render_template("admin/approve_research_request.jinja", research_signup_request = research_signup_request)


@admin.route("/list_of_researches", methods=["GET", "POST"])
def manage_researches():
    delete_research = request.form.get("delete_research")
    researches = get_research_list_admin()
    research_signup_request_count = get_research_signup_requests_count()
    return render_template("admin/list_of_researches.jinja", researches = researches, research_signup_request_count = research_signup_request_count)

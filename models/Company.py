# This file contains the model for the Company object
from flask_sqlalchemy import SQLAlchemy
from .SQLalchemy import db


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    website = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(500), nullable=False) # warning over default varchar length
    contact_user = db.Column(db.Integer, nullable=False)
    phonenumber = db.Column(db.Integer, nullable=False)
    extradetails = db.Column(db.String(500), nullable=False)  # warning over default varchar length
    mail = db.Column(db.String(120), unique=True, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def to_dict(self):
        return { 'id': self.id, 'name': self.name, 'website': self.website, 'description': self.description, 'phonenumber': self.phonenumber, 'extradetails': self.extradetails, 'mail': self.mail, 'user_id': self.user_id }



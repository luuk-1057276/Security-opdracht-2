from flask import Blueprint, jsonify, request
from models.Company import Company
from models.SQLalchemy import db


api = Blueprint('api', __name__)


@api.route('/companies', methods=['GET'])
def get_companies():
    companies = Company.query.all()  # Get all companies from the database
    return jsonify([company.to_dict() for company in companies])  # Convert companies to JSON


@api.route('/companies/<int:company_id>', methods=['GET'])
def get_company(company_id):
    company = Company.query.get(company_id)  # Get a specific company
    if company is None:
        return jsonify({'error': 'Company not found'}), 404
    return jsonify(company.to_dict())  # Convert company to JSON


@api.route('/companies', methods=['POST'])
def create_company():
    # why no work
    data = request.get_json()  # Get the request data
    company = Company(**data)  # Create a new company
    db.session.add(company)
    db.session.commit()
    return jsonify(company.to_dict()), 201  # Return the new company


@api.route('/companies/<int:company_id>', methods=['PUT'])
def update_company(company_id):
    data = request.get_json()  # Get the request data
    company = Company.query.get(company_id)  # Get the specific company
    if company is None:
        return jsonify({'error': 'Company not found'}), 404
    for key, value in data.items():
        setattr(company, key, value)
    db.session.commit()
    return jsonify(company.to_dict())  # Return the updated company


@api.route('/companies/<int:company_id>', methods=['DELETE'])
def delete_company(company_id):
    company = Company.query.get(company_id)  # Get the specific company
    if company is None:
        return jsonify({'error': 'Company not found'}), 404
    db.session.delete(company)  # Delete the company
    db.session.commit()
    return jsonify({'message': 'Company deleted'})
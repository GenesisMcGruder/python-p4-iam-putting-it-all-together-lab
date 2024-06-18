#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):

        data = request.get_json()
        
        if 'username' not in data:
            return {'error': 'Username is required'}, 422
        user = User(
            username=data['username'],
            image_url = data['image_url'],
            bio = data['bio']
        )
        
        user.password_hash = data['password']

        db.session.add(user)
        db.session.commit()
        # breakpoint()
        user_dict = user.to_dict()

        response = make_response(
            user_dict,
            201
        )
        
        return response
            
            

class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get('user_id')).first()
        if user:
            user_dict = user.to_dict()
            response = make_response(
                jsonify(user_dict),
                200
            )
            return response
        else:
            return {'error': 'Not logged in'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        user = User.query.filter_by(username=username).first()

        password = data.get('password')

        try:
            if user.authenticate(password):
                session['user_id'] = user.id
                user_dict = user.to_dict()
                response = make_response(
                    jsonify(user_dict),
                    200
                )
                return response
        except Exception as e:
            response = make_response(
                {'error': 'Invalid credentials'},
                401
            )
            return response

class Logout(Resource):
    def delete(self):
        user = User.query.filter(User.id== session.get('user_id')).first()
        if user:
            session['user_id'] = None
            return {}, 204
        else:
            return {'error':'No user to signout'}, 401

class RecipeIndex(Resource):
    def get(self):

        recipes = [recipe.to_dict() for recipe in Recipe.query.all()]
        
        user = User.query.filter(User.id == session.get('user_id')).first()

        if user:
            response = make_response(
                jsonify(recipes),
                200
            )
            return response
        else:
            return {'error': 'Please login'}, 401

    def post(self):
        user = User.query.filter(User.id == session.get('user_id')).first()
        data = request.get_json()
        
        if user:
            new_recipe = Recipe(
                title= data['title'],
                instructions= data['instructions'],
                minutes_to_complete = data['minutes_to_complete'],
                user_id= user.id
            )
            if len(new_recipe.instructions) >= 50:
                db.session.add(new_recipe)
                db.session.commit()
                response = make_response(
                    jsonify(new_recipe.to_dict()),
                    201
                )
                return response
            else:
                return {'error': 'Instructions must be 50 characters or more.'}, 422
        else:
            return {'error': 'Please login'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
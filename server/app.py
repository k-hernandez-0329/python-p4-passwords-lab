#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api, bcrypt
from models import User


class ClearSession(Resource):
    def delete(self):
        session["page_views"] = None
        session["user_id"] = None

        return {}, 204


class Signup(Resource):
    def post(self):
        json_data = request.get_json()

        username = json_data.get("username")
        password = json_data.get("password")

        if not username or not password:
            return {"error": "Username and password are required"}, 400

        hashed_password = bcrypt.generate_password_hash(
            password.encode("utf-8")
        ).decode("utf-8")

        new_user = User(username=username, _password_hash=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        session["user_id"] = new_user.id

        return new_user.to_dict(), 201

    # def post(self):
    #     json = request.get_json()
    #     user = User(username=json["username"], password_hash=json["password"])
    #     db.session.add(user)
    #     db.session.commit()
    #     return user.to_dict(), 201


class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get("user_id")).first()
        if user:
            return user.to_dict()
        else:
            return {}, 204


class Login(Resource):
    def post(self):
        json_data = request.get_json()

        username = json_data.get("username")
        password = json_data.get("password")

        if not username or not password:
            return {"error": "Username and password are required"}, 400

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200
        else:
            return {"error": "Invalid username or password"}, 401

    # def post(self):
    #     username = request.get_json()["username"]
    #     user = User.query.filter(User.username == username)

    #     password = request.get_json()["password"]
    #     if password == user.password:
    #         session["user_id"] = user.user.id
    #         return user.to_dict(), 200

    #     return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        session["user_id"] = None
        return {"message": "Logout successful"}, 204


api.add_resource(ClearSession, "/clear", endpoint="clear")
api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")

if __name__ == "__main__":
    app.run(port=5555, debug=True)

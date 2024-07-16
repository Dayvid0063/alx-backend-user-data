#!/usr/bin/env python3
"""Module for authentication"""


import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a psswrd"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Gets a UUID"""
    return str(uuid4())


class Auth:
    """Class to interact with the auth BD"""

    def __init__(self):
        """Initializes Auth instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Adds a new user to the DB"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Verifies user login details are valid"""
        u = None
        try:
            u = self._db.find_user_by(email=email)
            if u is not None:
                return bcrypt.checkpw(
                    password.encode("utf-8"),
                    u.hashed_password,
                )
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Creates user new session"""
        u = None
        try:
            u = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if u is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(u.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets user based on a given session ID"""
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates user psswrd given the user's reset token"""
        u = None
        try:
            u = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            u = None
        if u is None:
            raise ValueError()
        new_password_hash = _hash_password(password)
        self._db.update_user(
            u.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )

    def get_reset_password_token(self, email: str) -> str:
        """Gets a psswrd reset token for user"""
        u = None
        try:
            u = self._db.find_user_by(email=email)
        except NoResultFound:
            u = None
        if u is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(u.id, reset_token=reset_token)
        return reset_token

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session associated with a given user"""
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

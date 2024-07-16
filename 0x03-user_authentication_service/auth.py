#!/usr/bin/env python3
"""Module for authentication"""


import bcrypt
from typing import Union
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import TypeVar

from db import DB
from user import User

U = TypeVar(User)


def _hash_password(password: str) -> bytes:
    """Hashes a psswrd"""
    psswrd = password.encode('utf-8')
    return bcrypt.hashpw(psswrd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """Gets a UUID"""
    return str(uuid4())


class Auth:
    """Class to interact with the auth DB"""

    def __init__(self) -> None:
        """Initializes Auth instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Adds user to the DB"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed = _hash_password(password)
            usr = self._db.add_user(email, hashed)
            return usr
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Verifies if user login details are valid"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_psswrd = user.hashed_password
        psswrd = password.encode("utf-8")
        return bcrypt.checkpw(psswrd, user_psswrd)

    def create_session(self, email: str) -> Union[None, str]:
        """Creates a new session for a user"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[None, U]:
        """Gets user based on a given session ID"""
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session associated with a user"""
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Gets psswrd reset token for a user"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates user psswrd given the user's reset token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError()

        hashed = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)

#!/usr/bin/env python3
""" Use the bcrypt package to perform the hashing (with hashpw)
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """ Salted pass generation
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ is valid?
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

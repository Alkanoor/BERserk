import hashlib

class Generator():

    @classmethod
    def digest(cls, message):
        return hashlib.sha256(message).hexdigest()

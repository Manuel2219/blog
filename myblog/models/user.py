from myblog import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.Text)
    tipoUsuario=db.Column(db.Text)

    def __init__(self, username, password,tipoUsuario) -> None:
        self.username = username
        self.password = password
        self.tipoUsuario=tipoUsuario

    def __repr__(self) -> str:
        return f'User: {self.username}'
from flask_login import UserMixin
import secrets

class IAModels(object):
    def __init__(self, db):
        self.db = db
        self._make_models()
    
    def _make_models(self):
        db = self.db

        # Define classes
        class User(UserMixin, db.Model):
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String, unique=True, nullable=False)
            email = db.Column(db.String)
            phone = db.Column(db.String)
            address = db.Column(db.String)
            password_hash = db.Column(db.String)
            role = db.Column(db.String)
            role_interest = db.Column(db.Integer, default=0)
            enabled = db.Column(db.Boolean)

            @property
            def data_columns(self):
                return [self.username, self.email, self.role, self.role_interest, self.enabled]

            @property
            def data_headers(self):
                return ('Username', 'Email', 'Role', 'Level', 'Enabled')

            @property
            def admin_actions(self):
                return [
                    (f"/user/enable/{self.id}", 'bi bi-app'),
                    (f"/user/remove/{self.id}", 'bi bi-x-circle')
                ]
        self.User = User

        class Role(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String, unique=True, nullable=False)
        self.Role = Role

        class RoleRegistration(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
            role_id = db.Column(db.Integer, db.ForeignKey("role.id"))
        self.RoleRegistration = RoleRegistration

        class APIKey(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            key = db.Column(
                db.String, unique=True, nullable=False,
                default= lambda: secrets.token_urlsafe(32) #TODO get size from IAM config
            )
            user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
            expiration = db.Column(db.DateTime)
        self.APIKey = APIKey

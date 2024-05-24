from flask_login import UserMixin

class IAModels(object):
    def __init__(self, db):
        self.db = db
        self._make_models()
    
    def _make_models(self):
        class User(UserMixin, self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            username = self.db.Column(self.db.String, unique=True, nullable=False)
            email = self.db.Column(self.db.String)
            phone = self.db.Column(self.db.String)
            address = self.db.Column(self.db.String)
            password_hash = self.db.Column(self.db.String)
            role = self.db.Column(self.db.String)
            role_interest = self.db.Column(self.db.Integer, default=0)
            enabled = self.db.Column(self.db.Boolean)

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

        class Role(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            name = self.db.Column(self.db.String, unique=True, nullable=False)
        self.Role = Role

        class RoleRegistration(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            user_id = self.db.Column(self.db.Integer, self.db.ForeignKey("user.id"))
            role_id = self.db.Column(self.db.Integer, self.db.ForeignKey("role.id"))
        self.RoleRegistration = RoleRegistration


def create_app(run=False):
    import os
    from flask import Flask, redirect
    from flask_fefset import FEFset
    from flask_iam import IAM
    from flask_uxfab import UXFab
    from flask_sqlalchemy import SQLAlchemy
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config['SECRET_KEY'] = os.urandom(12).hex() # to allow csrf forms
    db = SQLAlchemy()
    fef = FEFset(frontend='bootstrap4', role_protection=True)
    fef.init_app(app)
    db.init_app(app)
    uxf = UXFab()
    uxf.init_app(app)
    iam = IAM(db)
    iam.init_app(app)
    with app.app_context():
        db.create_all()
    @app.route('/')
    def index():
        return redirect('/auth/user/add')

    return app


# flask imports
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField, SelectField, BooleanField
from wtforms.validators import InputRequired, DataRequired, Optional, Email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from http import HTTPStatus
import phonenumbers
from flask_iam.models import IAModels

class IAM:
    class LoginForm(FlaskForm):
        username = StringField('Username', validators=[InputRequired()])
        password = PasswordField('Password', validators=[InputRequired()])
        submit = SubmitField()

    class RegistrationForm(FlaskForm):
        username = StringField('Username', validators=[InputRequired()])
        email = EmailField('Email', validators=[InputRequired(), Email()], description='''
            Email is only used for site administration, and not shared with 3rd parties.
        ''')
        password = PasswordField('Password', validators=[InputRequired()])
        submit = SubmitField()

    class RoleForm(FlaskForm):
        name = StringField('Role name', validators=[InputRequired()])
        submit = SubmitField()

    class RoleAssignForm(FlaskForm):
        user = SelectField('User')
        role = SelectField('Role')
        submit = SubmitField()

    class ProfileForm(FlaskForm):
        username = StringField('Username', validators=[InputRequired()])
        email = EmailField('Email', validators=[InputRequired(), Email()], description='''
            Email is only used for site administration
            and confirmation of orders.
        ''')
        phone = StringField('Phone', validators=[Optional()],
            description='Optional, if you prefer being contacted by phone.'
        )
        address = StringField('Address', validators=[Optional()],
            description='Optional, if you require deliverable goods from here.'
        )
        old_password = PasswordField('Current password', validators=[Optional()])
        new_password = PasswordField('New password', validators=[Optional()])
        submit = SubmitField('Update profile')

        def validate_phone(self, phone):
            try:
                p = phonenumbers.parse(phone.data)
                if not phonenumbers.is_valid_number(p):
                    raise ValueError()
            except (phonenumbers.phonenumberutil.NumberParseException, ValueError):
                raise ValidationError('Invalid phone number. Provide with country code, e.g. "+32..."')

        def validate_old_password(self, old_password):
            if not check_password_hash(current_user.password_hash, old_password.data):
                raise ValidationError('This is not the user you are looking for')

    def __init__(self, app, db, url_prefix='/auth'):
        self.app = app
        self.db = db
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)

        self.models = IAModels(db)

        @self.login_manager.user_loader
        def load_user(user_id):
            return self.models.User.query.get_or_404(user_id)
        self.login_manager.login_view = 'iam_blueprint.read_login'
        self.blueprint = Blueprint(
            'iam_blueprint', __name__,
            url_prefix=url_prefix,
            template_folder='templates'
        )

        self.blueprint.add_url_rule("/", 'iam', view_func=self.iam_index, methods=['GET'])
        self.blueprint.add_url_rule("/user/add", 'register', view_func=self.add_user, methods=['GET','POST'])
        self.blueprint.add_url_rule("/user/login", 'login', view_func=self.login_user, methods=['GET','POST'])
        self.blueprint.add_url_rule("/user/logout", 'logout', view_func=self.logout_user, methods=['GET','POST'])
        self.blueprint.add_url_rule("/role/add", 'add_role', view_func=self.add_role, methods=['GET','POST'])
        self.blueprint.add_url_rule("/role/assign", 'assign_role', view_func=self.assign_role, methods=['GET','POST'])
        app.register_blueprint(
            self.blueprint, url_prefix=url_prefix
        )

    def iam_index(self):
        return render_template('IAM/index.html')

    def add_role(self):
        return ''

    def assign_role(self):
        return ''

    def add_user(self):
        form = self.RegistrationForm()
        if form.validate_on_submit():
            first_user = not bool(self.models.User.query.all())
            new_user = self.models.User(
                username=form.username.data,
                email=form.email.data,
                password_hash=generate_password_hash(form.password.data),
                role='admin' if first_user else 'viewer',
                enabled=first_user #if too many users disable
            )

            self.db.session.add(new_user)
            self.db.session.commit()

            flash("User was created")

            return render_template('IAM/registration_success.html') #redirect('/')
        return render_template('IAM/form.html', form=form, title='Register')

    def login_user(self):
        form = self.LoginForm()
        if form.validate_on_submit():
            # Login and validate the user.
            # user should be an instance of your `User` class
            user = self.models.User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password_hash, form.password.data):
                    login_user(user)#, remember=form.remember.data)
                    flash('Logged in successfully.')
                    next = request.args.get('next')
                    # is_safe_url should check if the url is safe for redirects.
                    # See http://flask.pocoo.org/snippets/62/ for an example.
                    #if not is_safe_url(next):
                    #    return flask.abort(400)
                    return redirect(next or '/')
        return render_template('IAM/login.html', form=form, title='Login')

    def logout_user(self):
        logout_user()
        return redirect('/')

    # Profile page
    @login_required
    def profile(self):
        form = self.ProfileForm(obj=current_user)
        if form.validate_on_submit():
            form.populate_obj(current_user)
            if form.old_password.data and form.new_password.data:
                current_user.password_hash = generate_password_hash(
                    form.new_password.data
                )
            self.db.session.commit()
        return render_template('IAM/form.html', form=form, title='Profile')    

    # Admin page
    @login_required
    def admin(self):
        if current_user.role != 'admin':
            abort(HTTPStatus.UNAUTHORIZED)
        users = self.models.User.query.all()
        return render_template('IAM/list.html', items=users, title=f"User list")

    @login_required
    def enabler(self,userid):
        if current_user.role != 'admin':
            abort(HTTPStatus.UNAUTHORIZED)
        user = self.models.User.query.get_or_404(userid)
        user.enabled = True
        self.db.session.commit()
        return redirect('/user/admin')

    @login_required
    def remove_user(self,userid):
        if current_user.role != 'admin':
            abort(HTTPStatus.UNAUTHORIZED)
        user = self.models.User.query.get_or_404(userid)
        self.db.session.delete(user)
        self.db.session.commit()
        return redirect('/user/admin')


if __name__ == '__main__':
    import os
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config['SECRET_KEY'] = os.urandom(12).hex() # to allow csrf forms
    db = SQLAlchemy()
    db.init_app(app)
    iam = IAM(app, db)
    with app.app_context():
        db.create_all()
    @app.route('/')
    def index():
        return redirect('/auth')
    app.run(host='0.0.0.0')

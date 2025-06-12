# flask imports
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import Blueprint, request, render_template, redirect, url_for, flash, abort, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField, SelectField, BooleanField
from wtforms.validators import InputRequired, DataRequired, Optional, Email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from http import HTTPStatus
from flask_iam.models import IAModels
from flask_iam.utils import root_required, role_required

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
        user_id = SelectField('User')
        role_id = SelectField('Role')
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
            import phonenumbers
            try:
                p = phonenumbers.parse(phone.data)
                if not phonenumbers.is_valid_number(p):
                    raise ValueError()
            except (phonenumbers.phonenumberutil.NumberParseException, ValueError):
                raise ValidationError('Invalid phone number. Provide with country code, e.g. "+32..."')

        def validate_old_password(self, old_password):
            if not check_password_hash(current_user.password_hash, old_password.data):
                raise ValidationError('This is not the user you are looking for')

    def __init__(self, db, app=None, url_prefix='/auth', root_role='admin'):
        self.db = db
        self.url_prefix = url_prefix
        self.root_role = root_role
        self.login_manager = LoginManager()
        self.models = IAModels(db)

        @self.login_manager.user_loader
        def load_user(user_id):
            return self.models.User.query.get_or_404(user_id)
        self.login_manager.login_view = 'iam_blueprint.login'
        self.blueprint = Blueprint(
            'iam_blueprint', __name__,
            url_prefix=self.url_prefix,
            template_folder='templates'
        )

        self.blueprint.add_url_rule("/", 'iam', view_func=self.iam_index, methods=['GET'])
        self.blueprint.add_url_rule("/user/add", 'register', view_func=self.add_user_form, methods=['GET','POST'])
        self.blueprint.add_url_rule("/api/user/add", 'api_register', view_func=self.add_user_api, methods=['POST'])
        self.blueprint.add_url_rule("/user/login", 'login', view_func=self.login_user_form, methods=['GET','POST'])
        self.blueprint.add_url_rule("/user/logout", 'logout', view_func=self.logout_user, methods=['GET','POST'])
        self.blueprint.add_url_rule("/api/user/login", 'api_login', view_func=self.login_user_api, methods=['GET','POST'])
        self.blueprint.add_url_rule("/role/add", 'add_role', view_func=self.add_role, methods=['GET','POST'])
        self.blueprint.add_url_rule("/role/assign", 'assign_role', view_func=self.assign_role, methods=['GET','POST'])
        self.blueprint.add_url_rule("/admin", 'admin' , view_func=self.admin, methods=['GET'])
        self.blueprint.add_url_rule("/api/key/get", 'get_api_key', view_func=self.get_api_key, methods=['GET','POST'])

    def init_app(self, app):
        app.extensions['IAM'] = self # link for decorator access
        self.login_manager.init_app(app)
        app.register_blueprint(
            self.blueprint, url_prefix=self.url_prefix
        )
        # Set menu
        if 'fefset' in app.extensions:
            fef = app.extensions['fefset']
            fef.settings['side_menu_name_function'] = self.side_menu_name #'Account'
            fef.add_side_menu_entry('Login', f"{self.url_prefix}/user/login", role=None)#url_for('iam_blueprint.login'))        
            fef.add_side_menu_entry('Register', f"{self.url_prefix}/user/add", role=None)#url_for('iam_blueprint.register'))
            fef.add_side_menu_entry('Logout', f"{self.url_prefix}/user/logout", role=True)
            fef.add_side_menu_entry('Admin', f"{self.url_prefix}/", role=self.root_role)
            self.headless = False
        else:
            app.logger.warning(
                'No frontend available, operating in headless mode.'
                'If this is unintended, be sure to init "fefset" before "IAM" extension'
            )
            self.headless = True

    def side_menu_name(self):
        return f"Hi, {current_user}" if current_user.is_authenticated else 'Account'

    @root_required
    def iam_index(self):
        return render_template('IAM/index.html')

    def add_user(self, username, email, password):
        first_user = not bool(self.models.User.query.all())
        new_user = self.models.User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=self.root_role if first_user else 'viewer',
            enabled=first_user #if too many users disable
        )
        
        self.db.session.add(new_user)
        self.db.session.commit()
    
    def add_user_form(self):
        form = self.RegistrationForm()
        if form.validate_on_submit():
            self.add_user(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data,
            )
            flash("User was created")

            return render_template('IAM/registration_success.html') #redirect('/')
        return render_template('uxfab/form.html', form=form, title='Register')
    
    def add_user_api(self):
        """
        API call route to add users.
        First user gets admin rights.

        Example:
          >>> import requests
          >>> r = requests.post(
          ...   'http://localhost:5000/auth/api/user/add',
          ...   json={'username':'admin',
          ...   'email':'admin@admin.be','password':'admin'}
          ... )
        
        """
        data = request.get_json()  # Get JSON data from the API call
        
        if data:  # Ensure data is provided
            # Check if the required fields are present in the JSON
            if 'username' in data and 'email' in data and 'password' in data:
                self.add_user(
                    username=data['username'],
                    email=data['email'],
                    password=data['password']
                )
                
                # Return a JSON success message
                return jsonify({"message": "User was created successfully", "status": "success"}), 201
            else:
                # Return an error message if fields are missing
                return jsonify({"message": "Missing required fields", "status": "error"}), 400
        else:
            # Return an error message if no JSON data is provided
            return jsonify({"message": "Invalid request: No JSON data", "status": "error"}), 400
    
    @root_required
    def add_role(self):
        form = self.RoleForm()
        if form.validate_on_submit():
            new_role = self.models.Role()
            form.populate_obj(new_role)
            self.db.session.add(new_role)
            self.db.session.commit()

            flash("Role was created")

            return redirect(url_for('iam_blueprint.iam'))
        return render_template('uxfab/form.html', form=form, title='Add role')

    @root_required
    def assign_role(self):
        form = self.RoleAssignForm()
        form.role_id.choices = [(r.id, r) for r in self.models.Role.query.all()]
        form.user_id.choices = [(r.id, r) for r in self.models.User.query.all()]
        if form.validate_on_submit():
            new_role_registration = self.models.RoleRegistration()
            form.populate_obj(new_role_registration)
            self.db.session.add(new_role_registration)
            self.db.session.commit()

            flash("Role was assigned")

            return redirect(url_for('iam_blueprint.iam'))
        return render_template('uxfab/form.html', form=form, title='Assign role')

    def login_user(self, username, password):
        user = self.models.User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password_hash, password):
                login_user(user)#, remember=form.remember.data)
                return True
        abort(404)

    def login_with_key(self, api_key):
        key = self.models.APIKey.query.filter_by(key=api_key).first()
        if key:
            login_user(self.models.User.query.get_or_404(key.user_id))
            return True
        abort(404)
        
    def login_user_form(self):
        form = self.LoginForm()
        if form.validate_on_submit():
            # Login and validate the user.
            # user should be an instance of your `User` class
            user_login_success = self.login_user(
                username = form.username.data,
                password = form.password.data
            )
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

    def login_user_api(self):
        """
        Important to work with sessions.
        Example login with key, but user/password works also.

        Example:
          >>> import requests
          >>> session = requests.Session()
          >>> session.post(
          ...   'http://localhost:5000/auth/api/user/login',
          ...   json={'key':key}
          ...   #or: json={'username':...,'password':...}
          ... )

        Continue with this session for your `post` or `get` calls.
        """
        data = request.get_json()
        
        if data:  # Ensure data is provided
            # Check if the required fields are present in the JSON
            if 'username' in data and 'password' in data:
                user_login_success = self.login_user(
                    username=data['username'],
                    password=data['password']
                )
                
                # Return a JSON success message
                return jsonify({"message": "User was logged in successfully", "status": "success"}), 201
            elif 'key' in data:
                user_login_sucess = self.login_with_key(data['key'])
                # Return a JSON success message
                return jsonify({"message": "User was logged in successfully", "status": "success"}), 201
            else:
                # Return an error message if fields are missing
                return jsonify({"message": "Missing required fields", "status": "error"}), 400
        else:
            # Return an error message if no JSON data is provided
            return jsonify({"message": "Invalid request: No JSON data", "status": "error"}), 400
        
    @login_required
    def get_api_key(self):
        """
        Example:
          >>> r = requests.post(
          ...   'http://localhost:5000/auth/api/user/add',
          ...   json={'username':'admin',
          ...   'email':'admin@admin.be','password':'admin'}
          ... )                                   
          >>> s = requests.Session()
          >>> r = s.post(
          ...   'http://localhost:5000/auth/api/user/login',
          ... json={'username':'admin','password':'admin'}
          ... )
          >>> r = s.post('http://localhost:5000/auth/api/key/get',json={})
          >>> print(r.json()) # shows API key
        """
        data = request.get_json()

        expiration = None
        if data:  # Ensure data is provided
            # Check if the required fields are present in the JSON
            if 'expiration' in data:
                expiration = data['expiration']
        
        key = self.models.APIKey(
            user_id = current_user.id,
            expiration = expiration
        )
        self.db.session.add(key)
        self.db.session.commit()
        return jsonify({"key": key.key, "status": "success"}), 201

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
        return render_template('uxfab/form.html', form=form, title='Profile')    

    # Admin page
    @root_required
    def admin(self):
        if current_user.role != 'admin':
            abort(HTTPStatus.UNAUTHORIZED)
        users = self.models.User.query.all()
        return render_template('IAM/list.html', items=users, title=f"User list")

    @root_required
    def enabler(self,userid):
        if current_user.role != 'admin':
            abort(HTTPStatus.UNAUTHORIZED)
        user = self.models.User.query.get_or_404(userid)
        user.enabled = True
        self.db.session.commit()
        return redirect('/user/admin')

    @root_required
    def remove_user(self,userid):
        if current_user.role != 'admin':
            abort(HTTPStatus.UNAUTHORIZED)
        user = self.models.User.query.get_or_404(userid)
        self.db.session.delete(user)
        self.db.session.commit()
        return redirect('/user/admin')

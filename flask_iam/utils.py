from functools import wraps
from flask import current_app, request
from flask_login import current_user
from flask_login.config import EXEMPT_METHODS

def root_required(func):
    """
    If you decorate a view with this, it will ensure that the current user is
    logged in and authenticated before calling the actual view. (If they are
    not, it calls the :attr:`LoginManager.unauthorized` callback.) For
    example::
 
    @app.route('/post')
    @root_required
        def post():
            pass
     
    If there are only certain times you need to require that your user is
    logged in, you can do so with::
     
    if not current_user.id == 0: #.is_authenticated:
        return current_app.login_manager.unauthorized()
     
    ...which is essentially the code that this function adds to your views.
 
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in EXEMPT_METHODS or current_app.config.get("LOGIN_DISABLED"):
            pass
        elif not current_user.id == 0: #.is_authenticated:
            return current_app.login_manager.unauthorized()
        return current_app.ensure_sync(func)(*args, **kwargs)
 
    return decorated_view

def role_required(role):
    """
    If you decorate a view with this, it will ensure that the current user is
    logged in and authenticated before calling the actual view. (If they are
    not, it calls the :attr:`LoginManager.unauthorized` callback.) For
    example::
 
    @app.route('/post')
    @role_required('admin')
        def post():
            pass
     
    """
    def specified_role_required(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if request.method in EXEMPT_METHODS or current_app.config.get("LOGIN_DISABLED"):
                pass
            else:
                print('Testing if role assigned')
                role_id = current_app.extensions['IAM'].models.Role.query.filter_by(name=role).first().id
                print(role_id)
                assigned_role = current_app.extensions['IAM'].models.RoleRegistration.query.filter_by(user_id=current_user.id).filter_by(role_id=role_id).first()
                print('Assigned role', assigned_role)
                if not assigned_role: return current_app.login_manager.unauthorized()
            return current_app.ensure_sync(func)(*args, **kwargs)
 
        return decorated_view
    return specified_role_required

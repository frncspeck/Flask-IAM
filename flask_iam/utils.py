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
        elif not current_user.id == 1: #.is_authenticated:
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

def check_user_role(role_name):
    """Checks if the user has a certain role

    Args:
        role_name: str | bool | None
            If str, than role name to check. If True, just requires user to be
            authenticated, if False no role required and if None it should be
            anonymous user

    TODO use this function from within role_required decorator
    """
    if role_name is None:
        return not current_user.is_authenticated
    elif role_name is True:
        return current_user.is_authenticated
    elif role_name is False:
        return True
    elif isinstance(role_name, str):
        if not current_user.is_authenticated: return False
        role = current_app.extensions['IAM'].models.Role.query.filter_by(name=role_name).first()
        if role:
            assigned_role = current_app.extensions['IAM'].models.RoleRegistration.query.filter_by(
                user_id=current_user.id
            ).filter_by(role_id=role.id).first()
            if assigned_role: return True
        return current_user.role == role_name
    else:
        raise TypeError('role_name should be str, bool or None')

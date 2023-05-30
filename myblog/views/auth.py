import functools
from os import error
from flask import(
    render_template, Blueprint, flash, g, redirect, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash
from flaskext.mysql import MySQL
from myblog.models.user import User

from myblog import db



auth = Blueprint('auth', __name__, url_prefix='/auth')

#Registrar un usuario 
@auth.route('/register', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        tipoUsuario="usuario"
        
        #instruccion sql
        user = User(username, generate_password_hash(password),tipoUsuario)

        error = None
        if not username:
            error = 'Se requiere nombre de usuario'
        elif not password:
            error = 'Se requiere contraseña'
        
        user_name = User.query.filter_by(username = username).first()
        if user_name == None:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        else:
            error = f'El usuario {username} ya esta registrado'
        flash(error)
        
    return render_template('auth/register.html')



@auth.route('/registerAdmin', methods=('GET','POST'))
def registerAdmin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        tipoUsuario=request.form.get('select')
        
        #instruccion sql
        user = User(username, generate_password_hash(password),tipoUsuario)

        error = None
        if not username:
            error = 'Se requiere nombre de usuario'
        elif not password:
            error = 'Se requiere contraseña'
        
        user_name = User.query.filter_by(username = username).first()
        if user_name == None:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('blog.indexAdmin'))
        else:
            error = f'El usuario {username} ya esta registrado'
        flash(error)
        
    return render_template('auth/registerAdmin.html')

@auth.route('/sobre')
def sobre():
    return render_template('blog/sobre.html')

@auth.route('mostrarUsuarios')
def mostrarUsuarios():
    data = User.query.all()
    db.session.commit()
    return render_template('blog/panelAdmin.html',data=data)



@auth.route('/login', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        tipoUsuario=request.form.get('select')

        error = None
        
        user = User.query.filter_by(username = username).first()
        
        if user == None:
            error = 'Nombre de usuario incorrecto'
        elif not check_password_hash(user.password, password):
            error = 'Contraseña incorrecta'
            #validacion de tipo de usuario
        elif not  user.tipoUsuario==tipoUsuario:
            error='Tipo de eusuario incorrecto'
        
        if user.tipoUsuario=="Administrador":
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('blog.indexAdmin'))
            #return render_template('blog/indexAdmin.html')
        
        elif error is None:
            session.clear()
            session['user_id'] = user.id
            
            return redirect(url_for('blog.index'))
        
        flash(error)
        
        
    return render_template('auth/login.html')


@auth.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get_or_404(user_id)

@auth.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('blog.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view



@auth.route('/delete/<int:id>')
def delete(id):
     user=User.query.get(id)
     db.session.delete(user)
     db.session.commit() 
     return redirect(url_for('blog.indexAdmin'))
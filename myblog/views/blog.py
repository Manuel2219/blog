
from operator import pos
from flask import(
    render_template, Blueprint, flash, g, redirect, request, url_for
)

from werkzeug.exceptions import abort

from myblog.models.post import Post
from myblog.models.user import User

from myblog.views.auth import login_required

from myblog import db

blog = Blueprint('blog', __name__)

#Obtner un ususario
def get_user(id):
    user = User.query.get_or_404(id)
    return user

@blog.route("/")
def index():
    posts = Post.query.all()
    posts = list(reversed(posts))
    db.session.commit()
    return render_template('blog/index.html', posts = posts, get_user=get_user)

@blog.route("/IndexAdmin")
def indexAdmin():
    posts = Post.query.all()
    posts = list(reversed(posts))
    db.session.commit()
    return render_template('blog/indexAdmin.html', posts = posts, get_user=get_user)

#Registrar un post 
@blog.route('/blog/create', methods=('GET','POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')

        post = Post(g.user.id, title, body)

        error = None
        if not title:
            error = 'Se requiere un título'
        
        if error is not None:
            flash(error)
        else:
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('blog.index'))
        
        flash(error)
        
    return render_template('blog/create.html')

@blog.route('/blog/createAdmin', methods=('GET','POST'))
@login_required
def createAdmin():
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')

        post = Post(g.user.id, title, body)

        error = None
        if not title:
            error = 'Se requiere un título'
        
        if error is not None:
            flash(error)
        else:
            db.session.add(post)
            db.session.commit()
            #return render_template('blog/indexAdmin.html')
            return redirect(url_for('blog.indexAdmin'))
        
        flash(error)
        
    return render_template('blog/createAdmin.html')

def get_post(id, check_author=True):
    post = Post.query.get(id)

    if post is None:
        abort(404, f'Id {id} de la publicación no existe.')

    if check_author and post.author != g.user.id:
        abort(404)
    
    return post

#Update post 
@blog.route('/blog/update/<int:id>', methods=('GET','POST'))
@login_required
def update(id):

    post = get_post(id) 

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.body = request.form.get('body')

        error = None
        if not post.title:
            error = 'Se requiere un título'
        
        if error is not None:
            flash(error)
        else:
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('blog.index'))
        
        flash(error)
        
    return render_template('blog/update.html', post=post)

@blog.route('/blog/updateAdmin/<int:id>', methods=('GET','POST'))
@login_required
def updateAdmin(id):

    post = get_post(id) 

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.body = request.form.get('body')

        error = None
        if not post.title:
            error = 'Se requiere un título'
        
        if error is not None:
            flash(error)
        else:
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('blog.indexAdmin'))
        
        flash(error)
        
    return render_template('blog/updateAdmin.html', post=post)



#Eliminar un post
@blog.route('/blog/delete/<int:id>')
@login_required
def delete(id):
    
    post = get_post(id)
    db.session.delete(post)
    db.session.commit()

    return redirect(url_for('blog.index'))

@blog.route('/blog/deleteAdmin/<int:id>')
@login_required
def deleteAdmin(id):
    
    post = get_post(id)
    db.session.delete(post)
    db.session.commit()

    return redirect(url_for('blog.indexAdmin'))

@blog.route('/mostrarPublicaciones')
def mostrarPublicaciones():
    data = Post.query.all()
    db.session.commit()
    return render_template('blog/mostrarPublicaciones.html',data=data)
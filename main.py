from base64 import b64encode
from sqlite3 import IntegrityError
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import os
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from wtforms import PasswordField, StringField, SubmitField, ValidationError
from flask_bcrypt import Bcrypt
from wtforms.validators import DataRequired
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_login import UserMixin
from datetime import datetime, timezone
from flask_bcrypt import Bcrypt
from functools import wraps
from flask_login import current_user
from flask import send_from_directory
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import timedelta
from sqlalchemy import or_
from flask_apscheduler import APScheduler
from sqlalchemy import func

bcrypt = Bcrypt()
app = Flask(__name__, static_folder='templates')

app.jinja_env.filters['b64encode'] = lambda x: b64encode(x).decode('utf-8')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SECRET_KEY'] = 'db2dda154f9dc44d77fbcb52'
app.config['UPLOAD_FOLDER'] = 'templates/files'
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
def liblogin():
    form = LibLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password_correction(form.password.data) and user.role == 'librarian':
            login_user(user)
            return redirect(url_for('section_page'))
        else:
            return 'Invalid credentials'
    return render_template('liblogin.html', form=form)

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                return redirect(url_for('liblogin_page'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False , unique=True)
    email = db.Column(db.String(100), nullable=False , unique=True)
    password_hash = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    def get_id(self):
        return str(self.id)
    @property
    def password(self):
        return self.password_hash
    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password_correction(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sectionid = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    section = db.Column(db.Integer, db.ForeignKey('section.title'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_issued = db.Column(db.DateTime, nullable=True)
    image = db.Column(db.LargeBinary, nullable=True)
    pdf = db.Column(db.String, nullable=True)
    requests = db.relationship('BookRequest', backref='book', lazy=True) 
    def __repr__(self):
        return f"Book('{self.name}', '{self.section}')"
    
class Section(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, nullable=True, default=datetime.now(timezone.utc))
    description = db.Column(db.String(100), nullable=True)
    def __repr__(self):
        return f"Section('{self.name}')"
    
class BookRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='user_requests', foreign_keys=[user_id])
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    request_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    request_days = db.Column(db.Integer, nullable=False)
    librarian_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    librarian = db.relationship('User', backref='librarian_requests', foreign_keys=[librarian_id])
    status = db.Column(db.String(100), nullable=False)
    accept_date = db.Column(db.DateTime)
    expiry_date = db.Column(db.DateTime)
    remarks = db.Column(db.String(500))
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
class UserRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password1 = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists. Please choose a different email.')
class UserLoginForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class LibLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class SectionForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    date_created = StringField('Date Created', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('Add Section')
    
class EditSectionForm(FlaskForm):
    section_id = StringField('Section ID', validators=[DataRequired()])
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('Update Section')
    
    
scheduler = APScheduler()



def get_average_rating(book_id):
    avg_rating = db.session.query(func.avg(Rating.rating)).filter(Rating.book_id == book_id).scalar()
    return round(avg_rating, 2) if avg_rating else 'No ratings yet'

@app.context_processor
def make_utility_functions_available():
    return dict(get_average_rating=get_average_rating)

@scheduler.task('interval', id='revoke_expired_requests', seconds=60, misfire_grace_time=900)
def revoke_expired_requests():
    now = datetime.now(timezone.utc)
    expired_requests = BookRequest.query.filter(BookRequest.status == 'Accepted', BookRequest.expiry_date <= now).all()
    for request in expired_requests:
        request.status = 'Revoked'
    db.session.commit()

@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')
@app.route('/books', methods=['GET', 'POST'])
@login_required
def books():
    if not current_user.is_authenticated:
        return redirect(url_for('home_page'))
    if request.method == 'POST':
        book_id = request.form.get('book_id')
        book = Book.query.filter_by(id=book_id).first()
        book_request = BookRequest(user_id=current_user.id, book_id=book.id, status='Pending', request_date=datetime.now(timezone.utc))
        db.session.add(book_request)
        db.session.commit()
        flash('Book request has been submitted', category='info')
    books = Book.query.filter(~Book.id.in_(db.session.query(BookRequest.book_id).filter(BookRequest.status == 'Accepted'))).all()
    return render_template('books.html', books=books, current_user=current_user)
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = UserRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password1.data)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login_page'))
        except:
            flash('Email already exists. Please choose a different email.', 'danger')
            db.session.rollback()
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', 'danger')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = UserLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash(f'Success! You are logged in as: {user.username}', category='success')
            return redirect(url_for('books'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/baselogin', methods=['GET', 'POST'])
def baselogin_page():
    return render_template('baselogin.html')

@app.route('/section', methods=['GET', 'POST'])
@login_required
@role_required('librarian')
def section_page():
    addsection_form = SectionForm()
    editsection_form = EditSectionForm()
    if not current_user.is_authenticated or current_user.role != 'librarian':
            return redirect(url_for('liblogin_page'))
    if request.method == 'POST' and editsection_form.validate_on_submit():
        section_id = editsection_form.section_id.data
        section_to_edit = Section.query.get(section_id)
        if section_to_edit:
            section_to_edit.title = request.form['title']
            section_to_edit.description = request.form['description']
            db.session.commit()
            flash('Section updated successfully')
        else:
            flash('Section not found')
        return redirect(url_for('section_page'))
    elif request.method == 'POST':
        section = Section(title=request.form['title'], description=request.form['description'])
        db.session.add(section)
        db.session.commit()
        flash('Section has been added', category='info')
        return redirect(url_for('section_page'))

    sections = Section.query.all()
    return render_template('section.html', sections=sections, editsection_form=editsection_form, addsection_form=addsection_form)

@app.route('/delete_section', methods=['POST'])
@login_required
@role_required('librarian')
def delete_section():
    if not current_user.is_authenticated or current_user.role != 'librarian':
        return redirect(url_for('liblogin_page'))
    
    section_id = request.form.get('section_id')
    section_to_delete = Section.query.get(section_id)
    if section_to_delete:
        try:
            db.session.delete(section_to_delete)
            db.session.commit()
            flash('Section deleted successfully', 'success')
        except:
            db.session.rollback()
            flash('Error deleting section', 'error')
    else:
        flash('Section not found', 'error')
    
    return redirect(url_for('section_page'))
    


@app.route("/searchsection")
@login_required
@role_required('librarian')
def searchsection():
    addsection_form = SectionForm()
    editsection_form = EditSectionForm()
    q = request.args.get('q')
    print(q)
    if q:
        results = Section.query.filter(or_(Section.title.contains(q), Section.description.contains(q))).all()
    else:
        results = []
    form = SectionForm()
    return render_template('sectionsearch.html', results=results, addsection_form=addsection_form, editsection_form=editsection_form)


@app.route('/searchlibbook')
@login_required
@role_required('librarian')
def searchlibbook():
    q = request.args.get('q')
    if q:
        results = Book.query.filter(or_(Book.name.contains(q), Book.author.contains(q), Book.description.contains(q), Book.section.contains(q))).all()
    else:
        results = []
    return render_template('libbooksearch.html', results=results)

@app.route('/searchlibrequest')
@login_required
@role_required('librarian')
def searchlibrequest():
    q = request.args.get('q')
    if q:
        results = BookRequest.query.join(User, User.id == BookRequest.user_id).join(Book, Book.id == BookRequest.book_id).filter(
            or_(
                User.username.contains(q),
                Book.name.contains(q),
                BookRequest.user_id.contains(q),
                BookRequest.book_id.contains(q),
                BookRequest.status.contains(q),
                BookRequest.request_date.contains(q)
            )
        ).all()
    else:
        results = []
    return render_template('librequestsearch.html', results=results)

@app.route('/searchbooks')
def searchbooks():
    q = request.args.get('q')
    if q:
        results = Book.query.filter(or_(Book.name.contains(q), Book.author.contains(q), Book.description.contains(q), Book.section.contains(q))).all()
    else:
        results = []
    if results:
        return render_template('bookssearch.html', results=results)
    else:
        return render_template('bookssearch.html', results=[], error="No books found")

@app.route('/searchmybooks')
def searchmybooks():
    q = request.args.get('q')
    if q:
        results = Book.query.filter(or_(Book.name.contains(q), Book.author.contains(q), Book.description.contains(q), Book.section.contains(q))).all()
    else:
        results = []
    return render_template('mybookssearch.html', results=results)


@app.route('/files/<path:filename>')
def serve_file(filename):
    return send_from_directory('/files', filename)

@app.route('/libbook', methods=['GET', 'POST'])
@role_required('librarian')
def libbook():
    if not current_user.is_authenticated or current_user.role != 'librarian':
        return redirect(url_for('liblogin_page'))
    addbookform = SectionForm()
    editbookform = EditSectionForm()

    if request.method == 'POST':
        image_file = request.files['image']
        pdf_file = request.files['pdf']
        pdf_filename = secure_filename(pdf_file.filename)
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename.replace('\\', '/'))
        pdf_file.save(pdf_path)

        section_name = request.form['section']
        section = Section.query.filter_by(title=section_name).first()
        if not section:
            flash('Section not found')
            return redirect(url_for('libbook'))

        book_id = request.form.get('id') 
        if book_id:
           
            book_to_edit = Book.query.get(book_id) 
            if book_to_edit:
                book_to_edit.sectionid = section.id
                book_to_edit.section = section_name
                book_to_edit.name = request.form['name']
                book_to_edit.author = request.form['author']
                book_to_edit.description = request.form['description']
                book_to_edit.date_issued = datetime.now()
                book_to_edit.image = image_file.read()
                book_to_edit.pdf = pdf_path
                db.session.commit()
                flash('Book updated successfully')
            else:
                flash('Book not found')
        else:
            try:
                new_book = Book(
                    sectionid=section.id,
                    section=section_name,
                    name=request.form['name'],
                    author=request.form['author'],
                    description=request.form['description'],
                    date_issued=datetime.now(),
                    image=image_file.read(),
                    pdf=pdf_path
                )
                db.session.add(new_book)
                db.session.commit()
                flash('Book uploaded successfully')
            except IntegrityError:
                db.session.rollback()
                existing_book = Book.query.filter_by(name=request.form['name']).first()
                if existing_book:
                    existing_book.image = image_file.read()
                    existing_book.pdf = pdf_path
                    db.session.commit()
                else:
                    pass

    books = Book.query.all()
    sections = Section.query.all()
    return render_template('libbook.html', addbookform=addbookform, editbookform=editbookform, books=books, sections=sections)

@app.route('/mybooks', methods=['GET'])
def mybooks():
    accepted_book_requests = BookRequest.query.join(Book, Book.id == BookRequest.book_id) \
        .filter(BookRequest.user_id == current_user.id, BookRequest.status == 'Accepted').all()
    accepted_books = [request.book for request in accepted_book_requests]
    
    revoked_books = BookRequest.query.filter_by(user_id=current_user.id, status='Revoked').all()
    if revoked_books:
        flash('You have books that have been revoked. Please review them.', category='info')
    
    return render_template('mybooks.html', books=accepted_books, revoked_books=revoked_books)

@app.route('/request_book/<int:book_id>', methods=['POST'])
def request_book(book_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login_page'))
        
    book = Book.query.filter_by(id=book_id).first()
    if not book:
        flash('Book not found', category='danger')
        return redirect(url_for('books'))

    existing_request = BookRequest.query.filter(
        BookRequest.user_id==current_user.id, 
        BookRequest.book_id==book.id, 
        BookRequest.status.in_(['Pending', 'Accepted'])
    ).first()
    if existing_request:
        flash('You have already requested this book and it has not been rejected', category='danger')
        return redirect(url_for('books'))

    days = min(int(request.form.get('days', 0)), 14)
    expiry_date = datetime.now(timezone.utc) + timedelta(days=days)

    book_request = BookRequest(user_id=current_user.id, book_id=book.id, status='Pending', request_date=datetime.now(timezone.utc), request_days=days)
    db.session.add(book_request)
    db.session.commit()


    flash('Book request has been submitted', category='info')
    return redirect(url_for('books'))



@app.route('/return_book', methods=['POST'])
def return_book():
    if not current_user.is_authenticated:
        return redirect(url_for('login_page'))

    book_id = request.form.get('book_id')
    rating = request.form.get('rating')
    book_request = BookRequest.query.filter_by(user_id=current_user.id, book_id=book_id, status='Accepted').first()
    if book_request:
        db.session.delete(book_request)
        db.session.commit()
        new_rating = Rating(user_id=current_user.id, book_id=book_id, rating=rating)
        db.session.add(new_rating)
        db.session.commit()
        flash('Book has been returned and your rating has been recorded', category='info')
    else:
        flash('Book not found', category='danger')

    return redirect(url_for('mybooks'))

@app.route('/ask_reason/<int:request_id>', methods=['POST'])
def ask_reason(request_id):
    book_request = BookRequest.query.get(request_id)
    if book_request:
        reason = request.form.get('reason')
        book_request.remarks = reason
        db.session.commit()
        flash('Reason has been submitted', category='success')
    else:
        flash('Book request not found', category='danger')
    return redirect(url_for('librarian_requests'))


@app.route('/librarian_requests', methods=['GET'])
@role_required('librarian')
def librarian_requests():
    all_requests = BookRequest.query.all()
    return render_template('librequest.html', requests=all_requests)


@app.route('/librarian_ratings/<int:book_id>', methods=['GET'])
@role_required('librarian')
def librarian_ratings(book_id):
    ratings = Rating.query.filter_by(book_id=book_id).all()
    return render_template('librarian_ratings.html', ratings=ratings)

@app.route('/requests')
def requests():
    requests = BookRequest.query.all()
    return render_template('librequest.html', requests=requests)
@app.route('/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    book_request = BookRequest.query.get(request_id)
    if book_request:
        book_request.status = 'Accepted'
        book_request.librarian_id = current_user.id
        book_request.accept_date = datetime.utcnow()
        book_request.expiry_date = book_request.accept_date + timedelta(days=book_request.request_days)
        db.session.commit()
        flash('Book request has been accepted', category='success')
    else:
        flash('Book request not found', category='danger')
    return redirect(url_for('librarian_requests'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    book_request = BookRequest.query.get(request_id)
    remarks = request.form.get('remarks')
    if book_request:
        book_request.status = 'Rejected'
        book_request.remarks = remarks
        book_request.librarian_id = current_user.id
        db.session.commit()
        flash('Book request has been rejected', category='success')
    else:
        flash('Book request not found', category='danger')
    return redirect(url_for('librarian_requests'))

@app.route('/rate_book/<int:book_id>', methods=['GET', 'POST'])
def rate_book(book_id):
    if request.method == 'POST':
        rating = request.form.get('rating')
        new_rating = Rating(user_id=current_user.id, book_id=book_id, rating=rating)
        db.session.add(new_rating)
        db.session.commit()
        flash('Your rating has been recorded', category='info')
        return redirect(url_for('mybooks'))

    return render_template('rate_book.html', book_id=book_id)


@app.route('/revoke_access/<int:request_id>', methods=['POST'])
def revoke_access(request_id):
    book_request = BookRequest.query.get(request_id)
    remarks = request.form.get('remarks')
    if book_request:
        book_request.status = 'Revoked'
        book_request.remarks = remarks
        db.session.commit()
        flash('Book access has been revoked', category='success')
    else:
        flash('Book request not found', category='danger')
    return redirect(url_for('librarian_requests'))

def revoke_expired_requests():
    now = datetime.now(timezone.utc)
    expired_requests = BookRequest.query.filter(BookRequest.status == 'Accepted', BookRequest.expiry_date <= now).all()
    for request in expired_requests:
        request.status = 'Revoked'
    db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(func=revoke_expired_requests, trigger="interval", days=1)
scheduler.start()

@app.route('/delete_book/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    db.session.query(BookRequest).filter(BookRequest.book_id == book_id).delete()
    book = Book.query.get(book_id)
    db.session.delete(book)

    db.session.commit()

    return redirect(url_for('libbook'))
    



@app.route('/libprofile', methods=['GET', 'POST'])
def libprofile():
    issued_books = BookRequest.query.filter_by(status='Accepted').all()

    top_request_user = db.session.query(User, func.count(BookRequest.id)).join(BookRequest, User.id == BookRequest.user_id).group_by(User.id).order_by(func.count(BookRequest.id).desc()).first()

    reviews = Rating.query.all()

    return render_template('libprofile.html', issued_books=issued_books, top_request_user=top_request_user, reviews=reviews)    

@app.route('/liblogin', methods=['GET', 'POST'])
def liblogin_page():
    form = LibLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password_correction(form.password.data) and user.role == 'librarian':
            login_user(user)
            return redirect(url_for('section_page'))
        else:
            return 'Invalid credentials'
    return render_template('liblogin.html', form=form)
@app.route('/logout')
def logout_page():
    logout_user()
    flash('You have been logged out', category='info')
    return redirect(url_for('home_page'))

if __name__ == "__main__":
    app.debug = True
    app.run()
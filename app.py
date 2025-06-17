import os
from flask import (
    Flask, render_template, redirect, url_for, flash,
    session, request, jsonify, abort
)
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required, logout_user, current_user
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField, PasswordField, SubmitField,
    DecimalField, BooleanField, HiddenField
)
from wtforms.validators import (
    DataRequired, Length, EqualTo, NumberRange
)
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import requests

# ── NO-OP UNDERSCORE FOR PYTHON & TEMPLATES ────────────────────────────────────────
def _(s):
    return s

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "supersecretkey12345")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tienda.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── CSRF PROTECTION ────────────────────────────────────────────────────────────────
csrf = CSRFProtect(app)

# Inject '_' into all templates
@app.context_processor
def inject_underscore():
    return {'_': _}

# ── EXTENSIONS ──────────────────────────────────────────────────────────────────────
db            = SQLAlchemy(app)
bcrypt        = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ── MODELS ──────────────────────────────────────────────────────────────────────────
class User(db.Model, UserMixin):
    id            = db.Column(db.Integer,   primary_key=True)
    username      = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_seller     = db.Column(db.Boolean,    default=False)
    is_approved   = db.Column(db.Boolean,    default=False)
    is_admin      = db.Column(db.Boolean,    default=False)

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)

class Product(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(120), nullable=False)
    price_btc = db.Column(db.Numeric(16,8), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller    = db.relationship('User', backref='products')

# ── FORMS ───────────────────────────────────────────────────────────────────────────
class RegisterForm(FlaskForm):
    username  = StringField(_('Usuario'), validators=[DataRequired(), Length(min=4, max=20)])
    password  = PasswordField(_('Contraseña'), validators=[DataRequired(), Length(min=6)])
    confirm   = PasswordField(_('Confirmar contraseña'), validators=[DataRequired(), EqualTo('password')])
    is_seller = BooleanField(_('Registrarme como vendedor'))
    submit    = SubmitField(_('Registrarse'))

class LoginForm(FlaskForm):
    username = StringField(_('Usuario'), validators=[DataRequired()])
    password = PasswordField(_('Contraseña'), validators=[DataRequired()])
    submit   = SubmitField(_('Ingresar'))

class ProductForm(FlaskForm):
    name      = StringField(_('Nombre del producto'), validators=[DataRequired(), Length(max=120)])
    price_btc = DecimalField(_('Precio (BTC)'), validators=[DataRequired(), NumberRange(min=0)], places=8)
    submit    = SubmitField(_('Guardar'))

class CheckoutForm(FlaskForm):
    address = StringField(_('Dirección'), validators=[DataRequired(), Length(min=5, max=255)])
    lat     = HiddenField(_('Latitud'), validators=[DataRequired()])
    lon     = HiddenField(_('Longitud'), validators=[DataRequired()])
    submit  = SubmitField(_('Confirmar pedido'))

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField(_('Contraseña actual'), validators=[DataRequired()])
    new_password     = PasswordField(_('Nueva contraseña'), validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(_('Confirmar nueva contraseña'), validators=[DataRequired(), EqualTo('new_password')])
    submit           = SubmitField(_('Cambiar contraseña'))

class AdminPasswordChangeForm(FlaskForm):
    new_password     = PasswordField(_('Nueva contraseña'), validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(_('Confirmar nueva contraseña'), validators=[DataRequired(), EqualTo('new_password')])
    submit           = SubmitField(_('Cambiar contraseña'))

# ── USER LOADER ────────────────────────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── ROLE DECORATORS ─────────────────────────────────────────────────────────────────
def admin_required(f):
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash(_('Acceso denegado: solo administradores.'), 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def seller_required(f):
    @login_required
    def decorated(*args, **kwargs):
        if not (current_user.is_seller and current_user.is_approved):
            flash(_('Acceso denegado: necesitas aprobación como vendedor.'), 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# ── DATABASE INIT & DEFAULT ADMIN ──────────────────────────────────────────────────
@app.before_request
def init_db():
    db.create_all()
    if not User.query.filter_by(is_admin=True).first():
        pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', password_hash=pw, is_admin=True, is_approved=True)
        db.session.add(admin)
        db.session.commit()

# ── PUBLIC ROUTES ─────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    products   = Product.query.all()
    blank_form = FlaskForm()
    return render_template('index.html', products=products, form=blank_form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash(_('Usuario ya existe.'), 'danger')
            return redirect(url_for('register'))
        pw   = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    password_hash=pw,
                    is_seller=form.is_seller.data,
                    is_approved=False)
        db.session.add(user)
        db.session.commit()
        if form.is_seller.data:
            flash(_('Solicitud enviada: esperá aprobación del admin.'), 'info')
        else:
            flash(_('Usuario creado. Ya podés ingresar.'), 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(_('Ingreso exitoso.'), 'success')
            return redirect(url_for('index'))
        flash(_('Usuario o contraseña inválidos.'), 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(_('Sesión cerrada.'), 'info')
    return redirect(url_for('index'))

# ── CART & CHECKOUT ───────────────────────────────────────────────────────────────
@app.route('/add_to_cart/<int:pid>')
@login_required
def add_to_cart(pid):
    prod = Product.query.get_or_404(pid)
    cart = session.get('cart', {})
    cart[str(pid)] = cart.get(str(pid), 0) + 1
    session['cart'] = cart
    flash(_(f'{prod.name} añadido al carrito.'), 'success')
    return redirect(url_for('index'))

@app.route('/cart')
@login_required
def cart():
    cart = session.get('cart', {})
    items, total = [], 0
    for pid, qty in cart.items():
        p = Product.query.get(int(pid))
        subtotal = float(p.price_btc) * qty
        items.append({'name':p.name,'price':p.price_btc,'qty':qty,'subtotal':subtotal})
        total += subtotal
    return render_template('cart.html', cart_items=items, total=total)

@app.route('/checkout', methods=['GET','POST'])
@login_required
def checkout():
    cart_data = session.get('cart', {})
    if not cart_data:
        flash(_('Carrito vacío.'), 'warning')
        return redirect(url_for('index'))
    form = CheckoutForm()
    if form.validate_on_submit():
        address, lat, lon = form.address.data, form.lat.data, form.lon.data
        total_btc, desc = 0, []
        for pid, qty in cart_data.items():
            p = Product.query.get(int(pid))
            total_btc += float(p.price_btc) * qty
            desc.append(f"{qty}×{p.name}")
        invoice = create_btcpay_invoice(total_btc, desc, current_user.id)
        if not invoice:
            flash(_('Error creando factura.'), 'danger')
            return redirect(url_for('cart'))
        session['last_order'] = {
            'invoice_id': invoice['id'],
            'url': invoice['checkoutLink'],
            'address': address,
            'total_btc': total_btc,
            'items': desc
        }
        session['cart'] = {}
        return redirect(url_for('order_status'))
    return render_template('checkout.html', form=form)

@app.route('/order_status')
@login_required
def order_status():
    order = session.get('last_order')
    if not order:
        flash(_('No hay pedido activo.'), 'info')
        return redirect(url_for('index'))
    return render_template('order_status.html', order=order)

@app.route('/check_invoice/<inv_id>')
@login_required
def check_invoice(inv_id):
    return jsonify(check_btcpay_invoice_status(inv_id))

# ── BTCPAY SERVER INTEGRATION ────────────────────────────────────────────────────
BTCPAY_API_URL  = os.getenv('BTCPAY_API_URL')
BTCPAY_API_KEY  = os.getenv('BTCPAY_API_KEY')
BTCPAY_STORE_ID = os.getenv('BTCPAY_STORE_ID')

def create_btcpay_invoice(amount, items, buyer_id):
    if not all([BTCPAY_API_URL, BTCPAY_API_KEY, BTCPAY_STORE_ID]):
        return None
    headers = {'Content-Type':'application/json', 'Authorization':f'token {BTCPAY_API_KEY}'}
    data = {'amount': round(amount,8), 'currency':'BTC',
            'metadata':{'buyerId':buyer_id,'items':items},
            'checkout':{'speedPolicy':'HighSpeed','paymentMethods':['BTC'],'expirationMinutes':15}}
    url = f"{BTCPAY_API_URL}/stores/{BTCPAY_STORE_ID}/invoices"
    try:
        r = requests.post(url, headers=headers, json=data)
        if r.status_code in (200,201):
            return r.json()
    except:
        pass
    return None

def check_btcpay_invoice_status(inv_id):
    if not all([BTCPAY_API_URL, BTCPAY_API_KEY, BTCPAY_STORE_ID]):
        return {'error': _('Config BTCPay faltante')}
    headers = {'Authorization':f'token {BTCPAY_API_KEY}'}
    url = f"{BTCPAY_API_URL}/stores/{BTCPAY_STORE_ID}/invoices/{inv_id}"
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            return {'status': r.json().get('status')}
    except Exception as e:
        return {'error': str(e)}
    return {'error': _('Desconocido')}

# ── SELLER PRODUCT MANAGEMENT ────────────────────────────────────────────────────
@app.route('/seller/products')
@seller_required
def seller_products():
    blank_form = FlaskForm()
    my_products = Product.query.filter_by(seller_id=current_user.id).all()
    return render_template('seller_products.html',
                           products=my_products,
                           form=blank_form)

@app.route('/seller/product/new', methods=['GET','POST'])
@seller_required
def new_product():
    form = ProductForm()
    if form.validate_on_submit():
        p = Product(name=form.name.data,
                    price_btc=form.price_btc.data,
                    seller=current_user)
        db.session.add(p)
        db.session.commit()
        flash(_('Producto creado.'), 'success')
        return redirect(url_for('seller_products'))
    return render_template('product_form.html', form=form, title=_('Nuevo producto'))

@app.route('/seller/product/<int:pid>/edit', methods=['GET','POST'])
@seller_required
def edit_product(pid):
    p = Product.query.get_or_404(pid)
    if p.seller_id != current_user.id:
        flash(_('Acceso denegado: producto de otro vendedor.'), 'danger')
        return redirect(url_for('seller_products'))
    form = ProductForm(obj=p)
    if form.validate_on_submit():
        p.name, p.price_btc = form.name.data, form.price_btc.data
        db.session.commit()
        flash(_('Producto actualizado.'), 'success')
        return redirect(url_for('seller_products'))
    return render_template('product_form.html', form=form, title=_('Editar producto'))

@app.route('/seller/product/<int:pid>/delete', methods=['POST'])
@seller_required
def delete_product(pid):
    p = Product.query.get_or_404(pid)
    if p.seller_id != current_user.id:
        flash(_('Acceso denegado: producto de otro vendedor.'), 'danger')
        return redirect(url_for('seller_products'))
    db.session.delete(p)
    db.session.commit()
    flash(_('Producto eliminado.'), 'info')
    return redirect(url_for('seller_products'))

# ── ADMIN: SELLER APPROVAL ─────────────────────────────────────────────────────────
@app.route('/admin/sellers')
@admin_required
def admin_sellers():
    pend = User.query.filter_by(is_seller=True, is_approved=False).all()
    blank_form = FlaskForm()
    return render_template('admin_sellers.html',
                           users=pend,
                           form=blank_form)

@app.route('/admin/seller/<int:uid>/approve', methods=['POST'])
@admin_required
def approve_seller(uid):
    u = User.query.get_or_404(uid)
    u.is_approved = True; db.session.commit()
    flash(_(f'{u.username} aprobado como vendedor.'), 'success')
    return redirect(url_for('admin_sellers'))

@app.route('/admin/seller/<int:uid>/reject', methods=['POST'])
@admin_required
def reject_seller(uid):
    u = User.query.get_or_404(uid)
    u.is_seller = False; db.session.commit()
    flash(_(f'Solicitud de {u.username} rechazada.'), 'info')
    return redirect(url_for('admin_sellers'))

# ── ADMIN: USER MANAGEMENT & PASSWORD CHANGE ──────────────────────────────────────
@app.route('/admin/users')
@admin_required
def admin_users():
    blank_form = FlaskForm()
    return render_template('admin_users.html',
                           users=User.query.all(),
                           form=blank_form)

@app.route('/admin/user/<int:uid>/change_password', methods=['GET','POST'])
@admin_required
def admin_change_password(uid):
    u = User.query.get_or_404(uid)
    form = AdminPasswordChangeForm()
    if form.validate_on_submit():
        u.password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        db.session.commit()
        flash(_(f'Contraseña de {u.username} actualizada.'), 'success')
        return redirect(url_for('admin_users'))
    return render_template('change_password.html', form=form, user=u, own=False)

# ── USER: CHANGE OWN PASSWORD ──────────────────────────────────────────────────────
@app.route('/change_password', methods=['GET','POST'])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash(_('Contraseña actual incorrecta.'), 'danger')
            return redirect(url_for('change_password'))
        current_user.password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        db.session.commit()
        flash(_('Tu contraseña ha sido actualizada.'), 'success')
        return redirect(url_for('index'))
    return render_template('change_password.html', form=form, own=True)

# ── RUN ────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False,host="0.0.0.0",port=80)

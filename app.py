from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Configurações
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'techsolutions-secure-key-2024'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# --- MODELOS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    due_date = db.Column(db.String(10), nullable=True)  # YYYY-MM-DD
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()


# --- ROTAS API (JSON) ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Preencha email e senha"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email já cadastrado"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "Conta criada com sucesso"}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Credenciais inválidas"}), 401


@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=current_user_id).all()
    output = []
    for t in tasks:
        output.append({
            'id': t.id,
            'title': t.title,
            'due_date': t.due_date,
            'completed': t.completed
        })
    return jsonify(output), 200


@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    if not data.get('title'): return jsonify({"msg": "Título obrigatório"}), 400

    new_task = Task(title=data.get('title'), due_date=data.get('due_date'), user_id=current_user_id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"msg": "Tarefa criada"}), 201


@app.route('/api/tasks/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_task(id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=id, user_id=current_user_id).first()
    if not task: return jsonify({"msg": "Erro"}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({"msg": "Deletado"}), 200


@app.route('/api/tasks/<int:id>', methods=['PUT'])
@jwt_required()
def update_task(id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=id, user_id=current_user_id).first()
    if not task: return jsonify({"msg": "Erro"}), 404
    data = request.get_json()
    if 'completed' in data: task.completed = data['completed']
    db.session.commit()
    return jsonify({"msg": "Atualizado"}), 200


# --- ROTA DE PÁGINAS (FRONTEND) ---
# Esta rota "Catch-All" pega qualquer URL (/, /login, /dashboard)
# e entrega o HTML. O JS cuida do resto.
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    return send_from_directory(basedir, 'index.html')


if __name__ == '__main__':
    app.run(debug=True, port=8000)

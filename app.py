from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import os
import re  # Para validar formato de email

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Configurações
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'chave-super-secreta-estudante-seguro'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# --- MODELOS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Mudou de username para email
    password_hash = db.Column(db.String(128), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()


# --- ROTA PARA SERVIR O FRONTEND ---
@app.route('/')
def index():
    return send_from_directory(basedir, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(basedir, filename)


# --- AUTENTICAÇÃO ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Email e senha são obrigatórios"}), 400

    # Validação simples de email
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"msg": "Formato de email inválido"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email já cadastrado"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password_hash=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Conta criada com sucesso"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Email ou senha incorretos"}), 401


# --- ROTAS DE TAREFAS ---
@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=current_user_id).all()

    output = []
    for task in tasks:
        output.append({
            'id': task.id,
            'title': task.title,
            'completed': task.completed
        })
    return jsonify(output), 200


@app.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    if not data.get('title'):
        return jsonify({"msg": "Título é obrigatório"}), 400

    new_task = Task(title=data.get('title'), user_id=current_user_id)
    db.session.add(new_task)
    db.session.commit()

    return jsonify({"msg": "Tarefa criada"}), 201


@app.route('/tasks/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_task(id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=id, user_id=current_user_id).first()
    if not task: return jsonify({"msg": "Não encontrado"}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({"msg": "Deletado"}), 200


@app.route('/tasks/<int:id>', methods=['PUT'])
@jwt_required()
def update_task(id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=id, user_id=current_user_id).first()
    if not task: return jsonify({"msg": "Não encontrado"}), 404

    data = request.get_json()
    if 'completed' in data:
        task.completed = data['completed']
    db.session.commit()
    return jsonify({"msg": "Atualizado"}), 200


if __name__ == '__main__':
    app.run(debug=True, port=8000)

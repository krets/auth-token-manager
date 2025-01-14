import signal
import sys
import logging

from flask import Flask, request, jsonify, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_service.db'
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')


# Models
class RequestToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(36), unique=True, nullable=False)
    client_name = db.Column(db.String(100), nullable=False)
    request_expiration = db.Column(db.DateTime, nullable=False)
    access_expiration = db.Column(db.DateTime)
    host = db.Column(db.String(100), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    redeemed = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'uid': self.uid,
            'client_name': self.client_name,
            'request_expiration': self.request_expiration.isoformat(),
            'access_expiration': self.access_expiration.isoformat() if self.access_expiration else None,
            'host': self.host,
            'created': self.created.isoformat(),
            'redeemed': self.redeemed
        }


class AuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False)
    request_uid = db.Column(db.String(36), nullable=False)
    renew_after = db.Column(db.DateTime, nullable=False)
    user_agent = db.Column(db.String(200))
    last_use = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'token': self.token,
            'request_uid': self.request_uid,
            'renew_after': self.renew_after.isoformat(),
            'user_agent': self.user_agent,
            'last_use': self.last_use.isoformat()
        }


# Admin routes
@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/')
def index():
    return render_template('default.html')


@app.route('/admin/create_request', methods=['POST'])
def create_request():
    data = request.json
    request_token = RequestToken(
        uid=str(uuid.uuid4()),
        client_name=data['client_name'],
        request_expiration=datetime.fromisoformat(data['request_expiration']),
        access_expiration=datetime.fromisoformat(data['access_expiration']) if data['access_expiration'] else None,
        host=data['host']
    )
    db.session.add(request_token)
    db.session.commit()
    return jsonify({'uid': request_token.uid}), 201


@app.route('/admin/get_tokens')
def get_tokens():
    request_tokens = RequestToken.query.all()
    auth_tokens = AuthToken.query.all()
    return jsonify(
        {
            'request_tokens': [token.to_dict() for token in request_tokens],
            'auth_tokens': [token.to_dict() for token in auth_tokens]
        })


@app.route('/admin/delete_request/<uid>', methods=['DELETE'])
def delete_request(uid):
    token = RequestToken.query.filter_by(uid=uid).first()
    if token:
        db.session.delete(token)
        db.session.commit()
        return '', 204
    return 'Token not found', 404


@app.route('/admin/delete_auth/<token>', methods=['DELETE'])
def delete_auth(token):
    auth_token = AuthToken.query.filter_by(token=token).first()
    if auth_token:
        db.session.delete(auth_token)
        db.session.commit()
        return '', 204
    return 'Token not found', 404

@app.route('/auth', methods=['POST', 'GET'], defaults={'path': ''}, strict_slashes=False)
@app.route('/auth/', methods=['POST', 'GET'], defaults={'path': ''}, strict_slashes=False)
@app.route('/auth/<path:path>', methods=['POST', 'GET'], strict_slashes=False)
def auth(path):
    krets_request_token = request.args.get('krets_request_token')
    krets_auth_token = request.cookies.get('krets_auth_token')
    original_host = request.headers.get('X-Original-Host')

    logging.debug("Auth request initiated. Request token: %s, Auth token: %s, Original Host: %s", krets_request_token, krets_auth_token, original_host)

    if krets_request_token:
        response, status_code = handle_redemption(krets_request_token, original_host)
        # Checking if the status code is 200
        if status_code == 200:
            return response, status_code

    if krets_auth_token:
        return handle_access(krets_auth_token, original_host)

    logging.warning("Invalid request: No valid tokens found.")
    return jsonify({'error': 'Invalid request', 'args': request.args}), 400


def handle_redemption(request_token_uid, original_host):
    request_token = RequestToken.query.filter_by(uid=request_token_uid).first()

    error = None
    if not request_token:
        error = "Token not found: '%s'" % request_token_uid
    elif request_token.redeemed:
        error = "Token already redeemed."
    elif request_token.request_expiration < datetime.utcnow():
        error = "Token has expired."
    elif request_token.host != original_host:
        error = "Redemption failed: Host mismatch."

    if error is not None:
        logging.error("Redemption failed: %s", error)
        return jsonify({'error': 'Invalid or expired request token'}), 400

    request_token.redeemed = True

    logging.info("Token redeemed successfully: %s", request_token_uid)

    auth_token = AuthToken(
        token=str(uuid.uuid4()),
        request_uid=request_token.uid,
        renew_after=datetime.utcnow() + timedelta(minutes=60),
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(auth_token)
    db.session.commit()

    response = make_response(jsonify({'message': 'Token redeemed successfully'}))
    response.set_cookie('krets_auth_token', auth_token.token)
    return response


def handle_access(auth_token, original_host):
    auth_token = AuthToken.query.filter_by(token=auth_token).first()

    if not auth_token:
        logging.error("Access denied: Invalid auth token.")
        return jsonify({'error': 'Invalid auth token'}), 400

    request_token = RequestToken.query.filter_by(uid=auth_token.request_uid).first()
    if not request_token or request_token.host != original_host:
        logging.error("Access denied: Invalid host.")
        return jsonify({'error': 'Invalid host'}), 400

    if auth_token.renew_after < datetime.utcnow():
        new_auth_token = AuthToken(
            token=str(uuid.uuid4()),
            request_uid=auth_token.request_uid,
            renew_after=datetime.utcnow() + timedelta(minutes=60),
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(new_auth_token)
        db.session.delete(auth_token)
        db.session.commit()

        logging.info("Auth token renewed for request: %s", auth_token.request_uid)

        response = make_response(jsonify({'message': 'Token renewed'}))
        response.set_cookie('krets_auth_token', new_auth_token.token)
        return response

    auth_token.last_use = datetime.utcnow()
    db.session.commit()

    logging.info("Access granted for token: %s", auth_token.token)
    return jsonify({'message': 'Access granted'}), 200


def handle_sigterm(*args):
    sys.exit(0)


signal.signal(signal.SIGTERM, handle_sigterm)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
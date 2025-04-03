import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from flask import Flask, request, send_file, render_template, g, redirect, url_for, session, abort, jsonify

app = Flask(__name__,
    template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates')),
    static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))
)
app.secret_key = os.urandom(24)
app.logger.setLevel(logging.DEBUG)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import google.oauth2.credentials
import google_auth_oauthlib.flow
import google.auth.transport.requests
from google.oauth2 import id_token
from pip._vendor import cachecontrol
from models import User, init_user_db, get_user
from auth import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
import os
import pathlib
import requests
import sqlite3
import io
from gcloud import CloudStorage
from flask_cors import CORS
import traceback
from datetime import datetime

CORS(app, resources={
    r"/*": {
        "origins": "http://localhost:5000",
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

# Initialize Cloud Storage with error handling
try:
    storage = CloudStorage()
    app.logger.info("Cloud Storage initialized successfully")
except Exception as e:
    app.logger.error(f"Failed to initialize Cloud Storage: {e}")
    storage = None

DATABASE = "files.db"

# Configure Google OAuth
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for development
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secrets.json")

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", 
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000/callback"  # Make sure this matches exactly
)

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Create table if not exists
def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        # Get current schema
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='files'")
        current_schema = cur.fetchone()
        
        if current_schema:
            app.logger.info("Files table exists with schema:")
            app.logger.info(current_schema[0])
        else:
            app.logger.info("Creating files table...")
            cur.execute("""
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_file_id INTEGER,
                    user_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    mimetype TEXT NOT NULL,
                    filesize INTEGER NOT NULL,
                    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    UNIQUE(user_id, user_file_id)
                )
            """)
            conn.commit()
            app.logger.info("Files table created successfully")

# Add this function to initialize database on first run
def initialize_app():
    # Create databases if they don't exist
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()
            print("Initialized files database")
    
    if not os.path.exists('users.db'):
        init_user_db()
        print("Initialized users database")

@app.before_request
def before_request():
    init_db()

# Add login routes
@app.route("/start-auth", methods=['POST'])
def start_auth():
    try:
        # Verify reCAPTCHA first
        recaptcha_response = request.json.get('g-recaptcha-response')
        if not recaptcha_response:
            return jsonify({'error': 'Please complete the reCAPTCHA verification'}), 400

        # Add remote IP to verification
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        response = requests.post(verify_url, data={
            'secret': '6LdcIgUrAAAAACRDr3O0mfpvr1R3qgNo1n7Rqub_',
            'response': recaptcha_response,
            'remoteip': request.remote_addr  # Add client IP
        })
        
        verification_response = response.json()
        
        if not verification_response.get('success'):
            app.logger.error(f"reCAPTCHA verification failed: {verification_response}")
            return jsonify({'error': 'reCAPTCHA verification failed'}), 400

        # Continue with OAuth flow
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        session['state'] = state
        return jsonify({'auth_url': authorization_url})
        
    except Exception as e:
        app.logger.error(f"Auth error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route("/login")
def login():
    if request.args.get('code'):
        # Handle OAuth callback
        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            
            request_session = requests.session()
            cached_session = cachecontrol.CacheControl(request_session)
            token_request = google.auth.transport.requests.Request(session=cached_session)

            # Add clock_skew_in_seconds parameter to handle minor time differences
            id_info = id_token.verify_oauth2_token(
                id_token=credentials._id_token,
                request=token_request,
                audience=GOOGLE_CLIENT_ID,
                clock_skew_in_seconds=10
            )

            user = User(
                id_=id_info.get("sub"),
                name=id_info.get("name"),
                email=id_info.get("email"),
                profile_pic=id_info.get("picture")
            )

            # Store user in database
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute('''INSERT OR REPLACE INTO users (id, name, email, profile_pic) 
                            VALUES (?, ?, ?, ?)''', 
                        (user.id, user.name, user.email, user.profile_pic))
                conn.commit()

            login_user(user)
            return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(f"Auth error: {str(e)}")
            return render_template('login.html', error="Authentication failed")
    
    return render_template('login.html')

@app.route("/callback")
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        # Add clock_skew_in_seconds parameter to handle minor time differences
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )

        user = User(
            id_=id_info.get("sub"),
            name=id_info.get("name"),
            email=id_info.get("email"),
            profile_pic=id_info.get("picture")
        )

        # Store user in database
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users (id, name, email, profile_pic) 
                        VALUES (?, ?, ?, ?)''', 
                    (user.id, user.name, user.email, user.profile_pic))
            conn.commit()

        login_user(user)
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Authentication error: {str(e)}")
        return render_template("login.html", error="Authentication failed. Please try again."), 401

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Upload file route
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    # Add CORS headers for the upload route
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:5000'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
        
    if "file[]" not in request.files:
        return jsonify({"error": "No files selected"}), 400

    files = request.files.getlist("file[]")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files selected"}), 400

    uploaded_files = []
    
    try:
        app.logger.debug(f"Uploading files for user {current_user.id}")
        
        with get_db() as conn:
            cur = conn.cursor()
            
            for file in files:
                app.logger.debug(f"Processing file: {file.filename}")
                
                # Get next user_file_id
                cur.execute(
                    "SELECT COALESCE(MAX(user_file_id), 0) + 1 FROM files WHERE user_id = ?", 
                    (current_user.id,)
                )
                next_file_id = cur.fetchone()[0]
                
                # Handle duplicate filenames
                filename, ext = os.path.splitext(file.filename)
                counter = 0
                new_filename = file.filename
                
                while True:
                    cur.execute("""
                        SELECT COUNT(*) FROM files 
                        WHERE user_id = ? AND filename = ?
                    """, (current_user.id, new_filename))
                    
                    exists = cur.fetchone()[0] > 0
                    if not exists:
                        break
                        
                    counter += 1
                    new_filename = f"{filename}_{counter}{ext}"

                # Read file data and get content type
                file_data = file.read()
                content_type = file.content_type or 'application/octet-stream'
                filesize = len(file_data)
                
                # Create storage path
                storage_path = f"{current_user.id}/{next_file_id}/{new_filename}"
                
                # Upload to Cloud Storage
                public_url = storage.upload_file(
                    file_data,
                    storage_path,
                    content_type
                )
                
                # Save metadata to SQLite
                cur.execute(
                    """INSERT INTO files 
                       (user_file_id, user_id, filename, storage_path, mimetype, filesize) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (next_file_id, current_user.id, new_filename, storage_path, 
                     content_type, filesize)
                )
                
                uploaded_files.append({
                    'filename': new_filename,
                    'url': public_url
                })
                
                app.logger.info(f"Successfully uploaded: {new_filename}")
            
            conn.commit()
            
        return jsonify({
            "message": f"Successfully uploaded {len(uploaded_files)} file(s)",
            "files": uploaded_files
        })
        
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Retrieve file route
@app.route("/file/<int:file_id>")
@login_required
def get_file(file_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT filename, storage_path, mimetype 
            FROM files 
            WHERE user_file_id = ? AND user_id = ?
        """, (file_id, current_user.id))
        file = cur.fetchone()
        
    if file is None:
        abort(404)
    
    try:
        # Download from Cloud Storage
        file_data = storage.download_file(file[1])
        
        return send_file(
            io.BytesIO(file_data),
            mimetype=file[2],
            as_attachment=True,
            download_name=file[0]
        )
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        abort(500)

# List files route
@app.route("/files")
@login_required
def list_files():
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # First, verify table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
            if not cur.fetchone():
                app.logger.error("Files table does not exist")
                raise Exception("Database table 'files' not found")
            
            app.logger.debug(f"Fetching files for user {current_user.id}")
            
            # Debug: Check if user has any files
            cur.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (current_user.id,))
            count = cur.fetchone()[0]
            app.logger.debug(f"Found {count} files for user {current_user.id}")
            
            # Execute main query
            cur.execute("""
                SELECT user_file_id, filename, mimetype, filesize, 
                       upload_timestamp, storage_path 
                FROM files 
                WHERE user_id = ?
                ORDER BY upload_timestamp DESC
            """, (current_user.id,))
            
            rows = cur.fetchall()
            app.logger.info(f"Retrieved {len(rows)} files from database")
            
            files = []
            storage = CloudStorage()
            
            for row in rows:
                try:
                    file_url = storage.generate_signed_url(row[5])
                    files.append({
                        'user_file_id': row[0],
                        'filename': row[1],
                        'mimetype': row[2],
                        'size': round(row[3] / (1024 * 1024), 2),
                        'upload_date': row[4],
                        'public_url': file_url
                    })
                except Exception as e:
                    app.logger.error(f"Error processing file {row[1]}: {str(e)}")
                    continue
            
            return render_template('files.html', files=files)
            
    except Exception as e:
        app.logger.error(f"Error listing files: {str(e)}")
        traceback.print_exc()
        return render_template('error.html', error=str(e)), 500

# Delete files route
@app.route("/delete-files", methods=["POST"])
@login_required
def delete_files():
    try:
        data = request.get_json()
        file_ids = data.get('file_ids', [])
        
        if not file_ids:
            return jsonify({'error': 'No files selected'}), 400

        storage = CloudStorage()
        deleted_files = []
        
        with get_db() as conn:
            cur = conn.cursor()
            # Get all files in one query
            cur.execute("""
                SELECT user_file_id, storage_path, filename 
                FROM files 
                WHERE user_file_id IN ({}) AND user_id = ?
            """.format(','.join('?' * len(file_ids))), 
            (*file_ids, current_user.id))
            
            files_to_delete = cur.fetchall()
            
            # Batch delete from database first
            cur.execute("""
                DELETE FROM files 
                WHERE user_file_id IN ({}) AND user_id = ?
            """.format(','.join('?' * len(file_ids))), 
            (*file_ids, current_user.id))
            
            # Delete from storage in parallel
            for file_id, storage_path, filename in files_to_delete:
                try:
                    blob = storage.bucket.blob(storage_path)
                    if blob.exists():
                        blob.delete()
                    deleted_files.append(filename)
                except Exception as e:
                    app.logger.error(f"Storage deletion error for {filename}: {str(e)}")
            
            conn.commit()
        
        return jsonify({
            'message': f"Successfully deleted {len(deleted_files)} files",
            'deleted_count': len(deleted_files)
        })
            
    except Exception as e:
        app.logger.error(f"Delete error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Debug route
@app.route("/debug")
@login_required
def debug_info():
    try:
        db_status = "Connected"
        storage_status = "Connected"
        error_details = None
        
        # Test database connection
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM files")
            file_count = cur.fetchone()[0]
            
        # Test storage connection
        storage = CloudStorage()
        storage.bucket.exists()
        
        return jsonify({
            'database': db_status,
            'storage': storage_status,
            'file_count': file_count
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'trace': traceback.format_exc()
        }), 500

# Test upload route
@app.route("/test-upload", methods=["GET"])
@login_required
def test_upload():
    try:
        # Create test file
        test_data = b"Hello, World!"
        test_filename = "test.txt"
        storage_path = f"{current_user.id}/test/{test_filename}"
        
        # Upload to storage
        storage = CloudStorage()
        public_url = storage.upload_file(
            test_data,
            storage_path,
            "text/plain"
        )
        
        # Save to database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO files 
                (user_file_id, user_id, filename, storage_path, mimetype, filesize) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (1, current_user.id, test_filename, storage_path, "text/plain", len(test_data)))
            conn.commit()
            
        return jsonify({
            "message": "Test file uploaded successfully",
            "url": public_url
        })
    except Exception as e:
        app.logger.error(f"Test upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Basic HTML form for testing
@app.route("/")
def index():
    if not current_user.is_authenticated:
        return render_template("login.html")
    return render_template("index.html")

if __name__ == "__main__":
    # Set environment variables
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.join(
        os.path.dirname(__file__), 
        "service-account.json"
    )
    
    initialize_app()
    init_user_db()  # Initialize user database
    
    # Use environment variables for host and port
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_ENV") == "development"
    )

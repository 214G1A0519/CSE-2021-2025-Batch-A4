from flask import Flask, render_template, request, redirect, url_for, flash, session
import joblib
import numpy as np
import json
import pandas as pd
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# Create users.json if it doesn't exist
if not os.path.exists('users.json'):
    with open('users.json', 'w') as f:
        json.dump({}, f)

# Load the pre-trained models
models = {
    'randomforest': joblib.load('rf.pkl'),
    'logistic': joblib.load('logreg.pkl'),
    'svm': joblib.load('svm.pkl')
}

# Mapping dictionaries for categorical variables
mappings = {
    'Comm_Time': {'Day': 0, 'Night': 1},
    'Non_Std_Ports': {'No': 0, 'Yes': 1},
    'TLS_Validity': {
        'Invalid Certificates': 0,
        'Invalid/Self-signed': 1,
        'Invalid/Spoofed': 2,
        'Spoofed/Invalid': 3,
        'Valid Certificates': 4
    },
    'User_Agent': {
        'Spoofed/Altered': 0,
        'Spoofed/Encrypted': 1,
        'Spoofed/Malicious': 2,
        'Standard Agents': 3,
        'Standard/Modified': 4
    },
    'Exfil_Indicator': {
        'No': 0,
        'Yes': 1,
        'Yes (Double Extortion)': 2,
        'Yes (Extensive)': 3
    }
}

categories = {
    0: 'Akira',
    1: 'Benign',
    2: 'BlackCat',
    3: 'LockBit',
    4: 'Play Ransomware',
    5: 'Rhysida',
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with open('users.json', 'r') as f:
            users = json.load(f)
            
        if username in users and users[username]['password'] == password:
            session['username'] = username
            session.pop('filename', None)  # Clear filename on login
            flash('Successfully logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
            
        with open('users.json', 'r') as f:
            users = json.load(f)
            
        if username in users:
            flash('Username already exists', 'error')
            return render_template('signup.html')
            
        users[username] = {'password': password}
        
        with open('users.json', 'w') as f:
            json.dump(users, f)
            
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('filename', None)  # Clear filename on logout
    session.clear()
    flash('Successfully logged out!', 'success')
    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('aboutus.html')

@app.route('/detect', methods=['GET', 'POST'])
@login_required
def detect():
    predictions = []

    if request.method == 'POST':
        if 'csv_file' not in request.files or 'model' not in request.form:
            flash('Please select a model and upload a CSV file.', 'error')
            return redirect(request.url)

        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)

        if file:
            try:
                df = pd.read_csv(file)

                for column, mapping in mappings.items():
                    if column in df.columns:
                        df[column] = df[column].map(mapping)

                df = df.dropna()
                df = df.fillna(0)

                X = df.to_numpy()

                model_name = request.form['model']
                if model_name not in models:
                    flash('Invalid model selection!', 'error')
                    return redirect(request.url)

                model = models[model_name]
                predictions = [categories.get(pred, "Unknown") for pred in model.predict(X)]

                # Store uploaded file name in session
                session['filename'] = file.filename

            except Exception as e:
                flash(f'Error processing file: {e}', 'error')
                predictions = []

        return render_template(
            'detect.html',
            predictions=list(enumerate(predictions)),
            selected_model=model_name,
            filename=session.get('filename')
        )

    else:
        session.pop('filename', None)  # Clear filename if page is just loaded (GET)
        return render_template(
            'detect.html',
            predictions=None,
            selected_model='No model Selected',
            filename=None  # Explicitly send None
        )


@app.route('/detectload', methods=['GET', 'POST'])
@login_required
def detectload():
    prediction = None
    if request.method == 'POST':
        features = {
            'Domain_Entropy': float(request.form['Domain_Entropy']),
            'Vowel_Ratio': float(request.form['Vowel_Ratio']),
            'Domain_Length': int(request.form['Domain_Length']),
            'Outbound_Conn': int(request.form['Outbound_Conn']),
            'Packet_Size': float(request.form['Packet_Size']),
            'Comm_Time': mappings['Comm_Time'][request.form['Comm_Time']],
            'Non_Std_Ports': mappings['Non_Std_Ports'][request.form['Non_Std_Ports']],
            'Distinct_IPs': int(request.form['Distinct_IPs']),
            'TLS_Validity': mappings['TLS_Validity'][request.form['TLS_Validity']],
            'DNS_Query_Rate': float(request.form['DNS_Query_Rate']),
            'User_Agent': mappings['User_Agent'][request.form['User_Agent']],
            'Exfil_Indicator': mappings['Exfil_Indicator'][request.form['Exfil_Indicator']]
        }

        X = np.array([list(features.values())])
        model_name = request.form['model']
        model = models[model_name]
        prediction = categories[model.predict(X)[0]]

    return render_template('detectload.html', prediction=prediction)

if __name__ == '__main__':
    app.run(debug=True)

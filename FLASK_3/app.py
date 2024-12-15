"""

Name: Gokhan Unal
Date: <11/27/2024><12/04/2024>
Assignment: #14 FLASK - Delete a user via sending encrypted message (HMAC)
Due Date: <12/04/2024>
Explanations & Assumptions:
The sixth flask homework, built on module 13. app.py below.
CSS updated on <11/17/2024> Please run BakingContestPeopleCreateDB.py
and BakingContestEntryCreateDB.py before running the app.py
If you choose to run this file on its own, please
comment-in line 381 in this script (give a keyboard interrupt to the
currently running server if you get one socket error), if not start running by server_starter.py
Pylint score: 8.63/10

"""

import os
import sqlite3
import subprocess
import socket
import hmac
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session, flash, render_template_string
from BakingContestPeopleCreateDB import decrypt
from config import SECRET_KEY

# load the secret key and save it as the cipher
# with open('secret.key') as key_file:
    #key = key_file.read()
cipher = Fernet(SECRET_KEY)

# load the key with read binary mode
with open('hmac_key.key', 'rb') as key_file:
    hmac_key = key_file.read()
#print("HMAC key loaded")


# print the random hex key and save it as the app's secret key
#print(os.urandom(24).hex())

# Create the app object
app = Flask(__name__)
app.secret_key = '592df6d60ee516ae3cb7ec128c59987f6ecd04e2c10a4b44'

# added for module 13
@app.route('/submit_vote', methods=['GET', 'POST'])
def submit_vote():
    """ Submit vote for baking contest entries """
    if 'user_id' not in session or int(session['security_level']) < 2:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entry_id = request.form.get('entry_id')
        excellent_votes = request.form.get('excellent_votes')
        ok_votes = request.form.get('ok_votes')
        bad_votes = request.form.get('bad_votes')

        # Input validation
        error_list:list = []
        if not entry_id.isdigit() or int(entry_id) <= 0:
            error_list.append("EntryId must be a numeric value greater than 0.")
        if not excellent_votes.isdigit() or int(excellent_votes) < 0:
            error_list.append("Number of Excellent Votes must be a numeric value >= 0.")
        if not ok_votes.isdigit() or int(ok_votes) < 0:
            error_list.append("Number of Ok Votes must be a numeric value >= 0.")
        if not bad_votes.isdigit() or int(bad_votes) < 0:
            error_list.append("Number of Bad Votes must be a numeric value >= 0.")

        # Check if EntryId exists in the database
        con = sqlite3.connect('baking_contest.db')
        cursor = con.cursor()
        cursor.execute('SELECT 1 FROM BakingContestEntry WHERE EntryID = ?', (entry_id,))
        if cursor.fetchone() is None:
            error_list.append("EntryId does not exist in the BakingContestEntry table.")
        con.close()

        # print out the error list if anything is in it
        if error_list:
            print(f"Validation errors: {error_list}")
            return render_template('result.html', msg='<br>'.join(error_list))

        # Update the entry in the database directly
        try:
            con = sqlite3.connect('baking_contest.db')
            cursor = con.cursor()
            cursor.execute('''
                UPDATE BakingContestEntry
                SET NumExcellentVotes = NumExcellentVotes + ?,
                    NumOkVotes = NumOkVotes + ?,
                    NumBadVotes = NumBadVotes + ?
                WHERE EntryID = ?
            ''', (excellent_votes, ok_votes, bad_votes, entry_id))
            con.commit()
            con.close()
            print(f"127.0.0.1 -- sent message: {entry_id}^%${excellent_votes}^%${ok_votes}^%${bad_votes}")  # Print statement
            print(f"entryId: {entry_id}")
            return render_template('result.html', msg="Vote successfully sent")
        except Exception as e:
            print(f"Error updating the database: {e}")  # Print statement
            return render_template('result.html', msg="Error - Vote NOT sent")

    return render_template('submit_vote.html')


# Home route
@app.route('/')
def home():
    """ Renders the home page based on session info """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # try except block
    try:
        print(f"User ID: {session['user_id']}, Username: {session['username']}, Security Level: {session['security_level']}")  # Debug print
        return render_template('home.html', username=session['username'], security_level=session['security_level'])
    except Exception as e:
        print(f"Error loading home page: {e}")
        return redirect(url_for('login'))


@app.route('/add_new_user', methods=["GET", "POST"])
def add_new_user():
    """ Add new user to BakingContestPeople database """
    if 'user_id' not in session or session['security_level'] != '3':
        return redirect(url_for('login'))
    if request.method == 'POST':
        Name = request.form.get('Name')
        Age = request.form.get('Age')
        PhNum = request.form.get('PhNum')
        SecurityLevel = request.form.get('SecurityLevel')
        LoginPassword = request.form.get('LoginPassword')

        # Input validation
        error_list = []
        if not Name.strip():
            error_list.append("Name is a required field!")
        if not Age.isdigit() or not 0 < int(Age) < 121:
            error_list.append("Age must be a whole number AND between 0 and 121!")
        if not PhNum.strip():
            error_list.append("PhNum is a required field!")
        if not SecurityLevel.isdigit() or not 1 <= int(SecurityLevel) <= 3:
            error_list.append("SecurityLevel must be a whole number AND between 1 and 3!")
        if not LoginPassword.strip():
            error_list.append("LoginPassword is a required field!")
        # render result.html. Join each error message in the error list
        if error_list:
            return render_template('result.html', msg='<br>'.join(error_list))

        # encrypting block - added on 11/17/2024
        encrypt_name = cipher.encrypt(Name.encode('utf-8'))
        encrypt_phnum = cipher.encrypt(PhNum.encode('utf-8'))
        encrypt_password = cipher.encrypt(LoginPassword.encode('utf-8'))

        # establish connection
        con = sqlite3.connect('baking_contest.db')
        cursor = con.cursor()
        try:
            cursor.execute(
                'INSERT INTO BakingContestPeople (Name, Age, PhNum, SecurityLevel, LoginPassword) VALUES (?, ?, ?, ?, ?)',
                (encrypt_name, Age, encrypt_phnum, SecurityLevel, encrypt_password)) # change 3 fields to encrypted versions
            # commit the changes
            con.commit()
        except Exception as e:
            print(f"Error: {e}")
            return "Internal Server Error", 500  # Return a 500 error with the error message
        finally:
            # close the connection
            con.close()

        # render the result.html after successful user addition
        return render_template('result.html', msg='User added successfully!')
    # render the add_new_user.html and return it
    return render_template('add_new_user.html')


# List users/bakers
@app.route('/list_users')
def list_users()-> str:
    """ List all bakers in the BakingContestPeople table """
    # if not in session ask for a login. Levels 2 and 3
    if 'user_id' not in session or session['security_level'] not in ['2', '3']:
        return redirect(url_for('login'))
    # establish connection
    con = sqlite3.connect('baking_contest.db')
    con.row_factory = sqlite3.Row
    # select all rows from the BakingContestPeople table
    users: list = con.execute('SELECT * FROM BakingContestPeople').fetchall()

    # 11/17/2024, decrypt Name, PhNum, LoginPassword
    view_decrypted_users: list = []
    # loop through, decrypt and view
    for user in users:
        decrypt_user = {
            'UserID': user['UserID'],
            'Name' : decrypt(user['Name']),
            'Age' : user['Age'],
            'PhNum' : decrypt(user['PhNum']),
            'SecurityLevel' : user['SecurityLevel'],
            'LoginPassword' : decrypt(user['LoginPassword']),
        }
        # append user to the decrypted view list
        view_decrypted_users.append(decrypt_user)

    con.commit()
    # close the connection
    con.close()
    # render list_user.html and return  it
    return render_template('list_users.html', users=view_decrypted_users)


@app.route('/list_results')
def list_results() -> list:
    """ List baking contest results for ALL bakers. """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    con = sqlite3.connect('baking_contest.db')
    con.row_factory = sqlite3.Row
    cursor = con.cursor()
    try:
        baking_contest_results: list = cursor.execute('SELECT * FROM BakingContestEntry').fetchall()
        print(f"Baking Contest Results: {baking_contest_results}")  # Debugging print statement

        # decrypted results for all bakers
        decrypted_baking_contest_results: list = []
        for row in baking_contest_results:
            try:
                decrypted_row = {
                    'EntryId': row['EntryId'],
                    'UserID': row['UserID'],
                    'NameOfBakingItem': row['NameOfBakingItem'],
                    'NumExcellentVotes': row['NumExcellentVotes'],
                    'NumOkVotes': row['NumOkVotes'],
                    'NumBadVotes': row['NumBadVotes'],
                }
                decrypted_baking_contest_results.append(decrypted_row)
            except KeyError as e:
                print(f"Key Error: {e}")
                return "Internal Server Error - Key Error", 500  # Return a 500 error with the error message
            except Exception as e:
                print(f"Decryption Error: {e}")
                return "Internal Server Error - Decryption Error", 500  # Return a 500 error with the error message
    except Exception as e:
        print(f"Error: {e}")
        return "Internal Server Error", 500  # Return a 500 error with the error message
    finally:
        # close the connection
        con.close()

    return render_template('list_results.html', baking_contest_results=decrypted_baking_contest_results)


@app.route('/list_individual_results')
def list_individual_results():
    """ List baking contest results for the current logged-in user/baker.
        Same as list_results, only the SQL statement is different """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    con = sqlite3.connect('baking_contest.db')
    con.row_factory = sqlite3.Row
    # cursor = con.cursor()
    baking_contest_individual_results = (
        con.execute('SELECT * FROM BakingContestEntry WHERE UserID = ?', (session['user_id'],)).fetchall())
    print(f"Baking Contest Results: {baking_contest_individual_results}")  # Debugging print statement
    con.close()
    return render_template('list_results.html', baking_contest_results=baking_contest_individual_results)


# Log in
@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Login to the website """
    if request.method == 'POST':
        # request the username and password entries from the form
        username = request.form['username']
        password = request.form['password']
        print(f"Username entered: {username}, Password entered: {password}")  # Debug print
        user, error_msg = vet_user(username, password)
        # if a user exists map the actual table column names from the
        # BakingContestPeople table to session variables
        if user:
            session['user_id'] = user['UserID']
            session['username'] = decrypt(user['Name'])
            session['security_level'] = user['SecurityLevel']
            print(f"Logged in: User ID: {session['user_id']}, Username: {session['username']}, "
                  f"Security Level: {session['security_level']}")  # Debugging print statement
            return redirect(url_for('home'))
        else:
            if error_msg == 'Username mismatch':
                flash('Invalid username!')
                print("Invalid username!")  # Debug print
            elif error_msg == 'Password mismatch':
                flash('Invalid password!')
                print("Invalid password!")  # Debug print
            else:
                flash('Login error, please try again.')
                print("Login error, please try again.")  # Debug print
    return render_template('login.html')


def vet_user(username, password):
    """ Vet and verify if user exists and the password matches the username """
    # establish connection and get the rows
    con = sqlite3.connect('baking_contest.db')
    con.row_factory = sqlite3.Row
    user = None  # Initialize user to None
    error_msg = None  # Initialize error message to None
    try:
        # get all users
        users = con.execute('SELECT * FROM BakingContestPeople').fetchall()

        # Iterate through users to find a match
        for x in users:
            # Decrypt the username and password from the database
            decrypted_username = decrypt(x['Name'])
            decrypted_password = decrypt(x['LoginPassword'])

            # if a match is found, set the user and break
            if decrypted_username == username and decrypted_password == password:
                user = x
                error_msg = None
                break
            # error cases
            elif decrypted_username != username:
                print(f"Username mismatch: {decrypted_username} != {username}")
                error_msg = 'Username mismatch!'
            elif decrypted_password != password:
                print(f"Password mismatch for user {decrypted_username}")
                error_msg = 'Password mismatch!'
        print(f"User found: {user}")  # Debug print
    except Exception as e:
        print(f"Error: {e}")
        error_msg = 'Database error'
    con.close()
    # return the user and error messages if any
    return user, error_msg


# Log out
@app.route('/logout')
def logout():
    """ clear session and logout """
    # end the session
    session.clear()
    return render_template('logout.html')


# add new baking contest entry
@app.route('/add_entry', methods=['GET', 'POST'])
def add_entry():
    """ Add a baking contest entry to the BakingContestEntry table
        the contest entry will be tied to the current logged-in user's
        UserID """
    # if not in session, ask for a login
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # if logged in, fill in the form
    if request.method == 'POST':
        name = request.form['name']
        excellent = request.form['excellent']
        ok = request.form['ok']
        bad = request.form['bad']
        # input validation
        if name.strip() and excellent.isdigit() and ok.isdigit() and bad.isdigit():
            # establish connection
            con = sqlite3.connect('baking_contest.db')
            con.execute(
                'INSERT INTO BakingContestEntry (UserID, NameOfBakingItem, '
                'NumExcellentVotes, NumOkVotes, NumBadVotes) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], name, excellent, ok, bad))
            # commit changes and close the connection
            con.commit()
            con.close()
            # flash the message
            flash('Record added successfully!')
        # invalid input case
        else:
            flash('Invalid input!')
        # redirect to add_entry
        return redirect(url_for('add_entry'))
    # render the add_baking_contest_entry.html
    return render_template('add_baking_contest_entry.html')


def encrypt_m(message: bytes, key: bytes) -> bytes:
    """ encrypt the message - module #14 """
    cipher = AES.new(key, AES.MODE_CBC) # no specific reason for mode_cbc
    # generate the ciphertext bytes
    ciphertext_bytes: bytes = cipher.encrypt(pad(message, AES.block_size))
    i_vector: str = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext: str = base64.b64encode(ciphertext_bytes).decode('utf-8')
    # return the encrypted message
    return f"{i_vector}:{ciphertext}".encode('utf-8')


@app.route('/delete_baking_entry', methods=['GET', 'POST'])
def delete_baking_entry():
    """ Delete baking contest entry from the BakingContestEntry table - module #14 """
    if request.method == 'POST':
        entry_id = request.form['entry_id']

        if not entry_id.isdigit() or int(entry_id) <= 0:
            flash("Input validation error: EntryId must be a numeric value greater than 0")
            return redirect(url_for('delete_baking_entry'))
        # establish the connection to sqlite3
        con = sqlite3.connect('baking_contest.db')
        cursor = con.cursor()
        cursor.execute('SELECT 1 FROM BakingContestEntry WHERE EntryID = ?', (entry_id,))
        if cursor.fetchone() is None:
            con.close()
            flash("EntryId does not exist in the BakingContestEntry table")
            return redirect(url_for('delete_baking_entry'))
        con.close()
        # encode the entry id
        message = entry_id.encode('utf-8')
        # get the encrypted message via its entry id encoded
        encrypted_message = cipher.encrypt(message)

        # create the HMAC digest
        hmac_digest = hmac.new(hmac_key, encrypted_message, hashlib.sha3_512).digest()

        # try except block
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', 8888)) # the socket is listening on port 8888
                s.sendall(hmac_digest + encrypted_message)
                # decode the message
                response = s.recv(1024).decode()
                if response == 'success':
                    flash("Message to Delete Baking Contest Entry successfully sent!!")
                else:
                    flash("*ERROR* - Message to Delete Baking Contest Entry NOT sent!!")
        except Exception as e:
            print(f"Error: {e}")
            flash("*ERROR* - Message to Delete Baking Contest Entry NOT sent!!")
        return redirect(url_for('delete_baking_entry'))

    return render_template('delete_baking_entry.html')


# name block
if __name__ == '__main__':
    # Run the database setup scripts
    #subprocess.run(['python', 'server_starter.py'], check=True)
    subprocess.run(['python', 'BakingContestPeopleCreateDB.py'], check=True)
    subprocess.run(['python', 'BakingContestEntryCreateDB.py'], check=True)

    # Run the Flask app
    app.run(debug=True)

import mysql.connector
import csv
import random
from io import StringIO
from flask import Flask, render_template, url_for, redirect, flash, session, Response, request
from info import RegisterForm, LoginForm, OTPForm, PhishingDetectionForm
from model_development.model_check import predict_url_legitimacy
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import smtplib
from email.mime.text import MIMEText
import random

# run below code if database is not present 👇       in the field of password put your mysql password
# # Create the database
# mydb = mysql.connector.connect(host="localhost", user="root", password="password")
# mycursor = mydb.cursor()
# database_name = "phishing_detection"

# mycursor.execute(f"CREATE DATABASE {database_name}")
# print(f"The database '{database_name}' has been created.")
# # Use the database
# mycursor.execute(f"USE {database_name}")

# --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
mydb = mysql.connector.connect(host="localhost", user="root", password="Password", database="phishing_detection")

mycursor = mydb.cursor()
table = "person_data"
table1 = "url_table"
# Check if the person_data exist
query = "SHOW TABLES LIKE %s"
mycursor.execute(query, (table,))
result = mycursor.fetchone()

# Create the person_data if it does not exist
if result:
    print(f"'{table}' is present.'")
else:
    if not result:
        mycursor.execute(f"CREATE TABLE {table} (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, password VARBINARY(255) NOT NULL)")
        print(f"The table '{table}' has been created.")
        mydb.commit()

# Check if the table 'url_table' exists
mycursor.execute(query, (table1,))
result1 = mycursor.fetchone()

# Create the 'url_table' table if it does not exist
if result1:
    print(f"'{table1}' is present.")
else:
    mycursor.execute(f"""CREATE TABLE {table1} (id INT AUTO_INCREMENT PRIMARY KEY, url VARCHAR(2083) NOT NULL, prediction_result TINYINT(1) NOT NULL);""")
    print(f"The table '{table1}' has been created.")
    mydb.commit()

#........................Encryption.............................
def key_generate():
    salt = b'\xcf\x87\xfb\xfd\x1c\xbbx\xa7'
    password= 'not known'
    key = PBKDF2(password, salt, dkLen=8)
    return key

def Encrypt(password):
    key = key_generate()
    cipher = DES.new(key, DES.MODE_ECB)
    # Encrypt the password
    padded_password = pad(password.encode(), DES.block_size)
    enc_pass = cipher.encrypt(padded_password)
    return enc_pass 

#........................Decryption.............................
def Decrypt(password):
    key = key_generate()

    cipher = DES.new(key, DES.MODE_ECB)
    # Decrypt the password
    decrypted_data = cipher.decrypt(password)
    unpadded_data = unpad(decrypted_data, DES.block_size).decode()
    return unpadded_data

# --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = "123456asamd"  # any password

# Main page 👇
@app.route("/")
def home():
    # Clear all session data when navigating to the home page
    session.clear()
    return render_template("index.html")



my_email = "email"
password = "password"  # Replace with your actual app password

def send_email(to_email, subject, body):
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        message = f"Subject:{subject}\n\n{body}"
        connection.sendmail(from_addr=my_email, to_addrs=to_email, msg=message)


# ...............................................Call the function to send OTP to user ................................................

def send_otp(email, otp):
    sender_email = "email here"
    sender_password = "password"  
    
    # Set up the email content
    msg = MIMEText(f"Your OTP for login is: {otp}")
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = sender_email
    msg['To'] = email

    # Send the email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com') as server:
            # server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
        print("OTP sent successfully")
    except Exception as e:
        print(f"Error sending OTP: {e}")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        epassword = Encrypt(login_form.password.data)
        query = f"SELECT * FROM {table} WHERE email = %s AND password = %s"
        mycursor.execute(query, (login_form.email.data, epassword))
        user = mycursor.fetchone()

        if user:
            session['user_id'] = user[0]
            otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
            session['otp'] = otp  # Store the OTP in the session
            session['email'] = login_form.email.data  # Store the email in the session
            
            send_otp(login_form.email.data, otp)  # Send the OTP to the user's email
            
            return redirect(url_for('otp_verification'))
        else:
            return redirect(url_for('register_page'))
        
    return render_template('login.html', form=login_form)

@app.route("/otp_verification", methods=["GET", "POST"])
def otp_verification():
    form = OTPForm()
    
    if 'otp' not in session or 'email' not in session:
        return redirect(url_for('login_page'))
    
    if form.validate_on_submit():
        entered_otp = form.otp.data
        if int(entered_otp) == session['otp']:
            # OTP is correct, proceed to the main web page
            session.pop('otp')  # Remove OTP from session after successful verification
            return redirect(url_for('input_web_page'))
        else:
            flash("Invalid OTP. Please try again.")
    
    return render_template('otp_verification.html', form=form)


@app.route('/register', methods=["GET", "POST"])
def register_page():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if register_form.password.data == register_form.re_password.data:
            epassword = Encrypt(register_form.password.data)
            # print(epassword)
            # Check if the email is already registered
            query = f"SELECT * FROM {table} WHERE email = %s"
            mycursor.execute(query, (register_form.email.data,))
            existing_user = mycursor.fetchone()

            if existing_user:
                # If email exists, redirect to login page with a flash message
                # flash("You are already registered. Please log in.")
                return redirect(url_for('login_page'))

            # Insert the new user record if email does not exist
            sql = f"INSERT INTO {table} (username, email, password) VALUES (%s, %s, %s)"
            val = (register_form.name.data, register_form.email.data, epassword)
            try:
                mycursor.execute(sql, val)
                mydb.commit()
                # After successful registration, redirect to the main web page
                session['user_id'] = mycursor.lastrowid  # Set user_id in session
                return redirect(url_for('web_page'))
            except Exception as e:
                print(f"Error inserting user: {e}")
                # flash("An error occurred while registering. Please try again.")
                return render_template("register.html", form=register_form)
        else:
            # flash("Passwords do not match!")
            return render_template("register.html", form=register_form)
    
    return render_template("register.html", form=register_form)


@app.route('/logout')
def logout():
    # Remove the user_id from the session
    session.pop('user_id', None)
    # Redirect to home page after logging out
    return redirect(url_for('home'))

@app.route('/about')
def about_us_page():
    return render_template('about_us.html')

@app.route('/fraud_detection')
def fraud_detection():
    return render_template('fraud_detection_page.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')


# -------------------------------------------------------------------------------------------

@app.route('/input_web_page', methods=["GET", "POST"])
def input_web_page():
    form = PhishingDetectionForm()
    if 'user_id' in session:
        if form.validate_on_submit():
            url = form.url.data
            result = predict_url_legitimacy(url)
            print(result)

            # Insert data into the 'real_time_data' table
            insert_query = f"""INSERT INTO {table1} (url, prediction_result) VALUES (%s, %s)"""
            values = (url, result)
            mycursor.execute(insert_query, values)
            mydb.commit()
            return render_template("url_result.html", url=url,  result=result)
        return render_template("url_input.html", form=form)
    else:
        return redirect(url_for('url_input'))

# # result= extract_features(url_to_check)
# result = predict_url_legitimacy("https://www.youtube.com/")

# # Output the features
# print("Extracted Features:", result)


@app.route('/show_data')
def show_data():
    query = f"SELECT * FROM {table1}"
    mycursor.execute(query)
    data = mycursor.fetchall()
    Data = []
    for row in data:
        # url = row[1]
        # prediction_result = row[2]
        masked_row = list(row)
        masked_row[1] = row[1] 
        masked_row[2] = row[2] 
        Data.append(tuple(masked_row))
    return render_template('show_data.html', data=Data)

@app.route('/delete/<int:id>', methods=['POST'])
def delete_data(id):
    try:
        delete_query = f"DELETE FROM {table1} WHERE id = %s"
        mycursor.execute(delete_query, (id,))
        mydb.commit()
    except Exception as e:
        print(f"Error deleting record: {e}")
    return redirect(url_for('show_data'))

@app.route('/download_csv')
def download_csv():
    try:
        query = f"SELECT * FROM {table1}"
        mycursor.execute(query)
        rows = mycursor.fetchall()

        # Create a CSV file in memory
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['Serial No.', 'URL', 'Prediction Result'])

        # Populate CSV with data
        for index, row in enumerate(rows, start=1):
            url = row[1]  # Assuming URL is in the second column (index 1)
            prediction_result = "Legitimate" if row[2] == 0 else "Phishing"  # Map prediction result
            writer.writerow([index, url, prediction_result])

        # Set up the response
        output = Response(si.getvalue(), mimetype='text/csv')
        output.headers['Content-Disposition'] = 'attachment; filename=URL_check_history.csv'

        return output
    except Exception as e:
        print(f"Error generating CSV: {e}")
        flash("An error occurred while generating the CSV file. Please try again.", "danger")
        return redirect(url_for('show_data'))

@app.route('/download_fraud_csv')
def download_fraud_csv():
    try:
        query = f"SELECT * FROM {table1} WHERE prediction_result = 1"
        mycursor.execute(query)
        rows = mycursor.fetchall()

        # Create a CSV file in memory
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['Serial No.', 'URL', 'Prediction Result'])

        for index, row in enumerate(rows, start=1):
            url = row[1]  # Assuming URL is in the second column (index 1)
            prediction_result = "Phishing"
            writer.writerow([index, url, prediction_result])

        # Set up the response
        output = Response(si.getvalue(), mimetype='text/csv')
        output.headers['Content-Disposition'] = 'attachment; filename=phishing_URLs_data.csv'

        return output
    except Exception as e:
        print(f"Error generating CSV: {e}")
        flash("An error occurred while generating the fraud CSV file. Please try again.", "danger")
        return redirect(url_for('show_data'))


# -------------------------------------------------------------------------------------------


if __name__ =="__main__":
    app.run(debug=True, port=5002)


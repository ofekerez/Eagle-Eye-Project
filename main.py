import random
import smtplib
import string

from flask import *
from flask_sqlalchemy import SQLAlchemy

import bin.PACKET_SNIFFER as snf
import bin.helper_methods as helper_methods
from bin.New_Port_Scanner import PortScanner

app = Flask(__name__, template_folder=r'D:\Eagle-Eye Project\templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = '12ojby312bAsjd' + random.choice(string.ascii_lowercase) + random.choice(string.digits)

# Creating an SQLAlchemy instance
db = SQLAlchemy(app)
reset_auth = ''


# EagleEyeProject1@gmail.com
# eagleeyeproject1
# Models

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), unique=False, nullable=False)
    lastname = db.Column(db.String(20), unique=False, nullable=False)
    username = db.Column(db.String(20), unique=False, nullable=False)
    password = db.Column(db.String(20), unique=False, nullable=False)
    checkpassword = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(20), unique=False, nullable=False)

    def __init__(self, firstname, lastname, username, password, checkpassword, email):
        self.email = email
        self.checkpassword = checkpassword
        self.password = password
        self.username = username
        self.firstname = firstname
        self.lastname = lastname

    # repr method represents how one object of this datatable
    # will look like
    @property
    def __repr__(self):
        return f"Name : {self.first_name}, Username: {self.username}"


@app.route('/', methods=['GET'])
def index_page():
    return render_template("login.html")


@app.route("/authenticate")
def authenticate():
    code = ''
    for i in range(8):
        code += random.choice(string.digits)

    gmail_user = "EagleEyeProject1@gmail.com"
    gmail_password = 'eagleeyeproject1'
    destination_gmail = Profile.query.filter_by(username=session["username"]).first().email
    print(destination_gmail)
    subject = 'Authentication Message'
    body = code

    email_text = f"""\
    From: {gmail_user}\n
    To: {", " + destination_gmail}\n
    Subject: {subject}\n
    {body}
    """

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(gmail_user, gmail_password)
        server.sendmail(gmail_user, destination_gmail, email_text)
    except Exception as e:
        print(e)
        return render_template('login.html')
    return render_template("Authentication.html", content=code)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    find_user = Profile.query.filter_by(username=username, password=password).first()
    # find_pass=Profile.query.filter_by(password=password)
    if find_user:
        session["username"] = request.form.get("username")
        session["password"] = request.form.get("password")
        return redirect(url_for('authenticate'))
    else:
        return redirect(url_for('index_page'))


@app.route("/ScanResults")
def func1():
    return render_template("ScanResults.html")


@app.route("/SniffResults")
def func2():
    return render_template("SniffResults.html")


@app.route("/about")
def func3():
    return render_template("About.html")


@app.route("/Shell")
def func4():
    return render_template("ConnectToShell.html")


@app.route("/auth/register", methods=['POST'])
def Register():
    # In this function we will input data from the
    # form page and store it in our database.
    # Remember that inside the get the name should
    # exactly be the same as that in the html
    # input fields
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    username = request.form.get("username")
    password = request.form.get("password")
    checkpassword = request.form.get("checkpassword")
    email = request.form.get("email")

    # create an object of the Profile class of models
    # and store data as a row in our datatable
    find_user_username = Profile.query.filter_by(username=username).first()
    find_user_email = Profile.query.filter_by(email=email).first()
    if find_user_username or find_user_email:
        flash("Username or Email already exists")
        return get_register()
    else:
        if firstname != '' and lastname != '' and username != '' and password != '' and checkpassword != '' and email != '':
            p = Profile(firstname=firstname, lastname=lastname, username=username, password=password,
                        checkpassword=checkpassword, email=email)
            db.session.add(p)
            db.session.commit()
            session["username"] = request.form.get("username")
            session["password"] = request.form.get("password")
            return render_template("RegisteredSuccessfully.html")
        # return render_template("PersonalArea.html")


@app.route("/SniffResults/Activate")
def sniff():
    st = ''
    sorted_packets = snf.gen_sniff()
    st += snf.filter_HTTP(sorted_packets[0]) + snf.filter_ICMP(sorted_packets[1]) + snf.filter_SMB(sorted_packets[2])
    st += snf.filter_FTP(sorted_packets[3]) + snf.filter_SSH(sorted_packets[4]) + snf.filterstringDNS(
        sorted_packets[5]) + snf.filter_DHCP(sorted_packets[6])
    return render_template("SniffResults.html", content=st.split('\n')[:-1])


@app.route("/ScanResults/SYN/<ip_address>")
def TCP_SYN_scan(ip_address):
    open_ports = PortScanner(ip_address).SYN_Scan_Wrap()
    st = ''
    for open_port in open_ports:
        st += f"Port {open_port} is open!" + '\n'
    return render_template('ScanResults.html', content=st.split('\n')[:-1])


@app.route("/ScanResults/Stealth/<ip_address>")
def TCP_Stealth_scan(ip_address):
    open_ports = PortScanner(ip_address).Stealth_Scan_Wrap()
    st = ''
    for open_port in open_ports:
        st += f"Port {open_port} is open!" + '\n'
    return render_template('ScanResults.html', content=st.split('\n')[:-1])


@app.route("/ScanResults/UDP/<ip_address>")
def UDP_port_scan(ip_address):
    open_ports = PortScanner(ip_address).UDP_Scan_Wrap()
    st = ''
    for open_port in open_ports:
        st += f"Port {open_port} is open!" + '\n'
    return render_template('ScanResults.html', content=st.split('\n')[:-1])


@app.route("/logout", methods=['GET', 'POST'])
def Logout():
    session["username"] = None
    return render_template("LoggedOutSuccessfully.html")


@app.route("/register", methods=["GET"])
def get_register():
    return render_template("register.html")


@app.route('/index')
def network_mapping():
    return render_template('ActiveIPs.html')


@app.route('/getemail', methods=['POST'])
def get_email():
    global reset_auth
    mail = request.form.get("email")
    print(mail)
    session["email"] = mail
    code = ''
    for i in range(8):
        code += random.choice(string.digits)
    reset_auth = code
    gmail_user = "EagleEyeProject1@gmail.com"
    gmail_password = 'eagleeyeproject1'

    subject = 'Authentication Message'
    body = code

    email_text = f"""\
       From: {gmail_user}\n
       To: {", " + mail}\n
       Subject: {subject}\n
       {body}
       """

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(gmail_user, gmail_password)
        server.sendmail(gmail_user, mail, email_text)
    except Exception as e:
        print(e)
    return render_template('CodeSentSuccessfully.html')


@app.route('/ResetPassword', methods=['GET'])
def reset_wrap():
    return render_template('AuthReset.html')


@app.route('/reset', methods=['GET'])
def reset():
    return render_template('ResetPassword.html')


@app.route('/resetdone', methods=['POST'])
def reset_password():
    code = request.form.get("authcode")
    global reset_auth
    if code == reset_auth:
        admin = Profile.query.filter_by(email=session["email"]).first()
        admin.password = request.form.get("password")
        db.session.commit()
        return render_template("ResetSuccessfully.html")
    print("Incorrect")
    return redirect(url_for('reset_wrap'))


@app.route('/active_ips', methods=['POST'])
def map_network():
    import threading
    subnet_mask = request.form.get("subnet")
    clients = []
    threads = []
    LOCK = threading.Lock()
    if subnet_mask:
        result = helper_methods.check_hosts(subnet_mask)
        for address in result.split('\n')[:-1]:
            t = threading.Thread(target=helper_methods.scanner, args=(address, LOCK, clients))
            t.start()
            threads.append(t)

        return render_template("ActiveIPs.html", content=clients)
    return render_template("ActiveIPs.html")


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, host="0.0.0.0")

from flask import *
from flask_sqlalchemy import SQLAlchemy

import bin.PACKET_SNIFFER as snf
import bin.Port_Scanner as ps
import string
import random

app = Flask(__name__, template_folder=r'D:\Eagle-Eye Project\templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = '12ojby312bAsjd' + random.choice(string.ascii_lowercase) + random.choice(string.digits)

# Creating an SQLAlchemy instance
db = SQLAlchemy(app)


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
        return f"Name : {self.first_name}, Age: {self.age}"


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        find_user = Profile.query.filter_by(username=username, password=password).first()
        # find_pass=Profile.query.filter_by(password=password)
        if find_user:
            session["username"] = request.form.get("username")
            return redirect(url_for('ActiveIPs.html'))
        else:
            return render_template("login.html")
    elif request.method == "GET":
        return render_template("login.html")
    else:
        print("WTF")


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
    print("HEllo")
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
    st = snf.filter_HTTP(sorted_packets[0]) + snf.filter_ICMP(sorted_packets[1]) + snf.filter_SMB(sorted_packets[2])
    st += snf.filter_FTP(sorted_packets[3]) + snf.filter_SSH(sorted_packets[4]) + snf.filterstringDNS(
        sorted_packets[5]) + snf.filter_DHCP(sorted_packets[6])
    return render_template("SniffResults.html", content=st.split('\n'))


@app.route("/ScanResults/SYN/<ip_address>")
def TCP_SYN_scan(ip_address):
    open_ports = ps.SYN_Scan(ip_address)
    st = ''
    for open_port in open_ports:
        st += f"Port {open_port} is open!" + '\n'
    return render_template('ScanResults.html', content=st.split('\n'))


@app.route("/ScanResults/Stealth/<ip_address>")
def TCP_Stealth_scan(ip_address):
    open_ports = ps.Stealth_Scan(ip_address)
    st = ''
    for open_port in open_ports:
        st += f"Port {open_port} is open!" + '\n'
    return render_template('ScanResults.html', content=st.split('\n'))


@app.route("/ScanResults/UDP/<ip_address>")
def UDP_port_scan(ip_address):
    open_ports = ps.UDP_Scan(ip_address)
    st = ''
    for open_port in open_ports:
        st += f"Port {open_port} is open!" + '\n'
    return render_template('ScanResults.html', content=st.split('\n'))


@app.route("/logout", methods=['GET', 'POST'])
def Logout():
    session["username"] = None
    return render_template("logout.html")


@app.route("/register", methods=["GET"])
def get_register():
    return render_template("register.html")


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, host="0.0.0.0")

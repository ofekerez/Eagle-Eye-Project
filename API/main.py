import bin.Packages_Installer
import hashlib
import random
import string
from flask import *
from flask_sqlalchemy import SQLAlchemy
import bin.helper_methods as helper_methods
from bin.Client import Client
from bin.Webshell_Server import Server
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import threading
import time

app = Flask(__name__, static_folder=r'..\API', template_folder=r'..\API\templates')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = '12ojby312bAsjd' + random.choice(string.ascii_lowercase) + random.choice(string.digits)

# Creating an SQLAlchemy instance
db = SQLAlchemy(app)
reset_auth = ''


class Helper:
    """A class designed to help store useful variables"""

    def __init__(self):
        self.__code = ''
        self.__username = ''
        self.active_ips = []
        self.API_KEY = os.getenv('MAIL_API_KEY')
        print(self.API_KEY)

    def connect(self):
        self.server = Server()
        self.server.connect()

    def execute_command(self, command: str):
        self.server.command = command
        res = self.server.execute()
        return res

    def get_cwd(self):
        return self.server.cwd

    def get_code(self):
        return self.__code

    def set_code(self, code: str):
        self.__code = code


helper = Helper()


# EagleEyeProject1@gmail.com
# eagleeyeproject1
# Models

class Profile(db.Model):
    firstname = db.Column(db.String(20), unique=False, nullable=False)
    lastname = db.Column(db.String(20), unique=False, nullable=False)
    username = db.Column(db.String(20), unique=False, nullable=False, primary_key=True)
    password = db.Column(db.String(20), unique=False, nullable=False)
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
    global helper
    if "authenticated" not in session:
        return render_template("login.html")
    return render_template('Running_Servers.html', content=helper.active_ips)


@app.route("/authenticate")
def authenticate():
    global helper
    code = ''
    for i in range(8):
        code += random.choice(string.digits)
    helper.set_code(code)
    try:
        message = Mail(
            from_email='eagleeyeproject1@gmail.com',
            to_emails=Profile.query.filter_by(username=session["username"]).first().email,
            subject='Authentication Code',
            plain_text_content=f'This is your auth code to our website: {code}')
        sg = SendGridAPIClient(helper.API_KEY)
        response = sg.send(message)
        print(response.status_code, response.body, response.headers)
    except Exception:
        print("Failed to send mail")
        return render_template('login.html')
    return render_template("Authentication.html")


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    bits = password.encode()
    secret = hashlib.sha256(bits)
    password = secret.hexdigest()
    find_user = Profile.query.filter_by(username=username, password=password).first()
    # find_pass=Profile.query.filter_by(password=password)
    session["active_ips"] = None
    if find_user:
        try:
            os.mkdir(username)
        except Exception:
            print("Directory already exists")
        session["username"] = request.form.get("username")
        session["password"] = request.form.get("password")
        return redirect(url_for('authenticate'))
    else:
        flash("Username or Password are incorrect")
        return redirect(url_for('index_page'))


@app.route("/ScanResults")
def func1():
    return render_template("ScanResults.html")


@app.route("/SniffResults")
def func2():
    if "authenticated" in session:
        content = os.listdir(f'./{session["username"]}')
        print(content)
        return render_template("Previousresults.html", content=content)
    return redirect('/')


@app.route("/about")
def about_us():
    return render_template("About.html")


@app.route("/Shell/<ip_address>")
def connect_to_shell(ip_address):
    if "authenticated" in session:
        Client(ip_address, 16549).activate_reverse_shell()
        global helper
        helper.connect()
        return render_template("ConnectToShell.html", content=[helper.get_cwd(), ''])
    return redirect('/')


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
        bits = password.encode()
        secret = hashlib.sha256(bits)
        password = secret.hexdigest()
        if firstname != '' and lastname != '' and username != '' and password != '' and checkpassword != '' and email != '':
            p = Profile(firstname=firstname, lastname=lastname, username=username, password=password,
                        checkpassword=checkpassword,
                        email=email)
            db.session.add(p)
            db.session.commit()
            session["username"] = request.form.get("username")
            session["password"] = request.form.get("password")
            return render_template("RegisteredSuccessfully.html")
        # return render_template("PersonalArea.html")


@app.route("/SniffResults/Activate/<ip_address>")
def sniff(ip_address):
    if "authenticated" in session:
        time_stamp, st = Client(ip_address, 16549).activate_sniff()
        print(st)
        num = len(os.listdir(os.getcwd() + f'\\{session["username"]}'))
        os.replace(f'{time_stamp}' + '.txt',
                   os.getcwd() + f'\\{session["username"]}\\{session["username"]}{num + 1}' + '.txt')
        print('File is saved as:', os.getcwd() + f'\\{session["username"]}\\{session["username"]}{num + 1}' + '.txt')
        return render_template("SniffResults.html", content=st.split('done')[:-1])
    return redirect('/')


@app.route("/ScanResults/SYN/<ip_address>")
def TCP_SYN_scan(ip_address):
    if "authenticated" in session:
        st = Client(ip_address, 16549).activate_SYN()
        return render_template('ScanResults.html', content=st.split('\n')[:-1])
    return redirect('/')


@app.route("/ScanResults/Stealth/<ip_address>")
def TCP_Stealth_scan(ip_address):
    if "authenticated" in session:
        st = Client(ip_address, 16549).activate_Stealth()
        return render_template('ScanResults.html', content=st.split('\n')[:-1])
    return redirect('/')


@app.route("/ScanResults/UDP/<ip_address>")
def UDP_port_scan(ip_address):
    if "authenticated" in session:
        st = Client(ip_address, 16549).activate_UDP()
        return render_template('ScanResults.html', content=st.split('\n')[:-1])
    return redirect('/')


@app.route("/logout", methods=['GET', 'POST'])
def Logout():
    if "authenticated" not in session:
        return redirect(url_for('index_page'))
    session.pop("username")
    session.pop("password")
    session.pop("authenticated")
    session.pop("active_ips")
    return render_template("LoggedOutSuccessfully.html")


@app.route("/register", methods=["GET"])
def get_register():
    return render_template("register.html")


@app.route('/index')
def network_mapping():
    if "authenticated" not in session:
        return render_template("login.html")
    return render_template('ActiveIPs.html')


@app.route('/getemail', methods=['POST'])
def get_email():
    global reset_auth, helper
    mail = request.form.get("email")
    print(mail)
    find_user_email = Profile.query.filter_by(email=mail).first()
    print(find_user_email)
    if find_user_email:
        session["email"] = mail
        code = ''
        for i in range(8):
            code += random.choice(string.digits)
        reset_auth = code
        try:
            message = Mail(
                from_email='eagleeyeproject1@gmail.com',
                to_emails=mail,
                subject='Authentication Code',
                plain_text_content=f'This is your auth code to our website: {code}')
            sg = SendGridAPIClient(helper.API_KEY)
            response = sg.send(message)
            print(response.status_code, response.body, response.headers)
        except Exception:
            print("Failed to send mail")
            return render_template('MailNotFound.html')
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
        password = request.form.get("password")
        if password == '':
            return redirect(url_for('reset_wrap'))
        bits = password.encode()
        secret = hashlib.sha256(bits)
        password = secret.hexdigest()
        admin.password = password
        db.session.commit()
        return render_template("ResetSuccessfully.html")
    print("Incorrect")
    return redirect(url_for('reset_wrap'))


@app.route('/active_ips', methods=['POST'])
def map_network():
    subnet_mask = helper_methods.get_subnet_mask()
    clients = []
    threads = []
    LOCK = threading.Lock()
    count = 0
    lists = [[] for i in range(helper_methods.get_processor_num() * 2)]
    if subnet_mask:
        result = helper_methods.check_hosts(subnet_mask)
        for address in result.split('\n')[:-1]:
            lists[count].append(address)
            if count == helper_methods.get_processor_num() * 2 - 1:
                count = 0
            else:
                count += 1
        print(lists)

        for i in range(len(lists)):
            t = threading.Thread(target=helper_methods.scanner, args=(lists[i], LOCK, clients, time.time()))
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()
        session["active_ips"] = clients
        return render_template("ActiveIPs.html", content=clients)
    return render_template("ActiveIPs.html")


@app.route('/computers/<ip_address>')
def handle_client(ip_address):
    return render_template('Client_Panel.html')


@app.route('/activated_reverse', methods=['POST'])
def execute():
    global helper
    result = helper.execute_command(request.form.get("input"))
    return render_template("ConnectToShell.html", content=[helper.get_cwd(), result])


@app.route('/check_authenticate', methods=['POST'])
def check_authenticate():
    inp = request.form.get("inp")
    if inp.strip('\n') == helper.get_code():
        print('User logged in')
        session["authenticated"] = True
    return redirect('/')


@app.route('/ping', methods=['POST'])
def receive_ping():
    address = request.get_data().decode().split('\n')[1][13:]
    global helper
    if address not in helper.active_ips:
        helper.active_ips.append(address)
    print(helper.active_ips)
    return render_template('login.html')


@app.route('/active_servers', methods=['GET'])
def show_active_servers():
    global helper
    if session["authenticated"]:
        return render_template('Running_Servers.html', content=helper.active_ips)
    return render_template('login.html')


@app.route('/view/<file_name>', methods=['GET'])
def view_result(file_name):
    if "authenticated" in session:
        content = open(os.getcwd() + '\\' + session["username"] + '\\' + file_name, 'r').read().split('done')[:-1]
        return render_template('view_page.html', content=content)
    return redirect('/')


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, host="0.0.0.0", port=80)

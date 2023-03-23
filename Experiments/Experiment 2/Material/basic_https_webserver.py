from flask import Flask, request
app = Flask(__name__)

@app.route('/', methods=['GET'])
def fun():
    return "Hello there, welcome to this basic HTTPS webserver"

if __name__ == "__main__":
    app.run(host="192.168.0.22", port=443, ssl_context=("./server/serverCert.pem","./server/serverKey.pem"))

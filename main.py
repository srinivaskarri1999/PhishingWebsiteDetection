from flask import Flask, request
from predict import predict

app = Flask(__name__)

@app.route('/', methods=['GET'])
def phishing():
    url = request.args["url"]
    return predict(url)


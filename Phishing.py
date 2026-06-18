from flask import Flask, request, render_template_string
import re
import webbrowser
from threading import Timer

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Awareness Analysis Tool</title>
    <style>
        body{
            font-family: Arial, sans-serif;
            background:#f4f4f4;
            margin:0;
            padding:20px;
        }

        .container{
            max-width:900px;
            margin:auto;
            background:white;
            padding:25px;
            border-radius:10px;
            box-shadow:0px 0px 10px rgba(0,0,0,0.2);
        }

        h1{
            text-align:center;
            color:#333;
        }

        textarea{
            width:100%;
            height:220px;
            padding:10px;
            font-size:16px;
            border:1px solid #ccc;
            border-radius:5px;
        }

        button{
            margin-top:15px;
            padding:12px 25px;
            background:#007bff;
            color:white;
            border:none;
            border-radius:5px;
            cursor:pointer;
            font-size:16px;
        }

        button:hover{
            background:#0056b3;
        }

        .result{
            margin-top:25px;
            padding:15px;
            background:#f9f9f9;
            border-radius:8px;
        }

        .danger{
            color:red;
            font-weight:bold;
        }

        .safe{
            color:green;
            font-weight:bold;
        }

        ul{
            line-height:1.8;
        }
    </style>
</head>
<body>

<div class="container">

<h1>Phishing Awareness Analysis Tool</h1>

<form method="POST">

<textarea name="message"
placeholder="Paste email or message here..." required>{{message}}</textarea>

<br>

<button type="submit">Analyze Message</button>

</form>

{% if analyzed %}

<div class="result">

<h2>Analysis Result</h2>

<p>
<b>Risk Level:</b>
<span class="{{risk_class}}">{{risk}}</span>
</p>

<h3>Suspicious Links Found</h3>

{% if links %}
<ul>
{% for link in links %}
<li>{{link}}</li>
{% endfor %}
</ul>
{% else %}
<p>No links detected.</p>
{% endif %}

<h3>Red Flags Identified</h3>

{% if red_flags %}
<ul>
{% for flag in red_flags %}
<li>{{flag}}</li>
{% endfor %}
</ul>
{% else %}
<p>No obvious phishing indicators found.</p>
{% endif %}

<h3>Why This Message May Be Unsafe</h3>

<p>{{explanation}}</p>

</div>

{% endif %}

</div>

</body>
</html>
"""

PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "account suspended",
    "click here",
    "password",
    "login now",
    "update information",
    "bank account",
    "confirm identity",
    "limited time",
    "winner",
    "claim prize",
    "security alert",
    "act immediately",
    "verify account",
    "reset password"
]


def analyze_message(text):

    red_flags = []

    links = re.findall(r'https?://[^\s]+', text)

    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in text.lower():
            red_flags.append(
                f"Suspicious keyword detected: '{keyword}'"
            )

    for link in links:

        if not link.startswith("https://"):
            red_flags.append(
                f"Insecure link uses HTTP instead of HTTPS: {link}"
            )

        suspicious_words = [
            "verify",
            "login",
            "secure",
            "account",
            "update",
            "confirm"
        ]

        for word in suspicious_words:
            if word in link.lower():
                red_flags.append(
                    f"Suspicious URL contains '{word}': {link}"
                )
                break

    if len(red_flags) >= 5:
        risk = "HIGH RISK"
        risk_class = "danger"
    elif len(red_flags) >= 2:
        risk = "MEDIUM RISK"
        risk_class = "danger"
    else:
        risk = "LOW RISK"
        risk_class = "safe"

    explanation = (
        "Phishing attacks often use urgency, fear, fake rewards, "
        "and suspicious links to trick users into revealing personal "
        "or financial information. Always verify sender details and "
        "avoid clicking unknown links."
    )

    return red_flags, links, risk, risk_class, explanation


@app.route("/", methods=["GET", "POST"])
def home():

    red_flags = []
    links = []
    risk = ""
    risk_class = ""
    explanation = ""
    message = ""
    analyzed = False

    if request.method == "POST":

        analyzed = True
        message = request.form["message"]

        red_flags, links, risk, risk_class, explanation = (
            analyze_message(message)
        )

    return render_template_string(
        HTML,
        red_flags=red_flags,
        links=links,
        risk=risk,
        risk_class=risk_class,
        explanation=explanation,
        message=message,
        analyzed=analyzed
    )


def open_browser():
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    Timer(1, open_browser).start()
    app.run(debug=False)
from flask import Flask
import json

app = Flask(__name__)

@app.route("/")
def home():
    with open("devices.json") as f:
        devices = json.load(f)

    with open("alerts.log") as f:
        all_lines = f.readlines()

    recent = all_lines[-15:]      # keep only the last 15 lines

    alert_rows = ""
    for line in recent:
        line = line.strip()
        if "CRITICAL" in line:
            color = "red"
        elif "WARNING" in line:
            color = "orange"
        else:
            color = "black"
        alert_rows += f'<li style="color: {color}">{line}</li>'

    rows = ""
    for ip, mac in devices.items():
        rows += f"<tr><td>{ip}</td><td>{mac}</td></tr>"

    return f"""
    <meta http-equiv="refresh" content="5">
    <h1>NetRadar Dashboard</h1>
    <h2>Recent Alerts</h2>
    <ul>
        {alert_rows}
    </ul>
    <h2>Devices ({len(devices)})</h2>
    <table border="1">
        <tr><th>IP Address</th><th>MAC Address</th></tr>
        {rows}
    </table>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

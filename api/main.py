# api_server.py
from flask import Flask, request, jsonify, send_from_directory
from includes.cico_scraper import fetch_vulnerabilities, scrape_affected_products

app = Flask(__name__, static_folder="static")

@app.route('/')
def serve_frontend():
    return send_from_directory('static', 'index.html')

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    product_title = request.args.get('product_title')
    if not product_title:
        return jsonify({"error": "Missing 'product_title' query parameter."}), 400

    try:
        vulnerabilities = fetch_vulnerabilities(product_title)
        output = []
        for record in vulnerabilities:
            affected_products = scrape_affected_products(record.get('url', ''))
            output.append({
                'Identifier': record.get('identifier', 'N/A'),
                'Title': record.get('title', 'N/A'),
                'First Published': record.get('firstPublished', 'N/A'),
                'Last Published': record.get('lastPublished', 'N/A'),
                'Severity': record.get('severity', 'N/A'),
                'CVE': record.get('cve', 'N/A'),
                'CWE': record.get('cwe', 'N/A'),
                'Summary': record.get('summary', 'N/A'),
                'Affected Products': affected_products if affected_products else ['N/A'],
                'URL': record.get('url', 'N/A')
            })
        return jsonify(output)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

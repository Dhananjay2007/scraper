import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from bs4 import BeautifulSoup
import time
import re
# Load training and testing datasets
train_path = "D:/frontend/model/pythonProject4/new 13/ai scraper/archive/train/train_preprocessed.csv"
test_path = "D:/frontend/model/pythonProject4/new 13/ai scraper/archive/test/test_preprocessed.csv"
train_data = pd.read_csv(train_path)
test_data = pd.read_csv(test_path)

# Define features and target
text_feature = "summary_clean"
tabular_features = ["cvss", "days_since_pub", "vendor", "vulnerable_product", "cwe_name"]
target = "severity_level_encoded"

# Split data into X (features) and y (target)
X_train = train_data[[text_feature] + tabular_features]
y_train = train_data[target]
X_test = test_data[[text_feature] + tabular_features]
y_test = test_data[target]

# Define a ColumnTransformer for preprocessing
preprocessor = ColumnTransformer(
    transformers=[
        ("tfidf", TfidfVectorizer(max_features=5000), text_feature),  # Text processing
        (
            "onehot",
            OneHotEncoder(handle_unknown="ignore"),
            ["vendor", "vulnerable_product", "cwe_name"],  # Categorical encoding
        ),
    ],
    remainder="passthrough",  # Pass through numerical features (cvss, days_since_pub)
)

# Define the model pipeline
pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42)),
    ]
)

# Visualize process start
start_time = time.time()
print("[INFO] Starting model training and evaluation...")

# Train the model
training_start_time = time.time()
pipeline.fit(X_train, y_train)
training_end_time = time.time()
print(f"[INFO] Training completed in {training_end_time - training_start_time:.2f} seconds.")

# Make predictions
prediction_start_time = time.time()
y_pred = pipeline.predict(X_test)
prediction_end_time = time.time()
print(f"[INFO] Prediction completed in {prediction_end_time - prediction_start_time:.2f} seconds.")

# Evaluate the model
evaluation_start_time = time.time()
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Low", "Medium", "High", "Critical"]))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
evaluation_end_time = time.time()
print(f"[INFO] Evaluation completed in {evaluation_end_time - evaluation_start_time:.2f} seconds.")

# Visualize total processing time
total_end_time = time.time()
print(f"[INFO] Total processing time: {total_end_time - start_time:.2f} seconds.")

# Test on HTML
# def test_on_html(html_content):
#     # Parse the HTML
#     soup = BeautifulSoup(html_content, 'html.parser')
#
#     # Extracting text from <div class="text-container col-xs-12">
#     summary = " ".join([div.text for div in soup.find_all('div', class_="text-container col-xs-12")])

def extract_cve_data(html_content):
    # Parse the HTML
    soup = BeautifulSoup(html_content, 'html.parser')

    # Initialize results
    extracted_data = []

    # Extract all relevant paragraphs
    paragraphs = soup.find_all('p')

    # Temporary variables for current vulnerability
    cve_id = None
    description = None
    cvss_score = None
    mitigation = None

    for p in paragraphs:
        text = p.text.strip()
        # Extract CVE ID
        if "CVE-" in text:
            if cve_id:  # Save the previous vulnerability if a new one starts
                extracted_data.append({
                    "CVE_ID": cve_id,
                    "Description": description,
                    "CVSS_Score": cvss_score,
                    "Mitigation": mitigation,
                })
                # Reset temporary variables
                description = None
                cvss_score = None
                mitigation = None

            match = re.search(r'CVE-\d{4}-\d+', text)
            if match:
                cve_id = match.group(0)

        # Extract description
        elif "Description:" in text:
            description = text.split("Description:", 1)[1].strip()

        # Extract CVSS score
        elif "CVSS Base Score" in text:
            try:
                cvss_score = float(re.search(r'(\d+\.\d+)', text).group(1))
            except AttributeError:
                pass

        # Extract mitigation steps
        elif "recommend" in text.lower() or "update" in text.lower():
            mitigation = text

    # Append the last vulnerability (if any)
    if cve_id:
        extracted_data.append({
            "CVE_ID": cve_id,
            "Description": description,
            "CVSS_Score": cvss_score,
            "Mitigation": mitigation,
        })

    # Convert to DataFrame
    df = pd.DataFrame(extracted_data)

    # Save to CSV
    output_path = "extracted_cve_data2.csv"
    df.to_csv(output_path, index=False)
    print(f"[INFO] CVE data saved to {output_path}")
    return df

# Example HTML content
test_html = """<div class="text-container col-xs-12 ">
                                
                                
                                    <h3>Summary:&nbsp;</h3>
<p>A potential security vulnerability in some Intel® oneAPI DPC++/C++ Compiler may allow escalation of privilege. Intel is releasing software updates to mitigate this potential vulnerability.</p>
<h3>Vulnerability Details:&nbsp;</h3>
<p>CVEID: &nbsp;<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-34165">CVE-2024-34165</a></p>
<p>Description: Uncontrolled search path in some Intel® oneAPI DPC++/C++ Compiler before version 2024.2 may allow an authenticated user to potentially enable escalation of privilege via local access.</p>
<p>CVSS Base Score 3.1: 6.7 Medium</p>
<p>CVSS Vector 3.1: &nbsp;<a href="https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H">CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H</a></p>
<p>CVSS Base Score 4.0: 5.4 Medium</p>
<p>CVSS Vector 4.0: &nbsp;<a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N">CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</a></p>
<h3>Affected Products:</h3>
<p>Intel® oneAPI Base Toolkit (Base Kit) before version 2024.2.<br>
<br>
Intel® HPC Toolkit (HPC Kit) before version 2024.2.<br>
<br>
Intel® oneAPI DPC++/C++ Compiler before version 2024.2.<br>
<br>
Intel® Fortran Compiler before version 2024.2.</p>
<h3>Recommendation:</h3>
<p>Intel recommends updating Intel® oneAPI Base Toolkit (Base Kit) to version 2024.2 or later. &nbsp;Updates are available for download at this location: &nbsp;<a href="https://www.intel.com/content/www/us/en/developer/tools/oneapi/base-toolkit-download.html">https://www.intel.com/content/www/us/en/developer/tools/oneapi/base-toolkit-download.html</a></p>
<p>Intel recommends updating Intel® HPC Toolkit (HPC Kit) to version 2024.2 or later. &nbsp;Updates are available for download at this location: &nbsp;<a href="https://www.intel.com/content/www/us/en/developer/tools/oneapi/hpc-toolkit.html#gs.136mhe">https://www.intel.com/content/www/us/en/developer/tools/oneapi/hpc-toolkit.html#gs.136mhe</a></p>
<p>Intel recommends updating Intel® oneAPI DPC++/C++ Compiler to version 2024.2 or later. &nbsp;Updates are available for download at this location: &nbsp;<a href="https://www.intel.com/content/www/us/en/developer/articles/tool/oneapi-standalone-components.html#dpcpp-cpp">https://www.intel.com/content/www/us/en/developer/articles/tool/oneapi-standalone-components.html#dpcpp-cpp</a></p>
<p>Intel recommends updating Intel® Fortran Compiler to version 2024.2 or later. &nbsp;Updates are available for download at this location: &nbsp;<a href="https://www.intel.com/content/www/us/en/developer/articles/tool/oneapi-standalone-components.html#fortran">https://www.intel.com/content/www/us/en/developer/articles/tool/oneapi-standalone-components.html#fortran</a></p>
<h3>Acknowledgements:</h3>
<p>Intel would like to thank ycdxsb for reporting this issue.</p>
<p>&nbsp;</p>
<p>Intel, and nearly the entire technology industry, follows a disclosure practice called Coordinated Disclosure, under which a cybersecurity vulnerability is generally publicly disclosed only after mitigations are available.</p>
 
                                
                            </div>"""

print("[INFO] Testing on FULL HTML input...")
extract_cve_data(test_html)
1
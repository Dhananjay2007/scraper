import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
import time

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

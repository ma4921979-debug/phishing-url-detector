import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier

# Load dataset
df = pd.read_csv("data/dataset.csv")

# Split features and target
X = df.drop("Result", axis=1)
y = df["Result"]

# Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Models to compare
models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42
    ),
    "Extra Trees": ExtraTreesClassifier(
        n_estimators=200,
        random_state=42
    ),
    "Gradient Boosting": GradientBoostingClassifier(
        random_state=42
    )
}

best_model = None
best_name = ""
best_accuracy = 0

# Train and compare models
for name, model in models.items():
    print("=" * 50)
    print(f"Training: {name}")

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print(f"Accuracy: {accuracy}")
    print(classification_report(y_test, predictions))

    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model
        best_name = name

# Save best model
joblib.dump(best_model, "model.pkl")
joblib.dump(list(X.columns), "feature_columns.pkl")

print("=" * 50)
print("Best Model:", best_name)
print("Best Accuracy:", best_accuracy)
print("Best model saved successfully ✅")
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

# Dataframe to read CSV file
df = pd.read_csv("traffic_patterns.csv")

# Creates columns and rows for the dataset
X = df.drop(columns=["label"])
y = df["label"]

# Maintans the balance of data to prevent overfitting the model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# Trains through the balance trees
rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train, y_train)

# Evaluates performance
y_pred = rf.predict(X_test)

print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))

# Formats the data for the analysis report
importance = pd.Series(
    rf.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

# Prints network analysis metrics
print(importance)


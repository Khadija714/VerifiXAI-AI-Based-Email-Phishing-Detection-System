import os
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from preprocessor import preprocess_dataframe

def train_and_save_model(csv_path, model_dir='models', n_samples=20000, max_features=1200, test_size=0.2):
    # Load dataset
    df = pd.read_csv(csv_path)
    print(f"Original dataset size: {len(df)}")
    print(f"Original class distribution:\n{df['label'].value_counts()}")
    
    # Simple random sampling with stratification (maintain class ratio)
    # Calculate samples per class proportionally
    class_counts = df['label'].value_counts()
    samples_per_class = {}
    for cls in class_counts.index:
        samples_per_class[cls] = int(n_samples * class_counts[cls] / len(df))
    
    # Adjust in case total is less than n_samples
    total = sum(samples_per_class.values())
    if total < n_samples:
        diff = n_samples - total
        # Add remaining to the majority class
        majority_cls = class_counts.idxmax()
        samples_per_class[majority_cls] += diff
    elif total > n_samples:
        # Remove from majority class
        majority_cls = class_counts.idxmax()
        samples_per_class[majority_cls] -= (total - n_samples)
    
    # Sample
    sampled_dfs = []
    for cls, n in samples_per_class.items():
        cls_df = df[df['label'] == cls]
        if n > len(cls_df):
            n = len(cls_df)  # Not enough samples? use all
        sampled = cls_df.sample(n=n, random_state=42)
        sampled_dfs.append(sampled)
    
    df_sampled = pd.concat(sampled_dfs, ignore_index=True)
    print(f"Sampled dataset size: {len(df_sampled)}")
    print(f"Sampled class distribution:\n{df_sampled['label'].value_counts()}")
    
    # Preprocess
    df_sampled = preprocess_dataframe(df_sampled, text_column='text_combined')
    
    # Check for NaN in processed_text
    if df_sampled['processed_text'].isnull().any():
        df_sampled['processed_text'] = df_sampled['processed_text'].fillna('')
    
    # TF-IDF
    tfidf = TfidfVectorizer(max_features=max_features, ngram_range=(1,2))
    X = tfidf.fit_transform(df_sampled['processed_text']).toarray()
    y = df_sampled['label'].values
    
    # Remove any rows with NaN in y (just in case)
    mask = ~np.isnan(y)
    X = X[mask]
    y = y[mask]
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    
    # Random Forest
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {acc*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(model_dir, 'rf_model.pkl'))
    joblib.dump(tfidf, os.path.join(model_dir, 'tfidf_vectorizer.pkl'))
    print(f"\nModel saved in '{model_dir}' folder.")
    
    return rf, tfidf
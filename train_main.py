# train_main.py
# This script train model & save.

from ml_model import train_and_save_model

if __name__ == "__main__":
    # Provide your dataset path
    dataset_path = r"E:\Ai-Based Email phishing detection system\dataset\phishing_email1\phishing_email.csv"
    
    # Train and save model
    # Train with 20,000 samples and 1,200 features
    rf, tfidf = train_and_save_model(
        csv_path=dataset_path,
        model_dir='models',
        n_samples=20000,      # 20k rows
        max_features=1200,    # features
        test_size=0.2
    )
    print("Training complete. Model ready in 'models/' folder")

    